use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use futures_util::future::BoxFuture;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::AgentError;
use crate::types::ProjectRuntimeContext;

const PROJECT_RUNTIME_CONTEXT_INVALIDATED: &str = "PROJECT_RUNTIME_CONTEXT_INVALIDATED";
const PROJECT_RUNTIME_BUSY: &str = "PROJECT_RUNTIME_BUSY";

pub type ProjectRuntimeRevalidator = Arc<dyn Fn() -> BoxFuture<'static, Result<(), AgentError>> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectRuntimeUse {
    Warmup,
    Turn { turn_id: String },
}

struct ProjectRuntimeEpochState {
    barrier: Arc<RwLock<()>>,
    authoritative_revision: Mutex<Option<u64>>,
    runtime_generation: AtomicU64,
}

impl Default for ProjectRuntimeEpochState {
    fn default() -> Self {
        Self {
            barrier: Arc::new(RwLock::new(())),
            authoritative_revision: Mutex::new(None),
            runtime_generation: AtomicU64::new(0),
        }
    }
}

/// Per-conversation runtime fence. Entries intentionally outlive task slots,
/// so bind/unbind leaves a no-slot tombstone until conversation deletion.
#[derive(Default)]
pub struct ProjectRuntimeEpochRegistry {
    states: DashMap<String, Arc<ProjectRuntimeEpochState>>,
}

impl ProjectRuntimeEpochRegistry {
    fn state(&self, conversation_id: &str) -> Arc<ProjectRuntimeEpochState> {
        Arc::clone(
            self.states
                .entry(conversation_id.to_owned())
                .or_insert_with(|| Arc::new(ProjectRuntimeEpochState::default()))
                .value(),
        )
    }

    pub fn runtime_generation(&self, conversation_id: &str) -> u64 {
        self.state(conversation_id).runtime_generation.load(Ordering::Acquire)
    }

    pub fn try_begin_mutation(&self, conversation_id: &str) -> Result<ProjectRuntimeMutationPermit, AgentError> {
        let state = self.state(conversation_id);
        let guard = Arc::clone(&state.barrier)
            .try_write_owned()
            .map_err(|_| AgentError::conflict(PROJECT_RUNTIME_BUSY))?;
        Ok(ProjectRuntimeMutationPermit { state, _guard: guard })
    }

    pub fn forget(&self, conversation_id: &str) {
        self.states.remove(conversation_id);
    }
}

pub struct ProjectRuntimeMutationPermit {
    state: Arc<ProjectRuntimeEpochState>,
    _guard: OwnedRwLockWriteGuard<()>,
}

impl ProjectRuntimeMutationPermit {
    pub fn commit_runtime_identity(
        &self,
        project_binding_revision: u64,
        advance_generation: bool,
    ) -> Result<u64, AgentError> {
        let mut revision = self
            .state
            .authoritative_revision
            .lock()
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_EPOCH_UNAVAILABLE"))?;
        *revision = Some(project_binding_revision);
        if !advance_generation {
            return Ok(self.state.runtime_generation.load(Ordering::Acquire));
        }
        self.state
            .runtime_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_add(1))
            .map(|previous| previous + 1)
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_GENERATION_EXHAUSTED"))
    }
}

#[derive(Clone)]
pub struct ProjectRuntimeBuildGate {
    state: Arc<ProjectRuntimeEpochState>,
    conversation_id: String,
    project_binding_revision: u64,
    process_runtime_generation: u64,
    revalidate: ProjectRuntimeRevalidator,
}

impl fmt::Debug for ProjectRuntimeBuildGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectRuntimeBuildGate")
            .field("conversation_id", &self.conversation_id)
            .field("project_binding_revision", &self.project_binding_revision)
            .field("process_runtime_generation", &self.process_runtime_generation)
            .field("revalidate", &"[redacted callback]")
            .finish_non_exhaustive()
    }
}

impl ProjectRuntimeBuildGate {
    pub fn new(
        registry: Arc<ProjectRuntimeEpochRegistry>,
        conversation_id: impl Into<String>,
        project_binding_revision: u64,
        revalidate: ProjectRuntimeRevalidator,
    ) -> Self {
        let conversation_id = conversation_id.into();
        let state = registry.state(&conversation_id);
        let process_runtime_generation = state.runtime_generation.load(Ordering::Acquire);
        Self {
            state,
            conversation_id,
            project_binding_revision,
            process_runtime_generation,
            revalidate,
        }
    }

    pub fn process_runtime_generation(&self) -> u64 {
        self.process_runtime_generation
    }

    pub async fn acquire_and_revalidate(
        &self,
        runtime_use: ProjectRuntimeUse,
    ) -> Result<ProjectRuntimeExecutionPermit, AgentError> {
        let guard = Arc::clone(&self.state.barrier).read_owned().await;
        if self.state.runtime_generation.load(Ordering::Acquire) != self.process_runtime_generation {
            return Err(AgentError::conflict(PROJECT_RUNTIME_CONTEXT_INVALIDATED));
        }
        {
            let revision = self
                .state
                .authoritative_revision
                .lock()
                .map_err(|_| AgentError::internal("PROJECT_RUNTIME_EPOCH_UNAVAILABLE"))?;
            if revision.is_some_and(|revision| revision != self.project_binding_revision) {
                return Err(AgentError::conflict(PROJECT_RUNTIME_CONTEXT_INVALIDATED));
            }
        }

        // Only a successful authoritative DB revalidation may seed the
        // process-local receipt. Rejected future revisions cannot wedge it.
        (self.revalidate)().await?;
        {
            let mut revision = self
                .state
                .authoritative_revision
                .lock()
                .map_err(|_| AgentError::internal("PROJECT_RUNTIME_EPOCH_UNAVAILABLE"))?;
            match *revision {
                Some(current) if current != self.project_binding_revision => {
                    return Err(AgentError::conflict(PROJECT_RUNTIME_CONTEXT_INVALIDATED));
                }
                Some(_) => {}
                None => *revision = Some(self.project_binding_revision),
            }
        }

        Ok(ProjectRuntimeExecutionPermit {
            inner: Arc::new(ProjectRuntimeExecutionPermitInner {
                conversation_id: self.conversation_id.clone(),
                project_binding_revision: self.project_binding_revision,
                process_runtime_generation: self.process_runtime_generation,
                runtime_use,
                on_release: Mutex::new(HashMap::new()),
                _guard: guard,
            }),
        })
    }
}

type ReleaseCallback = Arc<dyn Fn() + Send + Sync>;

struct ProjectRuntimeExecutionPermitInner {
    conversation_id: String,
    project_binding_revision: u64,
    process_runtime_generation: u64,
    runtime_use: ProjectRuntimeUse,
    on_release: Mutex<HashMap<u64, ReleaseCallback>>,
    _guard: OwnedRwLockReadGuard<()>,
}

impl Drop for ProjectRuntimeExecutionPermitInner {
    fn drop(&mut self) {
        let callbacks = self
            .on_release
            .lock()
            .map(|callbacks| callbacks.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for callback in callbacks {
            callback();
        }
    }
}

#[derive(Clone)]
pub struct ProjectRuntimeExecutionPermit {
    inner: Arc<ProjectRuntimeExecutionPermitInner>,
}

impl fmt::Debug for ProjectRuntimeExecutionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectRuntimeExecutionPermit")
            .field("conversation_id", &self.inner.conversation_id)
            .field("project_binding_revision", &self.inner.project_binding_revision)
            .field("process_runtime_generation", &self.inner.process_runtime_generation)
            .field("runtime_use", &self.inner.runtime_use)
            .finish_non_exhaustive()
    }
}

impl ProjectRuntimeExecutionPermit {
    pub fn matches(&self, conversation_id: &str, context: &ProjectRuntimeContext) -> bool {
        self.inner.conversation_id == conversation_id
            && self.inner.project_binding_revision == context.project_binding_revision
            && self.inner.process_runtime_generation == context.process_runtime_generation
    }

    pub fn runtime_use(&self) -> &ProjectRuntimeUse {
        &self.inner.runtime_use
    }

    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.inner) as usize
    }

    pub fn register_release_callback(
        &self,
        registration_id: u64,
        callback: ReleaseCallback,
    ) -> Result<bool, AgentError> {
        let mut current = self
            .inner
            .on_release
            .lock()
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_LIFECYCLE_UNAVAILABLE"))?;
        if let std::collections::hash_map::Entry::Vacant(entry) = current.entry(registration_id) {
            entry.insert(callback);
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn test_only(
        conversation_id: impl Into<String>,
        context: &ProjectRuntimeContext,
        runtime_use: ProjectRuntimeUse,
    ) -> Self {
        let barrier = Arc::new(RwLock::new(()));
        let guard = barrier.try_read_owned().expect("fresh test barrier");
        Self {
            inner: Arc::new(ProjectRuntimeExecutionPermitInner {
                conversation_id: conversation_id.into(),
                project_binding_revision: context.project_binding_revision,
                process_runtime_generation: context.process_runtime_generation,
                runtime_use,
                on_release: Mutex::new(HashMap::new()),
                _guard: guard,
            }),
        }
    }
}
