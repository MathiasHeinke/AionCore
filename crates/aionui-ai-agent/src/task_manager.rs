use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aionui_common::{
    AgentKillReason, AgentType, ConversationStatus, ErrorChain, OnConversationDelete, TimestampMs, now_ms,
};
use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::future::{BoxFuture, join_all};
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

use crate::agent_task::AgentInstance;
use crate::error::AgentError;
use crate::project_runtime_fence::{ProjectRuntimeExecutionPermit, ProjectRuntimeUse};
use crate::types::{BuildTaskOptions, ProjectRuntimeContext};

/// Factory function that creates an [`AgentInstance`] from build options.
///
/// Async so the factory can do real I/O (spawn a CLI process, negotiate the
/// ACP initialize handshake, etc.) without needing to `block_on` inside the
/// `IWorkerTaskManager` call site. Returning `BoxFuture` keeps the trait
/// object-safe for DI.
pub type AgentFactory =
    Arc<dyn Fn(BuildTaskOptions) -> BoxFuture<'static, Result<AgentInstance, AgentError>> + Send + Sync>;

/// Manages the lifecycle of active Agent tasks.
///
/// Each conversation has at most one active task (keyed by conversation ID).
/// The trait is object-safe for dependency injection.
#[async_trait]
pub trait IWorkerTaskManager: Send + Sync {
    /// Get an existing task by conversation ID.
    fn get_task(&self, conversation_id: &str) -> Option<AgentInstance>;

    /// Get an existing task or build a new one if none exists.
    ///
    /// Concurrent callers with the same `conversation_id` block on a shared
    /// [`OnceCell`] so the factory runs at most once per conversation —
    /// avoiding the race where two concurrent HTTP requests (e.g.
    /// `/messages` + `/warmup`) would each spawn their own CLI process and
    /// ACP connection, with one of them leaking.
    async fn get_or_build_task(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
    ) -> Result<AgentInstance, AgentError>;

    /// Get or build a task for proactive warmup without claiming an active
    /// user turn. Implementations that do not track warm residency may keep
    /// the historical behavior by delegating to [`Self::get_or_build_task`].
    async fn get_or_build_warm_task(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
    ) -> Result<AgentInstance, AgentError> {
        self.get_or_build_task(conversation_id, options).await
    }

    /// Kill and remove a task.
    fn kill(&self, conversation_id: &str, reason: Option<AgentKillReason>) -> Result<(), AgentError>;

    /// Kill a task and return a future that resolves when the process has terminated.
    fn kill_and_wait(
        &self,
        conversation_id: &str,
        reason: Option<AgentKillReason>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    /// Kill, remove, and wait for all active tasks to stop.
    async fn clear(&self);

    /// Number of active tasks (useful for diagnostics).
    fn active_count(&self) -> usize;

    /// Collect tasks eligible for idle cleanup.
    ///
    /// Returns conversation IDs of ACP tasks that have exceeded the idle
    /// threshold and are either warm-resident without a turn or finished.
    fn collect_idle(&self, idle_threshold_ms: TimestampMs) -> Vec<String>;

    /// Revalidate and kill an idle candidate selected by [`Self::collect_idle`].
    ///
    /// The default preserves compatibility for test and adapter managers.
    /// The production manager overrides this so a real turn that starts after
    /// the scan but before removal wins the race and keeps its task alive.
    async fn kill_idle_if_still_eligible(&self, conversation_id: &str, _idle_threshold_ms: TimestampMs) -> bool {
        self.kill_and_wait(conversation_id, Some(AgentKillReason::IdleTimeout))
            .await;
        true
    }
}

/// Per-conversation single-flight slot plus the pathless project runtime
/// identity it was built for. Invalidation fences a late factory result after
/// kill/remap so the spawned process cannot leak outside the map.
type TaskTerminationFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
static NEXT_TASK_SLOT_REGISTRATION_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_task_slot_registration_id(counter: &AtomicU64) -> Result<u64, AgentError> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            (current != 0).then(|| current.checked_add(1)).flatten()
        })
        .map_err(|_| AgentError::internal("PROJECT_RUNTIME_LIFECYCLE_EXHAUSTED"))
}

struct TaskSlot {
    registration_id: u64,
    project_runtime_context: Option<ProjectRuntimeContext>,
    instance: OnceCell<AgentInstance>,
    lifecycle: Mutex<TaskSlotLifecycle>,
    cleanup_started: AtomicBool,
    prior_termination: Mutex<Option<TaskTerminationFuture>>,
    turn_holders: Mutex<HashSet<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TaskSlotLifecycle {
    Building {
        project_runtime_use: Option<ProjectRuntimeUse>,
        intent: BuildIntent,
    },
    Ready,
    WarmIdle,
    TurnActive {
        turn_id: String,
    },
    Finished,
    FailedEmpty,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuildIntent {
    Warmup,
    Turn,
}

#[derive(Debug, Clone)]
struct IdleTaskSnapshot {
    agent_type: AgentType,
    status: Option<ConversationStatus>,
    lifecycle: TaskSlotLifecycle,
    idle_ms: TimestampMs,
    last_activity_at: TimestampMs,
}

impl TaskSlot {
    fn new_with_intent(
        project_runtime_context: Option<ProjectRuntimeContext>,
        project_runtime_use: Option<ProjectRuntimeUse>,
        intent: BuildIntent,
        prior_termination: Option<TaskTerminationFuture>,
    ) -> Result<Arc<Self>, AgentError> {
        Ok(Arc::new(Self {
            registration_id: allocate_task_slot_registration_id(&NEXT_TASK_SLOT_REGISTRATION_ID)?,
            project_runtime_context,
            instance: OnceCell::new(),
            lifecycle: Mutex::new(TaskSlotLifecycle::Building {
                project_runtime_use,
                intent,
            }),
            cleanup_started: AtomicBool::new(false),
            prior_termination: Mutex::new(prior_termination),
            turn_holders: Mutex::new(HashSet::new()),
        }))
    }

    fn get(&self) -> Option<&AgentInstance> {
        let ready = self.lifecycle.lock().is_ok_and(|lifecycle| {
            matches!(
                *lifecycle,
                TaskSlotLifecycle::Ready
                    | TaskSlotLifecycle::WarmIdle
                    | TaskSlotLifecycle::TurnActive { .. }
                    | TaskSlotLifecycle::Finished
            )
        });
        ready.then(|| self.instance.get()).flatten()
    }

    fn lifecycle(&self) -> Result<TaskSlotLifecycle, AgentError> {
        self.lifecycle
            .lock()
            .map(|lifecycle| lifecycle.clone())
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_LIFECYCLE_UNAVAILABLE"))
    }

    fn admit_exact(
        &self,
        requested_use: Option<&ProjectRuntimeUse>,
        requested_intent: BuildIntent,
    ) -> Result<(), AgentError> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_LIFECYCLE_UNAVAILABLE"))?;
        match (&mut *lifecycle, requested_use, requested_intent) {
            (
                TaskSlotLifecycle::Building {
                    project_runtime_use: None,
                    intent,
                },
                None,
                requested_intent,
            ) => {
                if requested_intent == BuildIntent::Turn {
                    *intent = BuildIntent::Turn;
                }
                Ok(())
            }
            (TaskSlotLifecycle::Ready, None, _) => Ok(()),
            (TaskSlotLifecycle::WarmIdle, None, BuildIntent::Warmup) => Ok(()),
            (TaskSlotLifecycle::Finished, None, BuildIntent::Warmup) => {
                *lifecycle = TaskSlotLifecycle::WarmIdle;
                Ok(())
            }
            (TaskSlotLifecycle::WarmIdle | TaskSlotLifecycle::Finished, None, BuildIntent::Turn) => {
                *lifecycle = TaskSlotLifecycle::Ready;
                Ok(())
            }
            (
                TaskSlotLifecycle::Building {
                    project_runtime_use: Some(current),
                    intent,
                },
                Some(requested),
                requested_intent,
            ) => {
                let admitted = match (&*current, requested) {
                    (ProjectRuntimeUse::Warmup, ProjectRuntimeUse::Turn { .. }) => {
                        *current = requested.clone();
                        true
                    }
                    (ProjectRuntimeUse::Turn { turn_id: active }, ProjectRuntimeUse::Turn { turn_id })
                        if active == turn_id =>
                    {
                        true
                    }
                    (ProjectRuntimeUse::Turn { .. }, ProjectRuntimeUse::Warmup)
                    | (ProjectRuntimeUse::Warmup, ProjectRuntimeUse::Warmup) => true,
                    _ => false,
                };
                if !admitted {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_TURN_ACTIVE"));
                }
                if requested_intent == BuildIntent::Turn {
                    *intent = BuildIntent::Turn;
                }
                Ok(())
            }
            (TaskSlotLifecycle::WarmIdle, Some(ProjectRuntimeUse::Warmup), BuildIntent::Warmup) => Ok(()),
            (TaskSlotLifecycle::Finished, Some(ProjectRuntimeUse::Warmup), BuildIntent::Warmup) => {
                *lifecycle = TaskSlotLifecycle::WarmIdle;
                Ok(())
            }
            (
                TaskSlotLifecycle::WarmIdle | TaskSlotLifecycle::Finished,
                Some(ProjectRuntimeUse::Turn { turn_id }),
                BuildIntent::Turn,
            ) => {
                *lifecycle = TaskSlotLifecycle::TurnActive {
                    turn_id: turn_id.clone(),
                };
                Ok(())
            }
            (TaskSlotLifecycle::TurnActive { .. }, Some(ProjectRuntimeUse::Warmup), BuildIntent::Warmup) => Ok(()),
            (
                TaskSlotLifecycle::TurnActive { turn_id: active },
                Some(ProjectRuntimeUse::Turn { turn_id }),
                BuildIntent::Turn,
            ) if active == turn_id => Ok(()),
            (TaskSlotLifecycle::FailedEmpty, requested_use, requested_intent) => {
                *lifecycle = TaskSlotLifecycle::Building {
                    project_runtime_use: requested_use.cloned(),
                    intent: requested_intent,
                };
                Ok(())
            }
            (TaskSlotLifecycle::Invalidated, _, _) => Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_INVALIDATED")),
            _ => Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT")),
        }
    }

    fn mark_ready(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock()
            && let TaskSlotLifecycle::Building {
                project_runtime_use,
                intent,
            } = &*lifecycle
        {
            let project_runtime_use = project_runtime_use.clone();
            let intent = *intent;
            *lifecycle = match (project_runtime_use, intent) {
                (None, BuildIntent::Warmup) => TaskSlotLifecycle::WarmIdle,
                (None, BuildIntent::Turn) => TaskSlotLifecycle::Ready,
                (Some(ProjectRuntimeUse::Warmup), _) => TaskSlotLifecycle::WarmIdle,
                (Some(ProjectRuntimeUse::Turn { turn_id }), _) => TaskSlotLifecycle::TurnActive { turn_id },
            };
        }
    }

    fn mark_failed(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock()
            && matches!(*lifecycle, TaskSlotLifecycle::Building { .. })
        {
            *lifecycle = TaskSlotLifecycle::FailedEmpty;
        }
    }

    fn mark_invalidated(&self) {
        if let Ok(mut lifecycle) = self.lifecycle.lock() {
            *lifecycle = TaskSlotLifecycle::Invalidated;
        }
    }

    fn is_invalidated(&self) -> bool {
        self.lifecycle()
            .is_ok_and(|lifecycle| lifecycle == TaskSlotLifecycle::Invalidated)
    }

    fn register_turn_holder(&self, permit_id: usize) -> Result<(), AgentError> {
        self.turn_holders
            .lock()
            .map_err(|_| AgentError::internal("PROJECT_RUNTIME_LIFECYCLE_UNAVAILABLE"))?
            .insert(permit_id);
        Ok(())
    }

    fn release_turn_holder(&self, turn_id: &str, permit_id: usize) {
        let no_holders = self
            .turn_holders
            .lock()
            .map(|mut holders| {
                holders.remove(&permit_id);
                holders.is_empty()
            })
            .unwrap_or(false);
        if no_holders
            && let Ok(mut lifecycle) = self.lifecycle.lock()
            && matches!(&*lifecycle, TaskSlotLifecycle::TurnActive { turn_id: active } if active == turn_id)
        {
            *lifecycle = TaskSlotLifecycle::Finished;
        }
    }

    fn start_cleanup(&self) -> bool {
        self.cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn take_prior_termination(&self) -> Result<Option<TaskTerminationFuture>, AgentError> {
        self.prior_termination
            .lock()
            .map(|mut guard| guard.take())
            .map_err(|_| AgentError::internal("Project runtime termination fence is unavailable"))
    }

    fn idle_snapshot(&self, idle_threshold_ms: TimestampMs, now: TimestampMs) -> Option<IdleTaskSnapshot> {
        let lifecycle = self.lifecycle().ok()?;
        let agent = self.get()?;
        let agent_type = agent.agent_type();
        let status = agent.status();
        let last_activity_at = agent.last_activity_at();
        let idle_ms = now.saturating_sub(last_activity_at);
        let warm_resident = lifecycle == TaskSlotLifecycle::WarmIdle;
        let completed_turn = status == Some(ConversationStatus::Finished)
            && matches!(lifecycle, TaskSlotLifecycle::Ready | TaskSlotLifecycle::Finished);

        (agent_type == AgentType::Acp && idle_ms > idle_threshold_ms && (warm_resident || completed_turn)).then_some(
            IdleTaskSnapshot {
                agent_type,
                status,
                lifecycle,
                idle_ms,
                last_activity_at,
            },
        )
    }
}

type SharedTaskSlot = Arc<TaskSlot>;

/// Default implementation of [`IWorkerTaskManager`] using a concurrent hash map.
pub struct WorkerTaskManagerImpl {
    tasks: DashMap<String, SharedTaskSlot>,
    factory: AgentFactory,
}

impl WorkerTaskManagerImpl {
    pub fn new(factory: AgentFactory) -> Self {
        Self {
            tasks: DashMap::new(),
            factory,
        }
    }

    /// Look up a fully-initialised instance by conversation id.
    fn initialised_instance(&self, conversation_id: &str) -> Option<AgentInstance> {
        self.tasks.get(conversation_id).and_then(|slot| slot.get().cloned())
    }

    fn select_slot(
        &self,
        conversation_id: &str,
        requested_context: Option<ProjectRuntimeContext>,
        requested_use: Option<&ProjectRuntimeUse>,
        requested_intent: BuildIntent,
    ) -> Result<SharedTaskSlot, AgentError> {
        use dashmap::mapref::entry::Entry;

        match self.tasks.entry(conversation_id.to_owned()) {
            Entry::Vacant(entry) => {
                let slot =
                    TaskSlot::new_with_intent(requested_context, requested_use.cloned(), requested_intent, None)?;
                entry.insert(Arc::clone(&slot));
                Ok(slot)
            }
            Entry::Occupied(mut entry) => {
                let existing = Arc::clone(entry.get());
                match (existing.project_runtime_context.as_ref(), requested_context.as_ref()) {
                    (None, None) => {
                        existing.admit_exact(None, requested_intent)?;
                        return Ok(existing);
                    }
                    (Some(previous), Some(requested)) if previous.same_runtime_as(requested) => {
                        existing.admit_exact(requested_use, requested_intent)?;
                        return Ok(existing);
                    }
                    _ => {}
                }

                let (Some(previous), Some(requested)) =
                    (existing.project_runtime_context.as_ref(), requested_context.as_ref())
                else {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                };
                if !requested.is_strictly_newer_than(previous) {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                }

                let prior_termination = match existing.lifecycle()? {
                    TaskSlotLifecycle::Building { .. } | TaskSlotLifecycle::TurnActive { .. } => {
                        return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                    }
                    TaskSlotLifecycle::WarmIdle | TaskSlotLifecycle::Finished => {
                        let Some(agent) = existing.get() else {
                            return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                        };
                        if agent.status() == Some(ConversationStatus::Running) {
                            return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                        }
                        existing.start_cleanup().then(|| agent.kill_and_wait(None))
                    }
                    TaskSlotLifecycle::FailedEmpty => None,
                    TaskSlotLifecycle::Invalidated => {
                        return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_INVALIDATED"));
                    }
                    TaskSlotLifecycle::Ready => {
                        return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                    }
                };

                existing.mark_invalidated();
                let replacement = TaskSlot::new_with_intent(
                    requested_context,
                    requested_use.cloned(),
                    requested_intent,
                    prior_termination,
                )?;
                entry.insert(Arc::clone(&replacement));
                Ok(replacement)
            }
        }
    }

    async fn get_or_build_task_with_intent(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
        intent: BuildIntent,
    ) -> Result<AgentInstance, AgentError> {
        let project_runtime = options.project_runtime_context.is_some();
        let project_execution = match (&options.project_runtime_context, &options.project_runtime_execution) {
            (Some(context), Some(permit)) if permit.matches(conversation_id, context) => {
                let intent_matches = matches!(
                    (intent, permit.runtime_use()),
                    (BuildIntent::Warmup, ProjectRuntimeUse::Warmup)
                        | (BuildIntent::Turn, ProjectRuntimeUse::Turn { .. })
                );
                if !intent_matches {
                    return Err(AgentError::bad_request("PROJECT_RUNTIME_PERMIT_USE_MISMATCH"));
                }
                Some(permit.clone())
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(AgentError::bad_request("PROJECT_RUNTIME_PERMIT_REQUIRED"));
            }
            (Some(_), Some(_)) => return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_INVALIDATED")),
            (None, None) => None,
        };
        self.get_or_build_task_under_project_fence(conversation_id, options, project_runtime, project_execution, intent)
            .await
    }
}

#[async_trait]
impl IWorkerTaskManager for WorkerTaskManagerImpl {
    fn get_task(&self, conversation_id: &str) -> Option<AgentInstance> {
        self.initialised_instance(conversation_id)
    }

    async fn get_or_build_task(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
    ) -> Result<AgentInstance, AgentError> {
        self.get_or_build_task_with_intent(conversation_id, options, BuildIntent::Turn)
            .await
    }

    async fn get_or_build_warm_task(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
    ) -> Result<AgentInstance, AgentError> {
        self.get_or_build_task_with_intent(conversation_id, options, BuildIntent::Warmup)
            .await
    }

    fn kill(&self, conversation_id: &str, reason: Option<AgentKillReason>) -> Result<(), AgentError> {
        if let Some((id, slot)) = self.tasks.remove(conversation_id) {
            let agent_type = slot.get().map(|agent| agent.agent_type());
            if matches!(reason, Some(AgentKillReason::IdleTimeout)) {
                info!(
                    conversation_id = %id,
                    ?agent_type,
                    reason = %"IdleTimeout",
                    "Idle kill: task removed from manager"
                );
            } else {
                info!(conversation_id = %id, ?reason, "Killing agent task");
            }
            slot.mark_invalidated();
            if let Some(agent) = slot.instance.get()
                && slot.start_cleanup()
            {
                agent.kill(reason)?;
            }
        }
        Ok(())
    }

    fn kill_and_wait(
        &self,
        conversation_id: &str,
        reason: Option<AgentKillReason>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        if let Some((id, slot)) = self.tasks.remove(conversation_id) {
            let agent_type = slot.get().map(|agent| agent.agent_type());
            if matches!(reason, Some(AgentKillReason::IdleTimeout)) {
                info!(
                    conversation_id = %id,
                    ?agent_type,
                    reason = %"IdleTimeout",
                    "Idle kill: task removed from manager"
                );
            } else {
                info!(conversation_id = %id, ?reason, "Killing agent task (awaitable)");
            }
            slot.mark_invalidated();
            if let Some(agent) = slot.instance.get()
                && slot.start_cleanup()
            {
                return agent.kill_and_wait(reason);
            }
        }
        Box::pin(std::future::ready(()))
    }

    async fn clear(&self) {
        let keys: Vec<String> = self.tasks.iter().map(|r| r.key().clone()).collect();
        let mut waits = Vec::new();
        for key in keys {
            if let Some((id, slot)) = self.tasks.remove(&key) {
                info!(conversation_id = %id, "Clearing agent task");
                slot.mark_invalidated();
                if let Some(agent) = slot.instance.get()
                    && slot.start_cleanup()
                {
                    waits.push(agent.kill_and_wait(None));
                }
            }
        }
        join_all(waits).await;
    }

    fn active_count(&self) -> usize {
        self.tasks.iter().filter(|entry| entry.value().get().is_some()).count()
    }

    fn collect_idle(&self, idle_threshold_ms: TimestampMs) -> Vec<String> {
        let now = now_ms();
        self.tasks
            .iter()
            .filter_map(|entry| {
                let snapshot = entry.value().idle_snapshot(idle_threshold_ms, now)?;
                info!(
                    conversation_id = %entry.key(),
                    agent_type = ?snapshot.agent_type,
                    status = ?snapshot.status,
                    lifecycle = ?snapshot.lifecycle,
                    idle_ms = snapshot.idle_ms,
                    threshold_ms = idle_threshold_ms,
                    last_activity_at = snapshot.last_activity_at,
                    "Idle scan: selected idle agent"
                );
                Some(entry.key().clone())
            })
            .collect()
    }

    async fn kill_idle_if_still_eligible(&self, conversation_id: &str, idle_threshold_ms: TimestampMs) -> bool {
        use dashmap::mapref::entry::Entry;

        let removed = match self.tasks.entry(conversation_id.to_owned()) {
            Entry::Vacant(_) => None,
            Entry::Occupied(entry) => {
                if entry.get().idle_snapshot(idle_threshold_ms, now_ms()).is_none() {
                    None
                } else {
                    Some(entry.remove_entry())
                }
            }
        };
        let Some((id, slot)) = removed else {
            debug!(
                conversation_id,
                threshold_ms = idle_threshold_ms,
                "Idle scan: candidate became active before cleanup"
            );
            return false;
        };

        let agent_type = slot.get().map(|agent| agent.agent_type());
        info!(
            conversation_id = %id,
            ?agent_type,
            reason = %"IdleTimeout",
            "Idle kill: task removed from manager"
        );
        slot.mark_invalidated();
        if let Some(agent) = slot.instance.get()
            && slot.start_cleanup()
        {
            agent.kill_and_wait(Some(AgentKillReason::IdleTimeout)).await;
        }
        true
    }
}

impl WorkerTaskManagerImpl {
    async fn get_or_build_task_under_project_fence(
        &self,
        conversation_id: &str,
        options: BuildTaskOptions,
        project_runtime: bool,
        project_execution: Option<ProjectRuntimeExecutionPermit>,
        intent: BuildIntent,
    ) -> Result<AgentInstance, AgentError> {
        let requested_use = project_execution
            .as_ref()
            .map(ProjectRuntimeExecutionPermit::runtime_use);
        let slot = self.select_slot(
            conversation_id,
            options.project_runtime_context.clone(),
            requested_use,
            intent,
        )?;
        if let Some(ProjectRuntimeUse::Turn { turn_id }) = requested_use {
            let weak_slot = Arc::downgrade(&slot);
            let turn_id = turn_id.clone();
            let permit = project_execution
                .as_ref()
                .expect("requested use came from execution permit");
            let permit_id = permit.identity();
            let slot_id = slot.registration_id;
            let registered = permit.register_release_callback(
                slot_id,
                Arc::new(move || {
                    if let Some(slot) = weak_slot.upgrade() {
                        slot.release_turn_holder(&turn_id, permit_id);
                    }
                }),
            )?;
            if registered {
                slot.register_turn_holder(permit_id)?;
            }
        }

        // `OnceCell::get_or_try_init` serialises concurrent initialisers:
        // the first caller to reach it runs the factory, every other caller
        // awaits the same future and ends up with the same instance. On
        // failure the cell stays empty so a later caller can retry.
        let factory = self.factory.clone();
        let slot_for_initialisation = Arc::clone(&slot);
        let instance = slot
            .instance
            .get_or_try_init(|| async move {
                if let Some(prior_termination) = slot_for_initialisation.take_prior_termination()? {
                    prior_termination.await;
                }
                factory(options).await
            })
            .await
            .map_err(|error| match error {
                AgentError::WorkspacePathRuntimeUnavailable(_) if project_runtime => {
                    AgentError::bad_request("PROJECT_RUNTIME_PATH_UNAVAILABLE")
                }
                other => other,
            });
        let instance = match instance {
            Ok(instance) => instance,
            Err(error) => {
                slot.mark_failed();
                return Err(error);
            }
        };
        if slot.is_invalidated() {
            if slot.start_cleanup() {
                let _ = instance.kill(None);
            }
            return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_INVALIDATED"));
        }
        slot.mark_ready();
        Ok(instance.clone())
    }
}

/// Wired up by `aionui-app` so deleting a conversation tears down its
/// agent process. Without this hook, ACP/aionrs subprocesses keep
/// streaming events for a `conversation_id` whose DB row is already gone
/// (Sentry ELECTRON-1BD).
#[async_trait]
impl OnConversationDelete for WorkerTaskManagerImpl {
    async fn on_conversation_deleted(&self, conversation_id: &str) {
        if let Err(e) = self.kill(conversation_id, Some(AgentKillReason::ConversationDeleted)) {
            warn!(
                conversation_id,
                error = %ErrorChain(&e),
                "Failed to kill agent task on conversation delete (non-fatal)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_task::{IAgentTask, IMockAgent};
    use crate::protocol::events::AgentStreamEvent;
    use crate::session_context::{
        AcpSessionBuildContext, AgentSessionContext, AgentSessionKind, ConversationContext, WorkspaceContext,
    };
    use crate::types::{ProjectRuntimeContext, SendMessageData};
    use aionui_common::{AgentKillReason, AgentType, ConversationStatus, ProviderWithModel};
    use futures_util::FutureExt;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use tokio::sync::{Notify, broadcast};

    /// A minimal mock agent for testing task manager logic. Lives behind
    /// the `AgentInstance::Mock` trait-object variant so we don't have to
    /// stand up a real `AcpAgentManager` just to exercise lifecycle
    /// dispatch.
    struct MockAgent {
        agent_type: AgentType,
        conversation_id: String,
        workspace: String,
        status: Option<ConversationStatus>,
        last_activity: AtomicI64,
        event_tx: broadcast::Sender<AgentStreamEvent>,
        kill_calls: Option<Arc<AtomicUsize>>,
    }

    impl MockAgent {
        fn new(conversation_id: &str, status: Option<ConversationStatus>) -> Self {
            let (event_tx, _) = broadcast::channel(16);
            Self {
                agent_type: AgentType::Acp,
                conversation_id: conversation_id.to_owned(),
                workspace: "/tmp/test".to_owned(),
                status,
                last_activity: AtomicI64::new(now_ms()),
                event_tx,
                kill_calls: None,
            }
        }

        fn with_agent_type(mut self, t: AgentType) -> Self {
            self.agent_type = t;
            self
        }

        fn with_last_activity(mut self, ts: TimestampMs) -> Self {
            self.last_activity = AtomicI64::new(ts);
            self
        }

        fn with_kill_counter(mut self, kill_calls: Arc<AtomicUsize>) -> Self {
            self.kill_calls = Some(kill_calls);
            self
        }
    }

    #[async_trait::async_trait]
    impl IAgentTask for MockAgent {
        fn agent_type(&self) -> AgentType {
            self.agent_type
        }
        fn conversation_id(&self) -> &str {
            &self.conversation_id
        }
        fn workspace(&self) -> &str {
            &self.workspace
        }
        fn status(&self) -> Option<ConversationStatus> {
            self.status
        }
        fn last_activity_at(&self) -> TimestampMs {
            self.last_activity.load(Ordering::Relaxed)
        }
        fn subscribe(&self) -> broadcast::Receiver<AgentStreamEvent> {
            self.event_tx.subscribe()
        }
        async fn send_message(
            &self,
            _data: SendMessageData,
        ) -> Result<(), crate::protocol::send_error::AgentSendError> {
            Ok(())
        }
        async fn cancel(&self) -> Result<(), AgentError> {
            Ok(())
        }
        fn kill(&self, _reason: Option<AgentKillReason>) -> Result<(), AgentError> {
            if let Some(kill_calls) = &self.kill_calls {
                kill_calls.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    impl IMockAgent for MockAgent {}

    fn make_options(conversation_id: &str) -> BuildTaskOptions {
        BuildTaskOptions::new(AgentSessionContext {
            conversation: ConversationContext {
                conversation_id: conversation_id.into(),
                user_id: "user-1".into(),
                agent_type: AgentType::Acp,
                source: None,
            },
            workspace: WorkspaceContext {
                path: "/tmp/test".into(),
                stored_path: "/tmp/test".into(),
                is_custom: true,
                project_environment_hint: None,
            },
            model: ProviderWithModel {
                provider_id: "p1".into(),
                model: "test".into(),
                use_model: None,
            },
            skills: vec![],
            team: None,
            kind: AgentSessionKind::Acp(Box::new(AcpSessionBuildContext {
                config: Default::default(),
                team: None,
                belongs_to_team: false,
                session_id: None,
                session_snapshot: None,
            })),
        })
    }

    fn project_context(
        runtime: &str,
        hint: &str,
        root_generation: u64,
        backend_generation: u64,
    ) -> ProjectRuntimeContext {
        ProjectRuntimeContext {
            runtime_fingerprint: runtime.to_owned(),
            environment_hint_fingerprint: hint.to_owned(),
            project_binding_revision: 1,
            process_runtime_generation: 1,
            backend_generation: format!("bg1:{backend_generation}"),
            root_catalog_revision: root_generation,
            root_ownership_revision: root_generation,
            project_catalog_revision: root_generation,
        }
    }

    fn make_project_options(
        conversation_id: &str,
        runtime: &str,
        hint: &str,
        root_generation: u64,
        backend_generation: u64,
    ) -> BuildTaskOptions {
        make_project_options_for_use(
            conversation_id,
            runtime,
            hint,
            root_generation,
            backend_generation,
            ProjectRuntimeUse::Turn {
                turn_id: "test-turn".to_owned(),
            },
        )
    }

    fn make_project_warmup_options(
        conversation_id: &str,
        runtime: &str,
        hint: &str,
        root_generation: u64,
        backend_generation: u64,
    ) -> BuildTaskOptions {
        make_project_options_for_use(
            conversation_id,
            runtime,
            hint,
            root_generation,
            backend_generation,
            ProjectRuntimeUse::Warmup,
        )
    }

    fn make_project_options_for_use(
        conversation_id: &str,
        runtime: &str,
        hint: &str,
        root_generation: u64,
        backend_generation: u64,
        runtime_use: ProjectRuntimeUse,
    ) -> BuildTaskOptions {
        let context = project_context(runtime, hint, root_generation, backend_generation);
        let permit = ProjectRuntimeExecutionPermit::test_only(conversation_id, &context, runtime_use);
        BuildTaskOptions::new(make_options(conversation_id).context)
            .with_project_runtime_context(context)
            .with_project_runtime_execution(permit)
    }

    fn mock_instance(agent: MockAgent) -> AgentInstance {
        AgentInstance::Mock(Arc::new(agent))
    }

    fn make_manager() -> WorkerTaskManagerImpl {
        let factory: AgentFactory = Arc::new(|opts: BuildTaskOptions| {
            async move { Ok(mock_instance(MockAgent::new(opts.conversation_id(), None))) }.boxed()
        });
        WorkerTaskManagerImpl::new(factory)
    }

    fn capture_logs(max_level: tracing::Level, f: impl FnOnce()) -> String {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt;

        #[derive(Clone)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);

        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let make_writer = {
            let buffer = Arc::clone(&buffer);
            move || SharedBuf(Arc::clone(&buffer))
        };

        let subscriber = fmt::Subscriber::builder()
            .with_max_level(max_level)
            .with_writer(make_writer)
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, f);

        String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
    }

    /// Two [`AgentInstance`]s point to the same underlying agent iff they
    /// share an `Arc` — check by pointer identity on the inner trait object.
    fn same_mock(a: &AgentInstance, b: &AgentInstance) -> bool {
        match (a, b) {
            (AgentInstance::Mock(x), AgentInstance::Mock(y)) => Arc::ptr_eq(x, y),
            _ => false,
        }
    }

    fn expect_agent_error(result: Result<AgentInstance, AgentError>) -> AgentError {
        match result {
            Ok(_) => panic!("expected agent error"),
            Err(error) => error,
        }
    }

    #[test]
    fn get_task_returns_none_when_empty() {
        let mgr = make_manager();
        assert!(mgr.get_task("nonexistent").is_none());
    }

    #[tokio::test]
    async fn get_or_build_creates_task() {
        let mgr = make_manager();
        let instance = mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        assert_eq!(instance.conversation_id(), "conv-1");
        assert_eq!(mgr.active_count(), 1);
    }

    #[tokio::test]
    async fn get_or_build_returns_existing() {
        let mgr = make_manager();
        let h1 = mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        let h2 = mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        assert!(same_mock(&h1, &h2));
        assert_eq!(mgr.active_count(), 1);
    }

    #[tokio::test]
    async fn warmup_builds_warm_idle_for_legacy_and_project_tasks() {
        let mgr = make_manager();
        mgr.get_or_build_warm_task("conv-warm", make_options("conv-warm"))
            .await
            .unwrap();
        assert_eq!(
            mgr.tasks.get("conv-warm").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::WarmIdle
        );

        mgr.get_or_build_warm_task(
            "conv-project-warm",
            make_project_warmup_options("conv-project-warm", "runtime-a", "hint-a", 1, 1),
        )
        .await
        .unwrap();
        assert_eq!(
            mgr.tasks.get("conv-project-warm").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::WarmIdle
        );
    }

    #[tokio::test]
    async fn turn_promotes_warm_idle_without_rebuilding() {
        let builds = Arc::new(AtomicUsize::new(0));
        let builds_for_factory = Arc::clone(&builds);
        let factory: AgentFactory = Arc::new(move |options| {
            let builds = Arc::clone(&builds_for_factory);
            async move {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(mock_instance(MockAgent::new(options.conversation_id(), None)))
            }
            .boxed()
        });
        let mgr = WorkerTaskManagerImpl::new(factory);

        let warmed = mgr
            .get_or_build_warm_task("conv-promote", make_options("conv-promote"))
            .await
            .unwrap();
        let active = mgr
            .get_or_build_task("conv-promote", make_options("conv-promote"))
            .await
            .unwrap();

        assert!(same_mock(&warmed, &active));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(
            mgr.tasks.get("conv-promote").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::Ready
        );
    }

    #[tokio::test]
    async fn project_rewarm_moves_finished_task_back_to_warm_idle() {
        let mgr = make_manager();
        let context = project_context("runtime-a", "hint-a", 1, 1);
        let turn_permit = ProjectRuntimeExecutionPermit::test_only(
            "conv-project-rewarm",
            &context,
            ProjectRuntimeUse::Turn {
                turn_id: "turn-1".to_owned(),
            },
        );
        mgr.get_or_build_task(
            "conv-project-rewarm",
            BuildTaskOptions::new(make_options("conv-project-rewarm").context)
                .with_project_runtime_context(context.clone())
                .with_project_runtime_execution(turn_permit.clone()),
        )
        .await
        .unwrap();
        drop(turn_permit);
        assert_eq!(
            mgr.tasks.get("conv-project-rewarm").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::Finished
        );

        let warm_permit =
            ProjectRuntimeExecutionPermit::test_only("conv-project-rewarm", &context, ProjectRuntimeUse::Warmup);
        mgr.get_or_build_warm_task(
            "conv-project-rewarm",
            BuildTaskOptions::new(make_options("conv-project-rewarm").context)
                .with_project_runtime_context(context)
                .with_project_runtime_execution(warm_permit),
        )
        .await
        .unwrap();

        assert_eq!(
            mgr.tasks.get("conv-project-rewarm").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::WarmIdle
        );
    }

    #[tokio::test]
    async fn turn_during_warmup_build_prevents_late_warm_completion_from_downgrading() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let builds = Arc::clone(&builds);
            Arc::new(move |options| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                let builds = Arc::clone(&builds);
                async move {
                    builds.fetch_add(1, Ordering::SeqCst);
                    entered.notify_one();
                    release.notified().await;
                    Ok(mock_instance(MockAgent::new(options.conversation_id(), None)))
                }
                .boxed()
            })
        };
        let mgr = Arc::new(WorkerTaskManagerImpl::new(factory));
        let warm = {
            let mgr = Arc::clone(&mgr);
            tokio::spawn(async move { mgr.get_or_build_warm_task("conv-race", make_options("conv-race")).await })
        };
        entered.notified().await;
        let turn = {
            let mgr = Arc::clone(&mgr);
            tokio::spawn(async move { mgr.get_or_build_task("conv-race", make_options("conv-race")).await })
        };

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let promoted = mgr.tasks.get("conv-race").is_some_and(|slot| {
                    matches!(
                        slot.lifecycle(),
                        Ok(TaskSlotLifecycle::Building {
                            intent: BuildIntent::Turn,
                            ..
                        })
                    )
                });
                if promoted {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("turn intent should promote the shared build");

        release.notify_waiters();
        warm.await.unwrap().unwrap();
        turn.await.unwrap().unwrap();

        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(
            mgr.tasks.get("conv-race").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::Ready
        );
    }

    #[tokio::test]
    async fn project_runtime_permit_use_must_match_build_intent() {
        let mgr = make_manager();
        let turn_with_warm_permit = expect_agent_error(
            mgr.get_or_build_task(
                "conv-project",
                make_project_warmup_options("conv-project", "runtime-a", "hint-a", 1, 1),
            )
            .await,
        );
        assert!(
            matches!(turn_with_warm_permit, AgentError::BadRequest(reason) if reason == "PROJECT_RUNTIME_PERMIT_USE_MISMATCH")
        );

        let warm_with_turn_permit = expect_agent_error(
            mgr.get_or_build_warm_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
            )
            .await,
        );
        assert!(
            matches!(warm_with_turn_permit, AgentError::BadRequest(reason) if reason == "PROJECT_RUNTIME_PERMIT_USE_MISMATCH")
        );
    }

    #[tokio::test]
    async fn project_task_reuses_only_the_exact_attested_runtime_context() {
        let mgr = make_manager();
        let first = mgr
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
            )
            .await
            .unwrap();
        let second = mgr
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 99, 1),
            )
            .await
            .unwrap();

        assert!(same_mock(&first, &second));
    }

    #[tokio::test]
    async fn project_task_rejects_context_change_while_active() {
        let mgr = make_manager();
        let active_context = project_context("runtime-a", "hint-a", 1, 1);
        let active_permit = ProjectRuntimeExecutionPermit::test_only(
            "conv-project",
            &active_context,
            ProjectRuntimeUse::Turn {
                turn_id: "active-turn".to_owned(),
            },
        );
        mgr.get_or_build_task(
            "conv-project",
            BuildTaskOptions::new(make_options("conv-project").context)
                .with_project_runtime_context(active_context)
                .with_project_runtime_execution(active_permit.clone()),
        )
        .await
        .unwrap();

        let error = expect_agent_error(
            mgr.get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-b", "hint-a", 2, 1),
            )
            .await,
        );
        assert!(matches!(error, AgentError::Conflict(reason) if reason == "PROJECT_RUNTIME_CONTEXT_CONFLICT"));
        drop(active_permit);
    }

    #[tokio::test]
    async fn finished_project_task_rebuilds_for_strictly_newer_generation_and_kills_old() {
        let builds = Arc::new(AtomicUsize::new(0));
        let kills = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let builds = Arc::clone(&builds);
            let kills = Arc::clone(&kills);
            Arc::new(move |options: BuildTaskOptions| {
                let builds = Arc::clone(&builds);
                let kills = Arc::clone(&kills);
                async move {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok(mock_instance(
                        MockAgent::new(options.conversation_id(), Some(ConversationStatus::Finished))
                            .with_kill_counter(kills),
                    ))
                }
                .boxed()
            })
        };
        let mgr = WorkerTaskManagerImpl::new(factory);
        let first = mgr
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
            )
            .await
            .unwrap();
        let second = mgr
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-b", "hint-b", 2, 1),
            )
            .await
            .unwrap();

        assert!(!same_mock(&first, &second));
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(kills.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn finished_project_task_rejects_stale_aba_and_same_generation_hint_drift() {
        let factory: AgentFactory = Arc::new(|options: BuildTaskOptions| {
            async move {
                Ok(mock_instance(MockAgent::new(
                    options.conversation_id(),
                    Some(ConversationStatus::Finished),
                )))
            }
            .boxed()
        });
        let mgr = WorkerTaskManagerImpl::new(factory);
        mgr.get_or_build_task(
            "conv-project",
            make_project_options("conv-project", "runtime-a", "hint-a", 2, 2),
        )
        .await
        .unwrap();

        for options in [
            make_project_options("conv-project", "runtime-old", "hint-old", 1, 1),
            make_project_options("conv-project", "runtime-a", "hint-drift", 2, 2),
        ] {
            let error = expect_agent_error(mgr.get_or_build_task("conv-project", options).await);
            assert!(matches!(error, AgentError::Conflict(reason) if reason == "PROJECT_RUNTIME_CONTEXT_CONFLICT"));
        }
    }

    #[tokio::test]
    async fn finished_project_task_rejects_cross_backend_generation_even_with_newer_catalog_revisions() {
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let builds = Arc::clone(&builds);
            Arc::new(move |options: BuildTaskOptions| {
                let builds = Arc::clone(&builds);
                async move {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok(mock_instance(MockAgent::new(
                        options.conversation_id(),
                        Some(ConversationStatus::Finished),
                    )))
                }
                .boxed()
            })
        };
        let mgr = WorkerTaskManagerImpl::new(factory);
        mgr.get_or_build_task(
            "conv-project",
            make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
        )
        .await
        .unwrap();

        let error = expect_agent_error(
            mgr.get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-b", "hint-b", 99, 2),
            )
            .await,
        );

        assert!(matches!(error, AgentError::Conflict(reason) if reason == "PROJECT_RUNTIME_CONTEXT_CONFLICT"));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fresh_manager_after_backend_restart_accepts_only_its_new_generation() {
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let builds = Arc::clone(&builds);
            Arc::new(move |options: BuildTaskOptions| {
                let builds = Arc::clone(&builds);
                async move {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Ok(mock_instance(MockAgent::new(options.conversation_id(), None)))
                }
                .boxed()
            })
        };

        let before_restart = WorkerTaskManagerImpl::new(Arc::clone(&factory));
        before_restart
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 7, 1),
            )
            .await
            .unwrap();

        let after_restart = WorkerTaskManagerImpl::new(factory);
        after_restart
            .get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-b", "hint-b", 1, 2),
            )
            .await
            .unwrap();

        assert_eq!(before_restart.active_count(), 1);
        assert_eq!(after_restart.active_count(), 1);
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn project_root_remap_is_rejected_while_single_flight_build_is_in_progress() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let factory: AgentFactory = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            Arc::new(move |options: BuildTaskOptions| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok(mock_instance(MockAgent::new(options.conversation_id(), None)))
                }
                .boxed()
            })
        };
        let mgr = Arc::new(WorkerTaskManagerImpl::new(factory));
        let first = {
            let mgr = Arc::clone(&mgr);
            tokio::spawn(async move {
                mgr.get_or_build_task(
                    "conv-project",
                    make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
                )
                .await
            })
        };
        entered.notified().await;

        let remap = expect_agent_error(
            mgr.get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-b", "hint-b", 2, 2),
            )
            .await,
        );
        assert!(matches!(remap, AgentError::Conflict(reason) if reason == "PROJECT_RUNTIME_CONTEXT_CONFLICT"));
        release.notify_waiters();
        first.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn kill_during_project_build_invalidates_and_kills_late_factory_result() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let kills = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let kills = Arc::clone(&kills);
            Arc::new(move |options: BuildTaskOptions| {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                let kills = Arc::clone(&kills);
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok(mock_instance(
                        MockAgent::new(options.conversation_id(), None).with_kill_counter(kills),
                    ))
                }
                .boxed()
            })
        };
        let mgr = Arc::new(WorkerTaskManagerImpl::new(factory));
        let build = {
            let mgr = Arc::clone(&mgr);
            tokio::spawn(async move {
                mgr.get_or_build_task(
                    "conv-project",
                    make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
                )
                .await
            })
        };
        entered.notified().await;
        mgr.kill("conv-project", None).unwrap();
        release.notify_waiters();

        let error = expect_agent_error(build.await.unwrap());
        assert!(matches!(error, AgentError::Conflict(reason) if reason == "PROJECT_RUNTIME_CONTEXT_INVALIDATED"));
        assert_eq!(kills.load(Ordering::SeqCst), 1);
        assert_eq!(mgr.active_count(), 0);
    }

    #[tokio::test]
    async fn same_turn_permit_rebinds_release_callback_after_kill_and_rebuild() {
        let mgr = make_manager();
        let context = project_context("runtime-a", "hint-a", 1, 1);
        let permit = ProjectRuntimeExecutionPermit::test_only(
            "conv-project",
            &context,
            ProjectRuntimeUse::Turn {
                turn_id: "turn-replay".to_owned(),
            },
        );
        let options = || {
            BuildTaskOptions::new(make_options("conv-project").context)
                .with_project_runtime_context(context.clone())
                .with_project_runtime_execution(permit.clone())
        };

        mgr.get_or_build_task("conv-project", options()).await.unwrap();
        let first_registration_id = mgr.tasks.get("conv-project").unwrap().registration_id;
        assert!(matches!(
            mgr.tasks.get("conv-project").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::TurnActive { ref turn_id } if turn_id == "turn-replay"
        ));

        mgr.kill("conv-project", None).unwrap();
        mgr.get_or_build_task("conv-project", options()).await.unwrap();
        let second_registration_id = mgr.tasks.get("conv-project").unwrap().registration_id;
        assert_ne!(first_registration_id, second_registration_id);
        assert!(matches!(
            mgr.tasks.get("conv-project").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::TurnActive { ref turn_id } if turn_id == "turn-replay"
        ));

        drop(permit);
        assert_eq!(
            mgr.tasks.get("conv-project").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::Finished
        );
    }

    #[tokio::test]
    async fn project_factory_workspace_error_is_pathless_but_legacy_error_is_preserved() {
        let secret_path = "/private/seat-owner/project-alpha";
        let factory: AgentFactory = Arc::new(move |_| {
            let secret_path = secret_path.to_owned();
            async move { Err(AgentError::WorkspacePathRuntimeUnavailable(secret_path)) }.boxed()
        });
        let mgr = WorkerTaskManagerImpl::new(factory);

        let project_error = expect_agent_error(
            mgr.get_or_build_task(
                "conv-project",
                make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
            )
            .await,
        );
        assert!(
            matches!(project_error, AgentError::BadRequest(reason) if reason == "PROJECT_RUNTIME_PATH_UNAVAILABLE")
        );

        let legacy_error = expect_agent_error(mgr.get_or_build_task("conv-legacy", make_options("conv-legacy")).await);
        assert!(matches!(legacy_error, AgentError::WorkspacePathRuntimeUnavailable(path) if path == secret_path));
    }

    #[tokio::test]
    async fn get_or_build_is_single_flight_under_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_factory = Arc::clone(&calls);
        let factory: AgentFactory = Arc::new(move |opts: BuildTaskOptions| {
            let calls = Arc::clone(&calls_for_factory);
            async move {
                // Simulate a slow build (CLI spawn + initialize handshake).
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(mock_instance(MockAgent::new(opts.conversation_id(), None)))
            }
            .boxed()
        });
        let mgr = Arc::new(WorkerTaskManagerImpl::new(factory));

        // Ten concurrent callers all racing on the same conversation id.
        let mut joins = Vec::new();
        for _ in 0..10 {
            let mgr = Arc::clone(&mgr);
            joins.push(tokio::spawn(async move {
                mgr.get_or_build_task("conv-race", make_options("conv-race")).await
            }));
        }
        let handles: Vec<_> = futures_util::future::join_all(joins)
            .await
            .into_iter()
            .map(|r| r.unwrap().unwrap())
            .collect();

        assert_eq!(calls.load(Ordering::SeqCst), 1, "factory must run only once");
        assert_eq!(mgr.active_count(), 1);
        for h in handles.iter().skip(1) {
            assert!(same_mock(&handles[0], h), "all callers see the same handle");
        }
    }

    #[tokio::test]
    async fn get_or_build_retries_after_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let fail_next = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&fail_next);
        let factory: AgentFactory = Arc::new(move |opts: BuildTaskOptions| {
            let flag = Arc::clone(&flag);
            async move {
                if flag.swap(false, Ordering::SeqCst) {
                    Err(AgentError::internal("first call fails"))
                } else {
                    Ok(mock_instance(MockAgent::new(opts.conversation_id(), None)))
                }
            }
            .boxed()
        });
        let mgr = WorkerTaskManagerImpl::new(factory);

        // First call fails, slot stays empty.
        assert!(mgr.get_or_build_task("conv-1", make_options("conv-1")).await.is_err());
        // Second call retries and succeeds.
        let h = mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        assert_eq!(h.conversation_id(), "conv-1");
        assert_eq!(mgr.active_count(), 1);
    }

    #[tokio::test]
    async fn get_task_finds_existing() {
        let mgr = make_manager();
        mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        let handle = mgr.get_task("conv-1");
        assert!(handle.is_some());
        assert_eq!(handle.unwrap().conversation_id(), "conv-1");
    }

    #[tokio::test]
    async fn kill_removes_task() {
        let mgr = make_manager();
        mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        assert_eq!(mgr.active_count(), 1);

        mgr.kill("conv-1", Some(AgentKillReason::IdleTimeout)).unwrap();
        assert_eq!(mgr.active_count(), 0);
        assert!(mgr.get_task("conv-1").is_none());
    }

    #[test]
    fn kill_nonexistent_is_ok() {
        let factory: AgentFactory = Arc::new(|_| async { unreachable!() }.boxed());
        let mgr = WorkerTaskManagerImpl::new(factory);
        assert!(mgr.kill("nothing", None).is_ok());
    }

    #[test]
    fn task_slot_registration_id_exhaustion_fails_closed() {
        let exhausted = AtomicU64::new(u64::MAX);
        assert!(matches!(
            allocate_task_slot_registration_id(&exhausted),
            Err(AgentError::Internal(reason)) if reason == "PROJECT_RUNTIME_LIFECYCLE_EXHAUSTED"
        ));
    }

    #[tokio::test]
    async fn clear_removes_all() {
        let mgr = make_manager();
        mgr.get_or_build_task("conv-1", make_options("conv-1")).await.unwrap();
        mgr.get_or_build_task("conv-2", make_options("conv-2")).await.unwrap();
        assert_eq!(mgr.active_count(), 2);

        mgr.clear().await;
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn collect_idle_finds_finished_and_stale_acp_tasks() {
        let factory: AgentFactory = Arc::new(|_| async { unreachable!() }.boxed());
        let mgr = WorkerTaskManagerImpl::new(factory);

        // Helper: insert a pre-initialised slot bypassing the async factory path.
        let insert = |id: &str, instance: AgentInstance| {
            let slot = TaskSlot::new_with_intent(None, None, BuildIntent::Turn, None).unwrap();
            slot.instance.set(instance).ok();
            slot.mark_ready();
            mgr.tasks.insert(id.into(), slot);
        };

        // ACP + Finished + old activity → should be collected
        insert(
            "conv-stale",
            mock_instance(
                MockAgent::new("conv-stale", Some(ConversationStatus::Finished)).with_last_activity(now_ms() - 600_000),
            ),
        );

        // ACP + Finished + recent activity → should NOT be collected
        insert(
            "conv-recent",
            mock_instance(
                MockAgent::new("conv-recent", Some(ConversationStatus::Finished)).with_last_activity(now_ms()),
            ),
        );

        // ACP + Running + old activity → should NOT be collected
        insert(
            "conv-running",
            mock_instance(
                MockAgent::new("conv-running", Some(ConversationStatus::Running))
                    .with_last_activity(now_ms() - 600_000),
            ),
        );

        // Non-ACP (Aionrs) + Finished + old activity → should NOT be collected
        insert(
            "conv-aionrs",
            mock_instance(
                MockAgent::new("conv-aionrs", Some(ConversationStatus::Finished))
                    .with_agent_type(AgentType::Aionrs)
                    .with_last_activity(now_ms() - 600_000),
            ),
        );

        let idle = mgr.collect_idle(300_000); // 5-min threshold
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0], "conv-stale");
    }

    #[tokio::test]
    async fn collect_idle_finds_warm_resident_acp_without_finished_status() {
        let factory: AgentFactory = Arc::new(|options| {
            async move {
                Ok(mock_instance(
                    MockAgent::new(options.conversation_id(), None).with_last_activity(now_ms() - 600_000),
                ))
            }
            .boxed()
        });
        let mgr = WorkerTaskManagerImpl::new(factory);

        mgr.get_or_build_warm_task("conv-warm-idle", make_options("conv-warm-idle"))
            .await
            .unwrap();

        assert_eq!(mgr.collect_idle(300_000), vec!["conv-warm-idle".to_owned()]);
    }

    #[tokio::test]
    async fn idle_revalidation_skips_candidate_promoted_by_a_real_turn() {
        let kills = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let kills = Arc::clone(&kills);
            Arc::new(move |options| {
                let kills = Arc::clone(&kills);
                async move {
                    Ok(mock_instance(
                        MockAgent::new(options.conversation_id(), None)
                            .with_last_activity(now_ms() - 600_000)
                            .with_kill_counter(kills),
                    ))
                }
                .boxed()
            })
        };
        let mgr = WorkerTaskManagerImpl::new(factory);
        mgr.get_or_build_warm_task("conv-race", make_options("conv-race"))
            .await
            .unwrap();
        assert_eq!(mgr.collect_idle(300_000), vec!["conv-race".to_owned()]);

        mgr.get_or_build_task("conv-race", make_options("conv-race"))
            .await
            .unwrap();
        let killed = mgr.kill_idle_if_still_eligible("conv-race", 300_000).await;

        assert!(!killed);
        assert_eq!(kills.load(Ordering::SeqCst), 0);
        assert!(mgr.get_task("conv-race").is_some());
        assert_eq!(
            mgr.tasks.get("conv-race").unwrap().lifecycle().unwrap(),
            TaskSlotLifecycle::Ready
        );
    }

    #[tokio::test]
    async fn idle_revalidation_kills_candidate_that_remains_warm_idle() {
        let kills = Arc::new(AtomicUsize::new(0));
        let factory: AgentFactory = {
            let kills = Arc::clone(&kills);
            Arc::new(move |options| {
                let kills = Arc::clone(&kills);
                async move {
                    Ok(mock_instance(
                        MockAgent::new(options.conversation_id(), None)
                            .with_last_activity(now_ms() - 600_000)
                            .with_kill_counter(kills),
                    ))
                }
                .boxed()
            })
        };
        let mgr = WorkerTaskManagerImpl::new(factory);
        mgr.get_or_build_warm_task("conv-warm-idle", make_options("conv-warm-idle"))
            .await
            .unwrap();

        let killed = mgr.kill_idle_if_still_eligible("conv-warm-idle", 300_000).await;

        assert!(killed);
        assert_eq!(kills.load(Ordering::SeqCst), 1);
        assert!(mgr.get_task("conv-warm-idle").is_none());
    }

    #[test]
    fn collect_idle_logs_selected_agent_with_idle_fields() {
        let manager = WorkerTaskManagerImpl::new(Arc::new(|_options| {
            async { Err(AgentError::bad_gateway("not used")) }.boxed()
        }));
        let now = now_ms();
        let agent =
            Arc::new(MockAgent::new("conv_idle", Some(ConversationStatus::Finished)).with_last_activity(now - 10_000));
        let slot = TaskSlot::new_with_intent(None, None, BuildIntent::Turn, None).unwrap();
        assert!(slot.instance.set(AgentInstance::Mock(agent)).is_ok());
        slot.mark_ready();
        manager.tasks.insert("conv_idle".to_owned(), slot);

        let captured = capture_logs(tracing::Level::INFO, || {
            let ids = manager.collect_idle(5_000);
            assert_eq!(ids, vec!["conv_idle".to_owned()]);
        });

        assert!(captured.contains("Idle scan: selected idle agent"));
        assert!(captured.contains("conversation_id=conv_idle"));
        assert!(captured.contains("agent_type=Acp"));
        assert!(captured.contains("status=Some(Finished)"));
        assert!(captured.contains("idle_ms="));
        assert!(captured.contains("threshold_ms=5000"));
        assert!(captured.contains("last_activity_at="));
    }

    #[test]
    fn kill_and_wait_logs_idle_task_removed_with_agent_type() {
        let manager = WorkerTaskManagerImpl::new(Arc::new(|_options| {
            async { Err(AgentError::bad_gateway("not used")) }.boxed()
        }));
        let agent = Arc::new(MockAgent::new("conv_idle", Some(ConversationStatus::Finished)));
        let slot = TaskSlot::new_with_intent(None, None, BuildIntent::Turn, None).unwrap();
        assert!(slot.instance.set(AgentInstance::Mock(agent)).is_ok());
        slot.mark_ready();
        manager.tasks.insert("conv_idle".to_owned(), slot);

        let captured = capture_logs(tracing::Level::INFO, || {
            let wait = manager.kill_and_wait("conv_idle", Some(AgentKillReason::IdleTimeout));
            drop(wait);
        });

        assert!(captured.contains("Idle kill: task removed from manager"));
        assert!(captured.contains("conversation_id=conv_idle"));
        assert!(captured.contains("agent_type=Some(Acp)"));
        assert!(captured.contains("reason=IdleTimeout"));
    }

    #[test]
    fn collect_idle_empty_when_no_tasks() {
        let mgr = make_manager();
        let idle = mgr.collect_idle(300_000);
        assert!(idle.is_empty());
    }
}
