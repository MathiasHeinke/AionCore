use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use aionui_common::{
    AgentKillReason, AgentType, ConversationStatus, ErrorChain, OnConversationDelete, TimestampMs, now_ms,
};
use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::future::{BoxFuture, join_all};
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::agent_task::AgentInstance;
use crate::error::AgentError;
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
    /// Returns conversation IDs of tasks that:
    /// - have `status == Some(Finished)`
    /// - have been idle longer than `idle_threshold_ms`
    fn collect_idle(&self, idle_threshold_ms: TimestampMs) -> Vec<String>;
}

/// Per-conversation single-flight slot plus the pathless project runtime
/// identity it was built for. Invalidation fences a late factory result after
/// kill/remap so the spawned process cannot leak outside the map.
type TaskTerminationFuture = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

struct TaskSlot {
    project_runtime_context: Option<ProjectRuntimeContext>,
    instance: OnceCell<AgentInstance>,
    invalidated: AtomicBool,
    cleanup_started: AtomicBool,
    prior_termination: Mutex<Option<TaskTerminationFuture>>,
}

impl TaskSlot {
    fn new(
        project_runtime_context: Option<ProjectRuntimeContext>,
        prior_termination: Option<TaskTerminationFuture>,
    ) -> Arc<Self> {
        Arc::new(Self {
            project_runtime_context,
            instance: OnceCell::new(),
            invalidated: AtomicBool::new(false),
            cleanup_started: AtomicBool::new(false),
            prior_termination: Mutex::new(prior_termination),
        })
    }

    fn get(&self) -> Option<&AgentInstance> {
        self.instance.get()
    }

    fn mark_invalidated(&self) {
        self.invalidated.store(true, Ordering::Release);
    }

    fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::Acquire)
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
    ) -> Result<SharedTaskSlot, AgentError> {
        use dashmap::mapref::entry::Entry;

        match self.tasks.entry(conversation_id.to_owned()) {
            Entry::Vacant(entry) => {
                let slot = TaskSlot::new(requested_context, None);
                entry.insert(Arc::clone(&slot));
                Ok(slot)
            }
            Entry::Occupied(mut entry) => {
                let existing = Arc::clone(entry.get());
                match (existing.project_runtime_context.as_ref(), requested_context.as_ref()) {
                    (None, None) => return Ok(existing),
                    (Some(previous), Some(requested)) if previous.same_runtime_as(requested) => {
                        return Ok(existing);
                    }
                    _ => {}
                }

                let (Some(previous), Some(requested)) =
                    (existing.project_runtime_context.as_ref(), requested_context.as_ref())
                else {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                };
                let Some(agent) = existing.get() else {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                };
                if agent.status() != Some(ConversationStatus::Finished) || !requested.is_strictly_newer_than(previous) {
                    return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_CONFLICT"));
                }

                existing.mark_invalidated();
                let prior_termination = existing.start_cleanup().then(|| agent.kill_and_wait(None));
                let replacement = TaskSlot::new(requested_context, prior_termination);
                entry.insert(Arc::clone(&replacement));
                Ok(replacement)
            }
        }
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
        let project_runtime = options.project_runtime_context.is_some();
        let slot = self.select_slot(conversation_id, options.project_runtime_context.clone())?;

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
            })?;
        if slot.is_invalidated() {
            if slot.start_cleanup() {
                let _ = instance.kill(None);
            }
            return Err(AgentError::conflict("PROJECT_RUNTIME_CONTEXT_INVALIDATED"));
        }
        Ok(instance.clone())
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
            if let Some(agent) = slot.get()
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
            if let Some(agent) = slot.get()
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
                if let Some(agent) = slot.get()
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
                let agent = entry.value().get()?;
                let agent_type = agent.agent_type();
                let status = agent.status();
                let last_activity_at = agent.last_activity_at();
                let idle_ms = now.saturating_sub(last_activity_at);

                let selected = agent_type == AgentType::Acp
                    && status == Some(ConversationStatus::Finished)
                    && idle_ms > idle_threshold_ms;
                if selected {
                    info!(
                        conversation_id = %entry.key(),
                        ?agent_type,
                        ?status,
                        idle_ms,
                        threshold_ms = idle_threshold_ms,
                        last_activity_at,
                        "Idle scan: selected idle agent"
                    );
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
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
        BuildTaskOptions::new(make_options(conversation_id).context).with_project_runtime_context(project_context(
            runtime,
            hint,
            root_generation,
            backend_generation,
        ))
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
        mgr.get_or_build_task(
            "conv-project",
            make_project_options("conv-project", "runtime-a", "hint-a", 1, 1),
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
            let slot = TaskSlot::new(None, None);
            slot.instance.set(instance).ok();
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

    #[test]
    fn collect_idle_logs_selected_agent_with_idle_fields() {
        let manager = WorkerTaskManagerImpl::new(Arc::new(|_options| {
            async { Err(AgentError::bad_gateway("not used")) }.boxed()
        }));
        let now = now_ms();
        let agent =
            Arc::new(MockAgent::new("conv_idle", Some(ConversationStatus::Finished)).with_last_activity(now - 10_000));
        let slot = TaskSlot::new(None, None);
        assert!(slot.instance.set(AgentInstance::Mock(agent)).is_ok());
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
        let slot = TaskSlot::new(None, None);
        assert!(slot.instance.set(AgentInstance::Mock(agent)).is_ok());
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
