use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aionui_api_types::AcpAsyncCompletionRequest;
use tokio::sync::{Notify, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, mpsc, oneshot};

use crate::types::BuildTaskOptions;

/// Opaque snapshot of the router's positive ACP session binding at dispatch
/// time. The generation advances monotonically on every real bind, rebind,
/// unbind, cancel/shutdown and at the beginning of every
/// `session/new|load|resume` attempt, so a lease minted before a binding
/// transition can never validate afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpSessionBindingLease {
    session_id: String,
    generation: u64,
}

impl AcpSessionBindingLease {
    /// The router mints leases from the live binding. The constructor is
    /// public so the bounded consumer/conversation fixtures can build
    /// dispatch values; a constructed lease never mutates nor authoritatively
    /// proves the binding — only [`AcpSessionBinding::validate_lease`] does.
    pub fn new(session_id: impl Into<String>, generation: u64) -> Self {
        Self {
            session_id: session_id.into(),
            generation,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Default)]
struct AcpSessionBindingState {
    bound_session_id: Option<String>,
    generation: u64,
}

/// Transient observation shared between the bounded consumer and conversation
/// service. It records only the in-memory active-turn linearization; durable
/// completion state remains solely in the receipt repository.
#[derive(Clone, Default)]
struct AcpSessionBindingTurnObservation {
    turn_claimed: Arc<AtomicBool>,
    turn_claimed_notify: Arc<Notify>,
}

impl AcpSessionBindingTurnObservation {
    pub fn turn_claimed(&self) -> bool {
        self.turn_claimed.load(Ordering::Acquire)
    }

    pub async fn wait_for_turn_claim(&self) {
        loop {
            if self.turn_claimed() {
                return;
            }
            let notified = self.turn_claimed_notify.notified();
            if self.turn_claimed() {
                return;
            }
            notified.await;
        }
    }

    fn mark_turn_claimed(&self) {
        self.turn_claimed.store(true, Ordering::Release);
        self.turn_claimed_notify.notify_waiters();
    }
}

/// A bounded read permit over the exact current ACP binding. The durable
/// consumer acquires it before its first receipt-affecting operation and the
/// conversation service releases it immediately after the synchronous
/// active-turn insertion. Its owning pre-turn future is bounded and dropped
/// on timeout, so a lifecycle writer either linearizes before the receipt
/// claim or waits only for that bounded pre-turn interval.
///
/// It deliberately is not persisted: the durable receipt repository remains
/// the sole cross-restart authority.
pub struct AcpSessionBindingAdmission {
    lease: AcpSessionBindingLease,
    /// Held until the durable consumer has synchronously inserted the active
    /// turn.  The service then releases it immediately, rather than holding a
    /// session lifecycle transition for the duration of worker execution.
    barrier: Mutex<Option<OwnedRwLockReadGuard<()>>>,
    observation: AcpSessionBindingTurnObservation,
}

impl AcpSessionBindingAdmission {
    pub fn lease(&self) -> &AcpSessionBindingLease {
        &self.lease
    }

    /// Linearizes an already claimed completion with the conversation runtime
    /// state. This is deliberately idempotent: error paths and dispatch drops
    /// still release the permit through `Drop`, while a successfully admitted
    /// turn releases it immediately after insertion.
    pub fn release_after_turn_claim(&self) {
        self.observation.mark_turn_claimed();
        self.release_barrier();
    }

    fn release_barrier(&self) {
        let barrier = self.barrier.lock().ok().and_then(|mut held| held.take());
        drop(barrier);
    }
}

/// The route-scoped, generation-bound authority carried by a durable
/// completion after router validation. It holds no lock itself; the durable
/// consumer turns it into one bounded admission before its first receipt
/// mutation and transfers that admission to the conversation service for the
/// synchronous active-turn insertion.
#[derive(Clone)]
pub struct AcpSessionBindingTurnGate {
    binding: AcpSessionBinding,
    lease: AcpSessionBindingLease,
    observation: AcpSessionBindingTurnObservation,
}

impl AcpSessionBindingTurnGate {
    pub fn new(binding: AcpSessionBinding, lease: AcpSessionBindingLease) -> Self {
        Self {
            binding,
            lease,
            observation: AcpSessionBindingTurnObservation::default(),
        }
    }

    pub fn lease(&self) -> &AcpSessionBindingLease {
        &self.lease
    }

    pub fn turn_claimed(&self) -> bool {
        self.observation.turn_claimed()
    }

    pub async fn wait_for_turn_claim(&self) {
        self.observation.wait_for_turn_claim().await;
    }

    /// Acquire the current route binding for one bounded durable completion.
    /// The caller must hold the admission from its first receipt-affecting
    /// operation through the synchronous active-turn insertion, then either
    /// release it with [`AcpSessionBindingAdmission::release_after_turn_claim`]
    /// or let its bounded pre-turn future drop it. This gives close/rebind a
    /// real linearization point before any stale receipt mutation.
    pub fn try_admit_turn(&self) -> Option<AcpSessionBindingAdmission> {
        self.binding
            .try_acquire_admission_for(&self.lease, self.observation.clone())
    }
}

/// Counts lifecycle transitions which have declared precedence over new
/// completion admissions. The count (rather than a boolean) preserves the
/// fail-closed state while more than one lifecycle request is queued.
struct AcpSessionBindingTransitionPending {
    pending: Arc<AtomicUsize>,
}

impl Drop for AcpSessionBindingTransitionPending {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::Release);
    }
}

struct AcpSessionBindingTransition {
    _pending: AcpSessionBindingTransitionPending,
    had_preexisting_transition: bool,
    _barrier: OwnedRwLockWriteGuard<()>,
}

impl AcpSessionBindingTransition {
    fn had_preexisting_transition(&self) -> bool {
        self.had_preexisting_transition
    }
}

/// Exclusive ownership of one in-flight ACP session lifecycle request.
///
/// The ticket retains the admission writer and the public fail-closed pending
/// state from the initial invalidation until the transport RPC terminates. A
/// successful `session/new|load|resume` may restore a binding only through the
/// generation captured by this exact ticket; dropping it after any failure or
/// close leaves the route unbound.
pub(crate) struct AcpSessionBindingLifecycle {
    state: Arc<Mutex<AcpSessionBindingState>>,
    invalidated_generation: u64,
    _transition: AcpSessionBindingTransition,
}

impl AcpSessionBindingLifecycle {
    /// Complete the exact lifecycle request with its positively acknowledged
    /// session. The writer permit prevents another lifecycle owner from
    /// changing state between the generation check and the bind.
    pub(crate) fn bind_acknowledged(self, session_id: &str) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.generation != self.invalidated_generation || state.bound_session_id.is_some() {
            return Err(());
        }
        state.generation = state.generation.checked_add(1).ok_or(())?;
        state.bound_session_id = Some(session_id.to_owned());
        Ok(())
    }
}

/// Shared synchronous authority for the canonical ACP session binding owned
/// by the client extension router. The completion consumer path only reads
/// snapshots and validates leases; every transition is driven by the
/// router's session lifecycle (`session/new|load|resume|close`, cancel and
/// shutdown).
#[derive(Debug, Clone, Default)]
pub struct AcpSessionBinding {
    state: Arc<Mutex<AcpSessionBindingState>>,
    /// The reader side is held by a completion from dispatch through durable
    /// receipt claim and the active-turn insertion. Lifecycle transitions hold
    /// the writer side before they advance the generation or change session.
    admission_barrier: Arc<RwLock<()>>,
    /// Set before a lifecycle transition attempts the writer permit. A
    /// completion checks it before and after acquiring a reader permit, so it
    /// cannot slip between a transition request and the writer acquisition.
    transition_pending: Arc<AtomicUsize>,
}

impl AcpSessionBinding {
    /// Snapshot the current lifecycle generation for an operation that may
    /// later restore a positive binding. `None` means a lifecycle transition
    /// already has precedence, so the later operation must stay fail-closed.
    pub(crate) fn lifecycle_generation(&self) -> Option<u64> {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return None;
        }
        self.state.lock().ok().map(|state| state.generation)
    }

    /// Snapshot the live binding as a lease, or `None` while the route is
    /// unbound (pre-bind, mid request interval, after close/cancel).
    pub fn lease(&self) -> Option<AcpSessionBindingLease> {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return None;
        }
        self.state.lock().ok().and_then(|state| {
            state
                .bound_session_id
                .as_ref()
                .map(|session_id| AcpSessionBindingLease {
                    session_id: session_id.clone(),
                    generation: state.generation,
                })
        })
    }

    pub fn bound_session_id(&self) -> Option<String> {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return None;
        }
        self.state.lock().ok().and_then(|state| state.bound_session_id.clone())
    }

    /// A lease is current only while the exact session remains positively
    /// bound and no binding transition has advanced the generation since the
    /// lease was minted.
    pub fn validate_lease(&self, lease: &AcpSessionBindingLease) -> bool {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return false;
        }
        self.state
            .lock()
            .map(|state| {
                state.bound_session_id.as_deref() == Some(lease.session_id.as_str())
                    && state.generation == lease.generation
            })
            .unwrap_or(false)
    }

    /// Atomically acquire the live binding for a test or non-correlated caller.
    /// Production durable work uses [`Self::try_acquire_admission_for`] with
    /// the route's already-dispatched lease.
    pub fn try_acquire_admission(&self) -> Option<AcpSessionBindingAdmission> {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return None;
        }
        let barrier = Arc::clone(&self.admission_barrier).try_read_owned().ok()?;
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            drop(barrier);
            return None;
        }
        let lease = self.state.lock().ok().and_then(|state| {
            state
                .bound_session_id
                .as_ref()
                .map(|session_id| AcpSessionBindingLease {
                    session_id: session_id.clone(),
                    generation: state.generation,
                })
        });
        lease.map(|lease| AcpSessionBindingAdmission {
            lease,
            barrier: Mutex::new(Some(barrier)),
            observation: AcpSessionBindingTurnObservation::default(),
        })
    }

    /// Acquire an admission only when the exact session and monotonically
    /// minted generation carried by a dispatch are still live. The caller owns
    /// it through its bounded pre-turn receipt work and synchronous active-turn
    /// insertion, so a close/rebind either wins first (no receipt mutation) or
    /// waits for that bounded pre-transition work.
    fn try_acquire_admission_for(
        &self,
        lease: &AcpSessionBindingLease,
        observation: AcpSessionBindingTurnObservation,
    ) -> Option<AcpSessionBindingAdmission> {
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            return None;
        }
        let barrier = Arc::clone(&self.admission_barrier).try_read_owned().ok()?;
        if self.transition_pending.load(Ordering::Acquire) != 0 {
            drop(barrier);
            return None;
        }
        let matches = self
            .state
            .lock()
            .map(|state| {
                state.bound_session_id.as_deref() == Some(lease.session_id.as_str())
                    && state.generation == lease.generation
            })
            .unwrap_or(false);
        if !matches {
            drop(barrier);
            return None;
        }
        Some(AcpSessionBindingAdmission {
            lease: lease.clone(),
            barrier: Mutex::new(Some(barrier)),
            observation,
        })
    }

    /// Bind a positively acknowledged session. Returns `Ok(true)` when a
    /// real (re)bind advanced the generation, `Ok(false)` for an idempotent
    /// same-session bind without an intervening begin-binding transition.
    pub(crate) async fn bind(&self, session_id: &str) -> Result<bool, ()> {
        let _transition = self.transition().await;
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.bound_session_id.as_deref() == Some(session_id) {
            return Ok(false);
        }
        state.generation = state.generation.checked_add(1).ok_or(())?;
        state.bound_session_id = Some(session_id.to_owned());
        Ok(true)
    }

    /// Bind only when no lifecycle transition has superseded the operation's
    /// starting generation. `None` means cancel/close/rebind/shutdown won the
    /// race; `Some(false)` is an idempotent same-session acknowledgement and
    /// `Some(true)` is a new positive binding.
    pub(crate) async fn bind_if_generation(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<Option<bool>, ()> {
        let transition = self.transition().await;
        if transition.had_preexisting_transition() {
            return Ok(None);
        }
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.generation != expected_generation {
            return Ok(None);
        }
        if state.bound_session_id.as_deref() == Some(session_id) {
            return Ok(Some(false));
        }
        state.generation = state.generation.checked_add(1).ok_or(())?;
        state.bound_session_id = Some(session_id.to_owned());
        Ok(Some(true))
    }

    /// Unbind a matching closed session, advancing the generation. Returns
    /// whether a live binding was dropped.
    pub(crate) async fn unbind_matching(&self, session_id: &str) -> Result<bool, ()> {
        let _transition = self.transition().await;
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.bound_session_id.as_deref() != Some(session_id) {
            return Ok(false);
        }
        Self::advance(&mut state);
        state.bound_session_id = None;
        Ok(true)
    }

    /// Invalidate the binding and advance the generation. Driven at the
    /// beginning of every `session/new|load|resume` attempt and on
    /// cancel/shutdown: until the request succeeds and binds, the route
    /// stays unbound and every previously minted lease is stale.
    pub(crate) async fn invalidate(&self) -> Result<(), ()> {
        let _transition = self.transition().await;
        let Ok(mut state) = self.state.lock() else {
            return Err(());
        };
        Self::advance(&mut state);
        state.bound_session_id = None;
        Ok(())
    }

    /// Invalidate the route and retain exclusive lifecycle ownership until
    /// the caller observes the terminal `session/new|load|resume` response.
    pub(crate) async fn begin_lifecycle(&self) -> Result<AcpSessionBindingLifecycle, ()> {
        let transition = self.transition().await;
        let invalidated_generation = {
            let mut state = self.state.lock().map_err(|_| ())?;
            Self::advance(&mut state);
            state.bound_session_id = None;
            state.generation
        };
        Ok(AcpSessionBindingLifecycle {
            state: Arc::clone(&self.state),
            invalidated_generation,
            _transition: transition,
        })
    }

    /// Retain lifecycle ownership across a close RPC while invalidating only
    /// the exact live session named by that request. A close for an already
    /// unbound or different session still owns the interval, but does not
    /// discard another live binding.
    pub(crate) async fn begin_close_lifecycle(
        &self,
        session_id: &str,
    ) -> Result<(AcpSessionBindingLifecycle, bool), ()> {
        let transition = self.transition().await;
        let (invalidated_generation, invalidated_matching_session) = {
            let mut state = self.state.lock().map_err(|_| ())?;
            let invalidated_matching_session = state.bound_session_id.as_deref() == Some(session_id);
            if invalidated_matching_session {
                Self::advance(&mut state);
                state.bound_session_id = None;
            }
            (state.generation, invalidated_matching_session)
        };
        Ok((
            AcpSessionBindingLifecycle {
                state: Arc::clone(&self.state),
                invalidated_generation,
                _transition: transition,
            },
            invalidated_matching_session,
        ))
    }

    /// Start a lifecycle transition. New completion admissions fail closed as
    /// soon as this method is entered; an existing admission linearizes before
    /// the transition and keeps the read permit until receipt/turn admission.
    async fn transition(&self) -> AcpSessionBindingTransition {
        let had_preexisting_transition = self.transition_pending.fetch_add(1, Ordering::AcqRel) != 0;
        let pending = AcpSessionBindingTransitionPending {
            pending: Arc::clone(&self.transition_pending),
        };
        let barrier = Arc::clone(&self.admission_barrier).write_owned().await;
        AcpSessionBindingTransition {
            _pending: pending,
            had_preexisting_transition,
            _barrier: barrier,
        }
    }

    /// Permanently close this route's admission gate. This synchronous path is
    /// used from protocol `Drop`; the route cannot be rebound after shutdown,
    /// so retaining the pending count is the correct fail-closed state.
    pub(crate) fn close_admissions(&self) {
        self.transition_pending.fetch_add(1, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn transition_pending(&self) -> bool {
        self.transition_pending.load(Ordering::Acquire) != 0
    }

    /// Test-only fixture constructor. Production admissions are only minted
    /// by the ACP extension router after a positive session binding.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn admission_for_test(session_id: &str) -> AcpSessionBindingAdmission {
        let binding = Self::default();
        binding.bind(session_id).await.expect("test session binding");
        binding.try_acquire_admission().expect("test admission")
    }

    /// Test-only positive binding fixture for cross-crate durable-completion
    /// tests. Production bindings remain owned by the ACP extension router.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn bound_for_test(session_id: &str) -> Self {
        let binding = Self::default();
        binding.bind(session_id).await.expect("test session binding");
        binding
    }

    /// Test-only deferred admission fixture which mirrors a routed durable
    /// completion: it snapshots a positive binding but does not hold a reader
    /// permit while the test performs simulated repository work.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn turn_gate_for_test(session_id: &str) -> AcpSessionBindingTurnGate {
        let binding = Self::bound_for_test(session_id).await;
        let lease = binding.lease().expect("test session lease");
        AcpSessionBindingTurnGate::new(binding, lease)
    }

    /// Test-only close operation used to prove that an unbounded pre-turn
    /// future cannot starve the lifecycle writer.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn close_for_test(&self, session_id: &str) -> bool {
        self.unbind_matching(session_id).await.expect("test session close")
    }

    /// Test-only ordinary-cancel transition for cross-crate durable consumer
    /// regressions. Production transitions remain router-owned.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn cancel_for_test(&self) {
        self.invalidate().await.expect("test session cancel")
    }

    fn advance(state: &mut AcpSessionBindingState) {
        if let Some(generation) = state.generation.checked_add(1) {
            state.generation = generation;
        }
    }
}

/// Transient, in-process routing state for the verified Hermes completion
/// extension. Project build options are copied from the already-attested task
/// build and are never serialized or persisted.
#[derive(Clone)]
pub struct CommandEveAsyncCompletionRoute {
    pub conversation_id: String,
    pub sender: CommandEveAsyncCompletionSender,
    pub project_build_options: Option<BuildTaskOptions>,
    /// Per-conversation session binding authority adopted by the ACP client
    /// extension router. One handle is minted per route so a rebind of one
    /// conversation can never invalidate another conversation's lease.
    pub session_binding: AcpSessionBinding,
}

/// Route decision for one validated Hermes background completion after the
/// ACP client extension router has positively bound its host conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEveAsyncCompletionDispatchKind {
    Apply,
    RejectSessionMismatch { bound_session_id: String },
}

/// One validated Hermes background completion routed through the existing
/// bounded in-process consumer path.
pub struct CommandEveAsyncCompletionDispatch {
    pub conversation_id: String,
    pub request: AcpAsyncCompletionRequest,
    pub kind: CommandEveAsyncCompletionDispatchKind,
    /// Route-scoped generation authority for a deferred, short turn admission.
    /// It intentionally holds no reader permit across database lookup, receipt
    /// claim, or project revalidation.
    pub turn_gate: AcpSessionBindingTurnGate,
    /// Snapshot retained for receipt correlation and test fixtures. The live
    /// authority is `turn_gate`, not a separately rechecked callback.
    pub lease: AcpSessionBindingLease,
    pub project_build_options: Option<BuildTaskOptions>,
    pub reply: oneshot::Sender<CommandEveAsyncCompletionResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEveAsyncCompletionResult {
    Completed {
        turn_id: String,
    },
    AlreadyCompleted {
        turn_id: String,
    },
    RetryableBusy {
        code: String,
    },
    Rejected {
        code: String,
    },
    /// Terminal explicit-unknown outcome. Only the receipt-owning consumer
    /// constructs it, and only after the exact `ExplicitUnknown`
    /// acknowledgement was durably persisted with the same code. The router
    /// never synthesizes a terminal unknown: reply timeouts, dropped
    /// consumers and unavailable channels stay retryable instead.
    PersistedUnknown {
        code: String,
    },
}

pub type CommandEveAsyncCompletionSender = mpsc::Sender<CommandEveAsyncCompletionDispatch>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::oneshot;

    use super::AcpSessionBinding;

    #[tokio::test]
    async fn lifecycle_ticket_drop_cancellation_and_unwind_release_the_transition_fence() {
        let binding = AcpSessionBinding::default();
        binding.bind("session-1").await.unwrap();

        // Hold the read side so `begin_lifecycle` deterministically reaches
        // the writer barrier. Poll it once, then cancel by dropping the future.
        let admission = binding.try_acquire_admission().expect("held admission");
        {
            let lifecycle = binding.begin_lifecycle();
            tokio::pin!(lifecycle);
            tokio::select! {
                biased;
                _ = &mut lifecycle => panic!("writer unexpectedly completed"),
                () = async {} => {}
            }
            assert!(binding.transition_pending());
        }
        assert!(!binding.transition_pending());
        assert_eq!(binding.bound_session_id().as_deref(), Some("session-1"));
        drop(admission);

        // A normal dropped owner releases both pending state and writer.
        let lifecycle = binding.begin_lifecycle().await.unwrap();
        assert!(binding.transition_pending());
        drop(lifecycle);
        assert!(!binding.transition_pending());

        // Unwinding across an owned ticket has identical fail-closed cleanup.
        let lifecycle = binding.begin_lifecycle().await.unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lifecycle = lifecycle;
            panic!("lifecycle unwind probe");
        }));
        assert!(!binding.transition_pending());

        // A fresh owner can still complete the exact positive bind afterward.
        let lifecycle = binding.begin_lifecycle().await.unwrap();
        lifecycle.bind_acknowledged("session-2").unwrap();
        assert!(!binding.transition_pending());
        assert_eq!(binding.bound_session_id().as_deref(), Some("session-2"));
    }

    #[tokio::test]
    async fn lifecycle_transition_fences_new_admissions_until_the_existing_turn_claim_releases() {
        let binding = Arc::new(AcpSessionBinding::default());
        binding.bind("session-1").await.unwrap();
        let admission = binding.try_acquire_admission().expect("positive binding");

        let transition_binding = Arc::clone(&binding);
        let (started_tx, started_rx) = oneshot::channel();
        let transition = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            transition_binding.invalidate().await.unwrap();
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;

        assert!(
            binding.transition_pending(),
            "rebind must fence new arrivals before writer admission"
        );
        assert!(
            binding.try_acquire_admission().is_none(),
            "stale work must not enter after rebind starts"
        );

        // This models the conversation runtime's synchronous active-turn
        // insertion.  Releasing only after that linearization lets the
        // lifecycle move on without allowing a stale dispatch to execute.
        admission.release_after_turn_claim();
        transition.await.unwrap();

        assert!(
            binding.lease().is_none(),
            "rebind leaves the route pre-bind and retryable"
        );
        assert!(binding.try_acquire_admission().is_none());
    }

    #[tokio::test]
    async fn admission_release_allows_the_next_positive_binding_without_reusing_the_old_lease() {
        let binding = AcpSessionBinding::default();
        binding.bind("session-1").await.unwrap();
        let admission = binding.try_acquire_admission().unwrap();
        let old_lease = admission.lease().clone();
        admission.release_after_turn_claim();

        binding.invalidate().await.unwrap();
        binding.bind("session-2").await.unwrap();
        let current = binding.lease().unwrap();

        assert_ne!(current, old_lease);
        assert!(!binding.validate_lease(&old_lease));
        assert!(binding.validate_lease(&current));
    }

    #[tokio::test]
    async fn close_fence_invalidates_a_deferred_turn_gate_without_waiting_for_preturn_work() {
        let binding = AcpSessionBinding::default();
        binding.bind("session-1").await.unwrap();
        let lease = binding.lease().expect("positive binding");
        let turn_gate = super::AcpSessionBindingTurnGate::new(binding.clone(), lease);

        let closed = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            binding.unbind_matching("session-1"),
        )
        .await
        .expect("close must not wait for deferred pre-turn work")
        .unwrap();

        assert!(closed);
        assert!(
            turn_gate.try_admit_turn().is_none(),
            "a close fence must win before a deferred completion inserts a turn"
        );
    }
}
