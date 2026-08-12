use std::sync::Arc;
use std::time::Duration;

use aionui_ai_agent::{
    AcpSessionBindingTurnGate, CommandEveAsyncCompletionDispatch, CommandEveAsyncCompletionDispatchKind,
    CommandEveAsyncCompletionResult, IWorkerTaskManager, types::BuildTaskOptions,
};
use aionui_common::AgentKillReason;
use aionui_conversation::{
    ConversationAgentTurnOutcome, ConversationAgentTurnRequest, ConversationAgentTurnStatus, ConversationError,
    ConversationService,
};
use aionui_db::{
    AsyncCompletionAckStatus, AsyncCompletionReceiptClaim, ClaimAsyncCompletionReceiptParams, DbError,
    IAcpSessionRepository, IAsyncCompletionReceiptRepository, IConversationRepository, RecordAsyncCompletionAckParams,
    RecordRejectedAsyncCompletionReceiptParams,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};

const ASYNC_COMPLETION_MAX_CONCURRENCY: usize = 4;
const ASYNC_COMPLETION_ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);
const ASYNC_COMPLETION_TURN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const ASYNC_COMPLETION_KILL_TIMEOUT: Duration = Duration::from_secs(20);
const ASYNC_COMPLETION_RECEIPT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of the bounded pre-turn window. The `Pin<Box<...>>` owning the
/// pre-turn future lives only inside that window, so every timeout path drops
/// a suspended receipt transaction before durable recovery starts.
enum CompletionWindowOutcome {
    Completed(CommandEveAsyncCompletionResult),
    PreTurnTimedOut,
    PostTurnTimedOut,
}

enum PreTurnSelection {
    Completed(CommandEveAsyncCompletionResult),
    TurnClaimed,
    DeadlineElapsed,
}

#[async_trait::async_trait]
trait IAsyncCompletionTurnRunner: Send + Sync {
    async fn run(
        &self,
        request: ConversationAgentTurnRequest,
        turn_id: String,
        project_build_options: Option<BuildTaskOptions>,
        turn_gate: &AcpSessionBindingTurnGate,
    ) -> Result<ConversationAgentTurnOutcome, ConversationError>;
}

#[async_trait::async_trait]
impl IAsyncCompletionTurnRunner for ConversationService {
    async fn run(
        &self,
        request: ConversationAgentTurnRequest,
        turn_id: String,
        project_build_options: Option<BuildTaskOptions>,
        turn_gate: &AcpSessionBindingTurnGate,
    ) -> Result<ConversationAgentTurnOutcome, ConversationError> {
        self.run_command_eve_async_completion_turn(request, turn_id, project_build_options, turn_gate)
            .await
    }
}

pub(crate) struct CommandEveAsyncCompletionConsumer {
    turn_runner: Arc<dyn IAsyncCompletionTurnRunner>,
    conversation_repo: Arc<dyn IConversationRepository>,
    acp_session_repo: Arc<dyn IAcpSessionRepository>,
    receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
    task_manager: Arc<dyn IWorkerTaskManager>,
    owner_instance_id: String,
    admission_timeout: Duration,
    turn_timeout: Duration,
    kill_timeout: Duration,
    receipt_recovery_timeout: Duration,
    max_concurrency: usize,
}

impl CommandEveAsyncCompletionConsumer {
    pub(crate) fn new(
        conversation_service: ConversationService,
        conversation_repo: Arc<dyn IConversationRepository>,
        acp_session_repo: Arc<dyn IAcpSessionRepository>,
        receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
        task_manager: Arc<dyn IWorkerTaskManager>,
        owner_instance_id: String,
    ) -> Self {
        Self::with_turn_runner(
            Arc::new(conversation_service),
            conversation_repo,
            acp_session_repo,
            receipt_repo,
            task_manager,
            owner_instance_id,
        )
    }

    fn with_turn_runner(
        turn_runner: Arc<dyn IAsyncCompletionTurnRunner>,
        conversation_repo: Arc<dyn IConversationRepository>,
        acp_session_repo: Arc<dyn IAcpSessionRepository>,
        receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
        task_manager: Arc<dyn IWorkerTaskManager>,
        owner_instance_id: String,
    ) -> Self {
        Self {
            turn_runner,
            conversation_repo,
            acp_session_repo,
            receipt_repo,
            task_manager,
            owner_instance_id,
            admission_timeout: ASYNC_COMPLETION_ADMISSION_TIMEOUT,
            turn_timeout: ASYNC_COMPLETION_TURN_TIMEOUT,
            kill_timeout: ASYNC_COMPLETION_KILL_TIMEOUT,
            receipt_recovery_timeout: ASYNC_COMPLETION_RECEIPT_RECOVERY_TIMEOUT,
            max_concurrency: ASYNC_COMPLETION_MAX_CONCURRENCY,
        }
    }

    pub(crate) fn start(self, mut receiver: mpsc::Receiver<CommandEveAsyncCompletionDispatch>) {
        let slots = Arc::new(Semaphore::new(self.max_concurrency));
        let consumer = Arc::new(self);
        tokio::spawn(async move {
            while let Some(dispatch) = receiver.recv().await {
                let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                    break;
                };
                let consumer = Arc::clone(&consumer);
                tokio::spawn(async move {
                    let _permit = permit;
                    let completion_id = dispatch.request.completion_id.clone();
                    let result = consumer.consume(&dispatch).await;
                    if dispatch.reply.send(result).is_err() {
                        warn!(
                            completion_id_bytes = completion_id.len(),
                            "ACP async completion reply receiver dropped"
                        );
                    }
                });
            }
        });
    }

    async fn consume(&self, dispatch: &CommandEveAsyncCompletionDispatch) -> CommandEveAsyncCompletionResult {
        let deadline = tokio::time::Instant::now() + self.admission_timeout;
        let payload_sha256 = hex_sha256(dispatch.request.content.as_bytes());
        let window_outcome = {
            // Keep the owning box scoped to this block. In particular, the
            // admission-deadline branch destroys a pending `claim()` future
            // (and any SQLite transaction it owns) before calling a receipt
            // recovery method below.
            let mut before_turn = Box::pin(self.consume_before_turn(dispatch, &payload_sha256));
            let mut turn_claimed = Box::pin(dispatch.turn_gate.wait_for_turn_claim());
            let selection = tokio::select! {
                result = &mut before_turn => PreTurnSelection::Completed(result),
                _ = &mut turn_claimed => PreTurnSelection::TurnClaimed,
                _ = tokio::time::sleep_until(deadline) => PreTurnSelection::DeadlineElapsed,
            };

            match selection {
                PreTurnSelection::Completed(result) => CompletionWindowOutcome::Completed(result),
                PreTurnSelection::TurnClaimed => match tokio::time::timeout(self.turn_timeout, before_turn).await {
                    Ok(result) => CompletionWindowOutcome::Completed(result),
                    Err(_) => CompletionWindowOutcome::PostTurnTimedOut,
                },
                PreTurnSelection::DeadlineElapsed => CompletionWindowOutcome::PreTurnTimedOut,
            }
        };

        match window_outcome {
            CompletionWindowOutcome::Completed(result) => result,
            CompletionWindowOutcome::PreTurnTimedOut => self.resolve_pre_turn_timeout(dispatch, &payload_sha256).await,
            CompletionWindowOutcome::PostTurnTimedOut => {
                self.resolve_post_turn_timeout(dispatch, &payload_sha256).await
            }
        }
    }

    async fn consume_before_turn(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
    ) -> CommandEveAsyncCompletionResult {
        let conversation = match self.conversation_repo.get(&dispatch.conversation_id).await {
            Ok(Some(conversation)) => conversation,
            Ok(None) => return rejected("conversation_not_found"),
            Err(error) => {
                warn!(error = %error, "ACP async completion conversation lookup failed");
                return retryable("conversation_lookup_failed");
            }
        };
        if let CommandEveAsyncCompletionDispatchKind::RejectSessionMismatch { bound_session_id } = &dispatch.kind {
            return self
                .reject_with_receipt(dispatch, bound_session_id, payload_sha256, "session_mismatch")
                .await;
        }
        let proposed_turn_id = ConversationService::mint_turn_id();
        let session = match self.acp_session_repo.get(&dispatch.conversation_id).await {
            Ok(Some(session)) => session,
            // A route can be restored before its positive ACP session binding
            // has finished loading. A missing pre-bind record is never a
            // terminal rejection; Hermes must retain and retry it.
            Ok(None) => return retryable("session_not_bound"),
            Err(error) => {
                warn!(error = %error, "ACP async completion session lookup failed");
                return retryable("session_lookup_failed");
            }
        };
        let Some(bound_session_id) = session.session_id.as_deref() else {
            // The ACP row exists before session/new or session/load has
            // positively rebound the route. This is still pre-bind and must
            // remain replayable across restart.
            return retryable("session_not_bound");
        };
        if bound_session_id != dispatch.request.session_id.as_str() {
            // The route-scoped ACP guard already rejected a genuinely foreign
            // post-bind request before it could reach this consumer. A
            // different persisted id here therefore means session/new or
            // session/load has rebound the live route before its repository
            // update became visible. Keep the durable wake replayable.
            return retryable("session_not_bound");
        }

        let claim = match self
            .receipt_repo
            .claim(&ClaimAsyncCompletionReceiptParams {
                completion_id: &dispatch.request.completion_id,
                conversation_id: &dispatch.conversation_id,
                acp_session_id: &dispatch.request.session_id,
                payload_sha256,
                owner_instance_id: &self.owner_instance_id,
                turn_id: &proposed_turn_id,
            })
            .await
        {
            Ok(claim) => claim,
            Err(error) => {
                warn!(error = %error, "ACP async completion receipt claim failed");
                return retryable("receipt_claim_failed");
            }
        };

        let turn_id = match claim {
            AsyncCompletionReceiptClaim::AlreadyCompleted { turn_id } => {
                if !self
                    .record_ack(dispatch, payload_sha256, AsyncCompletionAckStatus::AlreadyApplied, None)
                    .await
                {
                    return retryable("ack_persistence_failed");
                }
                return CommandEveAsyncCompletionResult::AlreadyCompleted { turn_id };
            }
            AsyncCompletionReceiptClaim::InFlight { .. } => {
                if !self
                    .record_ack(
                        dispatch,
                        payload_sha256,
                        AsyncCompletionAckStatus::Retryable,
                        Some("receipt_in_flight"),
                    )
                    .await
                {
                    return retryable("ack_persistence_failed");
                }
                return retryable("receipt_in_flight");
            }
            AsyncCompletionReceiptClaim::Unknown { turn_id } => {
                warn!(
                    conversation_id = %dispatch.conversation_id,
                    turn_id = %turn_id,
                    "ACP async completion replay has an explicitly unknown outcome"
                );
                if !self
                    .record_ack(
                        dispatch,
                        payload_sha256,
                        AsyncCompletionAckStatus::ExplicitUnknown,
                        Some("outcome_unknown_receipt"),
                    )
                    .await
                {
                    return retryable("ack_persistence_failed");
                }
                return persisted_unknown("outcome_unknown_receipt");
            }
            AsyncCompletionReceiptClaim::Conflict => {
                // The rejection ledger is independent of the execution row, so
                // this attempt remains visible without poisoning the identity
                // that legitimately owns the completion id.
                return self
                    .reject_with_receipt(dispatch, bound_session_id, payload_sha256, "receipt_identity_conflict")
                    .await;
            }
            AsyncCompletionReceiptClaim::Claimed { turn_id } => turn_id,
        };

        let turn = self.turn_runner.run(
            ConversationAgentTurnRequest {
                user_id: conversation.user_id,
                conversation_id: dispatch.conversation_id.clone(),
                content: dispatch.request.content.clone(),
                files: Vec::new(),
                inject_skills: Vec::new(),
                on_started: None,
            },
            turn_id.clone(),
            dispatch.project_build_options.clone(),
            &dispatch.turn_gate,
        );
        let outcome = match tokio::time::timeout(self.turn_timeout, turn).await {
            Ok(outcome) => outcome,
            Err(_) => {
                warn!(
                    conversation_id = %dispatch.conversation_id,
                    turn_id = %turn_id,
                    "ACP async completion turn timed out; outcome is unknown"
                );
                let cleanup = self
                    .task_manager
                    .kill_and_wait(&dispatch.conversation_id, Some(AgentKillReason::AgentErrorRecovery));
                if tokio::time::timeout(self.kill_timeout, cleanup).await.is_err() {
                    warn!(
                        conversation_id = %dispatch.conversation_id,
                        turn_id = %turn_id,
                        "ACP async completion timed out while waiting for task termination"
                    );
                }
                if !self
                    .mark_unknown(dispatch, payload_sha256, "turn_timeout", "outcome_unknown_turn_timeout")
                    .await
                {
                    return retryable("ack_persistence_failed");
                }
                return persisted_unknown("outcome_unknown_turn_timeout");
            }
        };

        match outcome {
            Err(ConversationError::Busy { reason }) if reason == "ACP_SESSION_BINDING_INVALIDATED" => {
                self.resolve_claimed_without_turn(
                    dispatch,
                    payload_sha256,
                    "session_not_bound",
                    "binding_invalidated_before_turn",
                    "outcome_unknown_binding_invalidated",
                )
                .await
            }
            Err(ConversationError::Busy { reason: _ }) => {
                let code = "conversation_busy";
                match self
                    .receipt_repo
                    .mark_retryable(&dispatch.request.completion_id, &self.owner_instance_id, code)
                    .await
                {
                    Ok(true) => {
                        if !self
                            .record_ack(
                                dispatch,
                                payload_sha256,
                                AsyncCompletionAckStatus::Retryable,
                                Some(code),
                            )
                            .await
                        {
                            return retryable("ack_persistence_failed");
                        }
                        retryable(code)
                    }
                    Ok(false) | Err(_) => {
                        if !self
                            .mark_unknown(
                                dispatch,
                                payload_sha256,
                                "outcome_unknown_retry_transition",
                                "outcome_unknown_retry_transition",
                            )
                            .await
                        {
                            return retryable("ack_persistence_failed");
                        }
                        persisted_unknown("outcome_unknown_retry_transition")
                    }
                }
            }
            Ok(outcome) if outcome.status == ConversationAgentTurnStatus::Completed => {
                match self
                    .receipt_repo
                    .mark_completed(&dispatch.request.completion_id, &self.owner_instance_id, &turn_id)
                    .await
                {
                    Ok(true) => {
                        if !self
                            .record_ack(dispatch, payload_sha256, AsyncCompletionAckStatus::Accepted, None)
                            .await
                        {
                            return retryable("ack_persistence_failed");
                        }
                        info!(
                            conversation_id = %dispatch.conversation_id,
                            completion_id_bytes = dispatch.request.completion_id.len(),
                            turn_id = %outcome.turn_id,
                            "ACP async completion applied"
                        );
                        CommandEveAsyncCompletionResult::Completed {
                            turn_id: outcome.turn_id,
                        }
                    }
                    Ok(false) | Err(_) => {
                        if !self
                            .mark_unknown(
                                dispatch,
                                payload_sha256,
                                "complete_transition_failed",
                                "outcome_unknown_complete_transition",
                            )
                            .await
                        {
                            return retryable("ack_persistence_failed");
                        }
                        persisted_unknown("outcome_unknown_complete_transition")
                    }
                }
            }
            Ok(_) => {
                if self
                    .mark_unknown(dispatch, payload_sha256, "turn_failed", "outcome_unknown_turn_failed")
                    .await
                {
                    persisted_unknown("outcome_unknown_turn_failed")
                } else {
                    retryable("ack_persistence_failed")
                }
            }
            Err(error) => {
                warn!(error = %error, "ACP async completion turn failed");
                if self
                    .mark_unknown(dispatch, payload_sha256, "turn_error", "outcome_unknown_turn_error")
                    .await
                {
                    persisted_unknown("outcome_unknown_turn_error")
                } else {
                    retryable("ack_persistence_failed")
                }
            }
        }
    }

    async fn resolve_pre_turn_timeout(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
    ) -> CommandEveAsyncCompletionResult {
        if dispatch.turn_gate.turn_claimed() {
            return self.resolve_post_turn_timeout(dispatch, payload_sha256).await;
        }
        self.resolve_claimed_without_turn(
            dispatch,
            payload_sha256,
            "admission_timeout_before_turn",
            "admission_timeout_outcome_unknown",
            "outcome_unknown_admission_timeout",
        )
        .await
    }

    /// Resolve a known-or-possible receipt claim that did not reach the
    /// synchronous active-turn insertion. The conditional receipt transition
    /// distinguishes a safely claimed row from a cancelled/no-op claim without
    /// inventing a second ledger.
    async fn resolve_claimed_without_turn(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
        retry_code: &str,
        unknown_error_code: &str,
        unknown_outcome_code: &str,
    ) -> CommandEveAsyncCompletionResult {
        match self
            .wait_for_receipt_recovery(
                self.receipt_repo
                    .mark_retryable(&dispatch.request.completion_id, &self.owner_instance_id, retry_code),
                "mark_retryable",
            )
            .await
        {
            Ok(true) => match self
                .record_recovery_ack(
                    dispatch,
                    payload_sha256,
                    AsyncCompletionAckStatus::Retryable,
                    Some(retry_code),
                )
                .await
            {
                Ok(true) => retryable(retry_code),
                Ok(false) => retryable("receipt_recovery_unavailable"),
                Err(code) => retryable(code),
            },
            Ok(false) => {
                // The claim may have committed as cancellation raced it; only
                // the durable receipt can classify that side effect. A
                // terminal unknown is valid only after both the transition
                // and its exact acknowledgement are durable.
                match self
                    .wait_for_receipt_recovery(
                        self.receipt_repo.mark_unknown(
                            &dispatch.request.completion_id,
                            &self.owner_instance_id,
                            unknown_error_code,
                        ),
                        "mark_unknown",
                    )
                    .await
                {
                    Ok(true) => match self
                        .record_recovery_ack(
                            dispatch,
                            payload_sha256,
                            AsyncCompletionAckStatus::ExplicitUnknown,
                            Some(unknown_outcome_code),
                        )
                        .await
                    {
                        Ok(true) => persisted_unknown(unknown_outcome_code),
                        Ok(false) => retryable("receipt_recovery_unavailable"),
                        Err(code) => retryable(code),
                    },
                    Ok(false) => retryable("receipt_recovery_unavailable"),
                    Err(code) => retryable(code),
                }
            }
            Err(code) => retryable(code),
        }
    }

    async fn resolve_post_turn_timeout(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
    ) -> CommandEveAsyncCompletionResult {
        let cleanup = self
            .task_manager
            .kill_and_wait(&dispatch.conversation_id, Some(AgentKillReason::AgentErrorRecovery));
        if tokio::time::timeout(self.kill_timeout, cleanup).await.is_err() {
            warn!(
                conversation_id = %dispatch.conversation_id,
                "ACP async completion admission timed out while waiting for task termination"
            );
        }
        match self
            .wait_for_receipt_recovery(
                self.receipt_repo.mark_unknown(
                    &dispatch.request.completion_id,
                    &self.owner_instance_id,
                    "admission_timeout_after_turn",
                ),
                "mark_unknown",
            )
            .await
        {
            Ok(true) => match self
                .record_recovery_ack(
                    dispatch,
                    payload_sha256,
                    AsyncCompletionAckStatus::ExplicitUnknown,
                    Some("outcome_unknown_admission_timeout"),
                )
                .await
            {
                Ok(true) => persisted_unknown("outcome_unknown_admission_timeout"),
                Ok(false) => retryable("receipt_recovery_unavailable"),
                Err(code) => retryable(code),
            },
            Ok(false) => retryable("receipt_recovery_unavailable"),
            Err(code) => retryable(code),
        }
    }

    async fn wait_for_receipt_recovery<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, DbError>>,
        operation_name: &'static str,
    ) -> Result<T, &'static str> {
        match tokio::time::timeout(self.receipt_recovery_timeout, operation).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                warn!(error = %error, operation_name, "ACP async completion receipt recovery failed");
                Err("receipt_recovery_failed")
            }
            Err(_) => {
                warn!(operation_name, "ACP async completion receipt recovery timed out");
                Err("receipt_recovery_timeout")
            }
        }
    }

    async fn record_recovery_ack(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
        status: AsyncCompletionAckStatus,
        code: Option<&str>,
    ) -> Result<bool, &'static str> {
        let params = RecordAsyncCompletionAckParams {
            completion_id: &dispatch.request.completion_id,
            conversation_id: &dispatch.conversation_id,
            acp_session_id: &dispatch.request.session_id,
            payload_sha256,
            status,
            code,
        };
        self.wait_for_receipt_recovery(self.receipt_repo.record_ack(&params), "record_ack")
            .await
    }

    async fn mark_unknown(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
        error_code: &str,
        outcome_code: &str,
    ) -> bool {
        if let Err(error) = self
            .receipt_repo
            .mark_unknown(&dispatch.request.completion_id, &self.owner_instance_id, error_code)
            .await
        {
            warn!(error = %error, "ACP async completion unknown transition failed");
        }
        self.record_ack(
            dispatch,
            payload_sha256,
            AsyncCompletionAckStatus::ExplicitUnknown,
            Some(outcome_code),
        )
        .await
    }

    async fn record_ack(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        payload_sha256: &str,
        status: AsyncCompletionAckStatus,
        code: Option<&str>,
    ) -> bool {
        let params = RecordAsyncCompletionAckParams {
            completion_id: &dispatch.request.completion_id,
            conversation_id: &dispatch.conversation_id,
            acp_session_id: &dispatch.request.session_id,
            payload_sha256,
            status,
            code,
        };
        match self.receipt_repo.record_ack(&params).await {
            Ok(true) => true,
            Ok(false) => {
                warn!(
                    completion_id_bytes = dispatch.request.completion_id.len(),
                    status = status.as_str(),
                    "ACP async completion acknowledgement did not match the current receipt identity/state"
                );
                false
            }
            Err(error) => {
                warn!(
                    error = %error,
                    status = status.as_str(),
                    "ACP async completion acknowledgement persistence failed"
                );
                false
            }
        }
    }

    async fn reject_with_receipt(
        &self,
        dispatch: &CommandEveAsyncCompletionDispatch,
        bound_session_id: &str,
        payload_sha256: &str,
        code: &str,
    ) -> CommandEveAsyncCompletionResult {
        match self
            .receipt_repo
            .record_rejected(&RecordRejectedAsyncCompletionReceiptParams {
                completion_id: &dispatch.request.completion_id,
                conversation_id: &dispatch.conversation_id,
                bound_acp_session_id: bound_session_id,
                requested_acp_session_id: &dispatch.request.session_id,
                payload_sha256,
                code,
            })
            .await
        {
            Ok(true) => rejected(code),
            Ok(false) => {
                warn!(
                    completion_id_bytes = dispatch.request.completion_id.len(),
                    code, "ACP async completion rejection was not durably recorded"
                );
                retryable("rejection_persistence_failed")
            }
            Err(error) => {
                warn!(error = %error, code, "ACP async completion rejection persistence failed");
                retryable("rejection_persistence_failed")
            }
        }
    }
}

fn retryable(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::RetryableBusy { code: code.to_owned() }
}

fn rejected(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::Rejected { code: code.to_owned() }
}

/// Terminal explicit-unknown result. Only constructed after the exact
/// `ExplicitUnknown` acknowledgement was durably persisted with the same
/// code — the receipt repository remains the sole terminal-outcome
/// authority.
fn persisted_unknown(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::PersistedUnknown { code: code.to_owned() }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aionui_ai_agent::{AcpSessionBinding, AcpSessionBindingTurnGate, AgentError, AgentInstance};
    use aionui_api_types::{
        AcpAsyncCompletionRequest, COMMAND_EVE_ASYNC_COMPLETION_VERSION, ConversationRuntimeStateKind,
        ConversationRuntimeSummary,
    };
    use aionui_common::TimestampMs;
    use aionui_db::{
        AsyncCompletionReceiptRecord, DbError, SqliteAcpSessionRepository, SqliteAsyncCompletionReceiptRepository,
        SqliteConversationRepository, SqlitePool, init_database_memory,
    };
    use tokio::sync::{Barrier, oneshot};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedAck {
        status: AsyncCompletionAckStatus,
        code: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedRejection {
        completion_id: String,
        conversation_id: String,
        bound_acp_session_id: String,
        requested_acp_session_id: String,
        code: String,
    }

    struct RecordingReceiptRepo {
        claim: AsyncCompletionReceiptClaim,
        ack_applied: bool,
        rejected_applied: bool,
        mark_retryable_applied: bool,
        mark_completed_applied: bool,
        mark_unknown_applied: bool,
        claim_calls: AtomicUsize,
        acks: Mutex<Vec<RecordedAck>>,
        rejections: Mutex<Vec<RecordedRejection>>,
        retryable_codes: Mutex<Vec<String>>,
        unknown_error_codes: Mutex<Vec<String>>,
        stall_retryable: bool,
    }

    impl RecordingReceiptRepo {
        fn new(claim: AsyncCompletionReceiptClaim) -> Self {
            Self {
                claim,
                ack_applied: true,
                rejected_applied: true,
                mark_retryable_applied: true,
                mark_completed_applied: true,
                mark_unknown_applied: true,
                claim_calls: AtomicUsize::new(0),
                acks: Mutex::new(Vec::new()),
                rejections: Mutex::new(Vec::new()),
                retryable_codes: Mutex::new(Vec::new()),
                unknown_error_codes: Mutex::new(Vec::new()),
                stall_retryable: false,
            }
        }

        fn recorded_acks(&self) -> Vec<RecordedAck> {
            self.acks.lock().expect("ack recorder poisoned").clone()
        }

        fn recorded_rejections(&self) -> Vec<RecordedRejection> {
            self.rejections.lock().expect("rejection recorder poisoned").clone()
        }

        fn unknown_error_codes(&self) -> Vec<String> {
            self.unknown_error_codes
                .lock()
                .expect("unknown error recorder poisoned")
                .clone()
        }

        fn with_stalled_retryable(mut self) -> Self {
            self.stall_retryable = true;
            self
        }
    }

    #[async_trait::async_trait]
    impl IAsyncCompletionReceiptRepository for RecordingReceiptRepo {
        async fn claim(
            &self,
            _params: &ClaimAsyncCompletionReceiptParams<'_>,
        ) -> Result<AsyncCompletionReceiptClaim, DbError> {
            self.claim_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.claim.clone())
        }

        async fn mark_retryable(
            &self,
            _completion_id: &str,
            _owner_instance_id: &str,
            error_code: &str,
        ) -> Result<bool, DbError> {
            self.retryable_codes
                .lock()
                .expect("retryable recorder poisoned")
                .push(error_code.to_owned());
            if self.stall_retryable {
                std::future::pending::<()>().await;
            }
            Ok(self.mark_retryable_applied)
        }

        async fn mark_completed(
            &self,
            _completion_id: &str,
            _owner_instance_id: &str,
            _turn_id: &str,
        ) -> Result<bool, DbError> {
            Ok(self.mark_completed_applied)
        }

        async fn mark_unknown(
            &self,
            _completion_id: &str,
            _owner_instance_id: &str,
            error_code: &str,
        ) -> Result<bool, DbError> {
            self.unknown_error_codes
                .lock()
                .expect("unknown error recorder poisoned")
                .push(error_code.to_owned());
            Ok(self.mark_unknown_applied)
        }

        async fn record_ack(&self, params: &RecordAsyncCompletionAckParams<'_>) -> Result<bool, DbError> {
            self.acks.lock().expect("ack recorder poisoned").push(RecordedAck {
                status: params.status,
                code: params.code.map(ToOwned::to_owned),
            });
            Ok(self.ack_applied)
        }

        async fn record_rejected(
            &self,
            params: &RecordRejectedAsyncCompletionReceiptParams<'_>,
        ) -> Result<bool, DbError> {
            self.rejections
                .lock()
                .expect("rejection recorder poisoned")
                .push(RecordedRejection {
                    completion_id: params.completion_id.to_owned(),
                    conversation_id: params.conversation_id.to_owned(),
                    bound_acp_session_id: params.bound_acp_session_id.to_owned(),
                    requested_acp_session_id: params.requested_acp_session_id.to_owned(),
                    code: params.code.to_owned(),
                });
            Ok(self.rejected_applied)
        }

        async fn list_for_conversation(
            &self,
            _conversation_id: &str,
        ) -> Result<Vec<AsyncCompletionReceiptRecord>, DbError> {
            Ok(Vec::new())
        }
    }

    /// Holds a real SQLite transaction open after the same receipt insert
    /// performed by the production repository. The single-connection memory
    /// pool makes a recovery query block until cancellation drops this future.
    ///
    /// It is intentionally test-only: production continues to use the native
    /// `SqliteAsyncCompletionReceiptRepository` as its sole receipt authority.
    struct TransactionalStalledClaimRepo {
        pool: SqlitePool,
        claim_started: Arc<Barrier>,
    }

    impl TransactionalStalledClaimRepo {
        fn delegate(&self) -> SqliteAsyncCompletionReceiptRepository {
            SqliteAsyncCompletionReceiptRepository::new(self.pool.clone())
        }
    }

    #[async_trait::async_trait]
    impl IAsyncCompletionReceiptRepository for TransactionalStalledClaimRepo {
        async fn claim(
            &self,
            params: &ClaimAsyncCompletionReceiptParams<'_>,
        ) -> Result<AsyncCompletionReceiptClaim, DbError> {
            let mut transaction = self.pool.begin().await?;
            sqlx::query(
                "INSERT INTO command_eve_async_completion_receipts \
                 (completion_id, conversation_id, acp_session_id, payload_sha256, state, \
                  owner_instance_id, turn_id, attempt_count, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, 'processing', ?, ?, 1, 1, 1)",
            )
            .bind(params.completion_id)
            .bind(params.conversation_id)
            .bind(params.acp_session_id)
            .bind(params.payload_sha256)
            .bind(params.owner_instance_id)
            .bind(params.turn_id)
            .execute(&mut *transaction)
            .await?;
            self.claim_started.wait().await;

            // Cancellation must drop `transaction` here. Keeping the future
            // pending exercises the exact SQLite self-block the deadline path
            // used to risk, rather than a pure in-memory stub.
            std::future::pending::<Result<AsyncCompletionReceiptClaim, DbError>>().await
        }

        async fn mark_retryable(
            &self,
            completion_id: &str,
            owner_instance_id: &str,
            error_code: &str,
        ) -> Result<bool, DbError> {
            self.delegate()
                .mark_retryable(completion_id, owner_instance_id, error_code)
                .await
        }

        async fn mark_completed(
            &self,
            completion_id: &str,
            owner_instance_id: &str,
            turn_id: &str,
        ) -> Result<bool, DbError> {
            self.delegate()
                .mark_completed(completion_id, owner_instance_id, turn_id)
                .await
        }

        async fn mark_unknown(
            &self,
            completion_id: &str,
            owner_instance_id: &str,
            error_code: &str,
        ) -> Result<bool, DbError> {
            self.delegate()
                .mark_unknown(completion_id, owner_instance_id, error_code)
                .await
        }

        async fn record_ack(&self, params: &RecordAsyncCompletionAckParams<'_>) -> Result<bool, DbError> {
            self.delegate().record_ack(params).await
        }

        async fn record_rejected(
            &self,
            params: &RecordRejectedAsyncCompletionReceiptParams<'_>,
        ) -> Result<bool, DbError> {
            self.delegate().record_rejected(params).await
        }

        async fn list_for_conversation(
            &self,
            conversation_id: &str,
        ) -> Result<Vec<AsyncCompletionReceiptRecord>, DbError> {
            self.delegate().list_for_conversation(conversation_id).await
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum StubTurnResult {
        Completed,
        Failed,
        Busy,
        Error,
        Pending,
    }

    struct StubTurnRunner {
        result: StubTurnResult,
        calls: AtomicUsize,
    }

    impl StubTurnRunner {
        fn new(result: StubTurnResult) -> Self {
            Self {
                result,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl IAsyncCompletionTurnRunner for StubTurnRunner {
        async fn run(
            &self,
            request: ConversationAgentTurnRequest,
            turn_id: String,
            _project_build_options: Option<BuildTaskOptions>,
            _turn_gate: &AcpSessionBindingTurnGate,
        ) -> Result<ConversationAgentTurnOutcome, ConversationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.result {
                StubTurnResult::Completed => Ok(ConversationAgentTurnOutcome {
                    conversation_id: request.conversation_id,
                    turn_id,
                    status: ConversationAgentTurnStatus::Completed,
                    runtime: ConversationRuntimeSummary {
                        state: ConversationRuntimeStateKind::Idle,
                        can_send_message: true,
                        has_task: false,
                        task_status: None,
                        is_processing: false,
                        pending_confirmations: 0,
                        turn_id: None,
                    },
                }),
                StubTurnResult::Failed => Ok(ConversationAgentTurnOutcome {
                    conversation_id: request.conversation_id,
                    turn_id,
                    status: ConversationAgentTurnStatus::Failed,
                    runtime: ConversationRuntimeSummary {
                        state: ConversationRuntimeStateKind::Idle,
                        can_send_message: true,
                        has_task: false,
                        task_status: None,
                        is_processing: false,
                        pending_confirmations: 0,
                        turn_id: None,
                    },
                }),
                StubTurnResult::Busy => Err(ConversationError::Busy {
                    reason: "test busy".to_owned(),
                }),
                StubTurnResult::Error => Err(ConversationError::BadRequest {
                    reason: "test turn error".to_owned(),
                }),
                StubTurnResult::Pending => std::future::pending().await,
            }
        }
    }

    struct StubTaskManager;

    #[async_trait::async_trait]
    impl IWorkerTaskManager for StubTaskManager {
        fn get_task(&self, _conversation_id: &str) -> Option<AgentInstance> {
            None
        }

        async fn get_or_build_task(
            &self,
            _conversation_id: &str,
            _options: BuildTaskOptions,
        ) -> Result<AgentInstance, AgentError> {
            Err(AgentError::internal("unused test task manager"))
        }

        fn kill(&self, _conversation_id: &str, _reason: Option<AgentKillReason>) -> Result<(), AgentError> {
            Ok(())
        }

        fn kill_and_wait(
            &self,
            _conversation_id: &str,
            _reason: Option<AgentKillReason>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            Box::pin(std::future::ready(()))
        }

        async fn clear(&self) {}

        fn active_count(&self) -> usize {
            0
        }

        fn collect_idle(&self, _idle_threshold_ms: TimestampMs) -> Vec<String> {
            Vec::new()
        }
    }

    async fn test_pool(bound_session_id: Option<&str>) -> SqlitePool {
        let db = init_database_memory().await.expect("memory database");
        let pool = db.pool().clone();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at, updated_at) \
             VALUES ('user-1', 'async-consumer-test', 'none', 1, 1)",
        )
        .execute(&pool)
        .await
        .expect("insert user");
        sqlx::query(
            "INSERT INTO conversations (id, user_id, name, type, extra, status, created_at, updated_at) \
             VALUES ('conversation-1', 'user-1', 'test', 'acp', '{}', 'pending', 1, 1)",
        )
        .execute(&pool)
        .await
        .expect("insert conversation");
        sqlx::query(
            "INSERT INTO acp_session \
             (conversation_id, agent_source, agent_id, session_id, session_status, session_config, last_active_at) \
             VALUES ('conversation-1', 'builtin', 'hermes', ?, 'idle', '{}', 1)",
        )
        .bind(bound_session_id)
        .execute(&pool)
        .await
        .expect("insert ACP session");
        pool
    }

    async fn consumer_with(
        receipt_repo: Arc<RecordingReceiptRepo>,
        turn_result: StubTurnResult,
        bound_session_id: Option<&str>,
    ) -> (CommandEveAsyncCompletionConsumer, Arc<StubTurnRunner>) {
        let pool = test_pool(bound_session_id).await;
        let turn_runner = Arc::new(StubTurnRunner::new(turn_result));
        let consumer = CommandEveAsyncCompletionConsumer::with_turn_runner(
            turn_runner.clone(),
            Arc::new(SqliteConversationRepository::new(pool.clone())),
            Arc::new(SqliteAcpSessionRepository::new(pool)),
            receipt_repo,
            Arc::new(StubTaskManager),
            "owner-test".to_owned(),
        );
        (consumer, turn_runner)
    }

    async fn dispatch(
        session_id: &str,
    ) -> (
        CommandEveAsyncCompletionDispatch,
        oneshot::Receiver<CommandEveAsyncCompletionResult>,
    ) {
        let (reply, receiver) = oneshot::channel();
        let binding = AcpSessionBinding::bound_for_test(session_id).await;
        dispatch_for_binding(session_id, binding, reply, receiver)
    }

    fn dispatch_for_binding(
        session_id: &str,
        binding: AcpSessionBinding,
        reply: oneshot::Sender<CommandEveAsyncCompletionResult>,
        receiver: oneshot::Receiver<CommandEveAsyncCompletionResult>,
    ) -> (
        CommandEveAsyncCompletionDispatch,
        oneshot::Receiver<CommandEveAsyncCompletionResult>,
    ) {
        let lease = binding.lease().expect("test session lease");
        (
            CommandEveAsyncCompletionDispatch {
                conversation_id: "conversation-1".to_owned(),
                request: AcpAsyncCompletionRequest {
                    version: COMMAND_EVE_ASYNC_COMPLETION_VERSION.to_owned(),
                    completion_id: "completion-1".to_owned(),
                    session_id: session_id.to_owned(),
                    content: "Background work finished".to_owned(),
                },
                kind: CommandEveAsyncCompletionDispatchKind::Apply,
                turn_gate: AcpSessionBindingTurnGate::new(binding, lease.clone()),
                lease,
                project_build_options: None,
                reply,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn timed_out_preturn_drops_real_sqlite_claim_before_bounded_recovery() {
        let claim_started = Arc::new(Barrier::new(2));
        let pool = test_pool(Some("session-1")).await;
        let repo = Arc::new(TransactionalStalledClaimRepo {
            pool: pool.clone(),
            claim_started: Arc::clone(&claim_started),
        });
        let turn_runner = Arc::new(StubTurnRunner::new(StubTurnResult::Completed));
        let mut consumer = CommandEveAsyncCompletionConsumer::with_turn_runner(
            turn_runner.clone(),
            Arc::new(SqliteConversationRepository::new(pool.clone())),
            Arc::new(SqliteAcpSessionRepository::new(pool.clone())),
            repo,
            Arc::new(StubTaskManager),
            "owner-test".to_owned(),
        );
        consumer.admission_timeout = Duration::from_millis(10);
        consumer.receipt_recovery_timeout = Duration::from_millis(50);
        let binding = AcpSessionBinding::bound_for_test("session-1").await;
        let (reply, receiver) = oneshot::channel();
        let (completion, _unused_reply) = dispatch_for_binding("session-1", binding.clone(), reply, receiver);

        let consumer = Arc::new(consumer);
        let completion_task = tokio::spawn({
            let consumer = Arc::clone(&consumer);
            async move { consumer.consume(&completion).await }
        });
        claim_started.wait().await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), completion_task)
                .await
                .expect("pre-turn deadline must resolve the stalled claim")
                .unwrap(),
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "receipt_recovery_unavailable".to_owned(),
            }
        );
        assert_eq!(
            turn_runner.calls.load(Ordering::SeqCst),
            0,
            "no turn may start after close"
        );
        let receipt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM command_eve_async_completion_receipts WHERE completion_id = 'completion-1'",
        )
        .fetch_one(&pool)
        .await
        .expect("the cancelled transaction must release the SQLite connection");
        assert_eq!(receipt_count, 0, "the dropped claim transaction must roll back");
    }

    #[tokio::test]
    async fn receipt_recovery_timeout_is_fail_closed() {
        let repo = Arc::new(
            RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-recovery-timeout".to_owned(),
            })
            .with_stalled_retryable(),
        );
        let (mut consumer, _) = consumer_with(repo, StubTurnResult::Completed, Some("session-1")).await;
        consumer.receipt_recovery_timeout = Duration::from_millis(1);
        let (completion, _receiver) = dispatch("session-1").await;

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                consumer.resolve_claimed_without_turn(
                    &completion,
                    &hex_sha256(completion.request.content.as_bytes()),
                    "test_retry",
                    "test_unknown",
                    "test_unknown_outcome",
                ),
            )
            .await
            .expect("receipt recovery must have a deadline"),
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "receipt_recovery_timeout".to_owned(),
            }
        );
    }

    #[test]
    fn payload_hash_is_stable_and_content_sensitive() {
        assert_eq!(
            hex_sha256(b"wake"),
            "51391bf0ab33e8272bcfca0d61b5ab242391822f331fe51ac5930b58da8e5b25"
        );
        assert_ne!(hex_sha256(b"wake"), hex_sha256(b"wake "));
    }

    #[tokio::test]
    async fn consumer_persists_accepted_and_fails_closed_when_the_ack_writer_refuses_success() {
        let accepted_repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
            turn_id: "turn-accepted".to_owned(),
        }));
        let (consumer, runner) =
            consumer_with(accepted_repo.clone(), StubTurnResult::Completed, Some("session-1")).await;
        let (accepted_dispatch, _receiver) = dispatch("session-1").await;
        assert_eq!(
            consumer.consume(&accepted_dispatch).await,
            CommandEveAsyncCompletionResult::Completed {
                turn_id: "turn-accepted".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            accepted_repo.recorded_acks(),
            vec![RecordedAck {
                status: AsyncCompletionAckStatus::Accepted,
                code: None
            }]
        );

        let mut refusing = RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
            turn_id: "turn-refused".to_owned(),
        });
        refusing.ack_applied = false;
        let refusing = Arc::new(refusing);
        let (consumer, _) = consumer_with(refusing.clone(), StubTurnResult::Completed, Some("session-1")).await;
        let (refusing_dispatch, _receiver) = dispatch("session-1").await;
        assert_eq!(
            consumer.consume(&refusing_dispatch).await,
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "ack_persistence_failed".to_owned()
            }
        );
        assert_eq!(refusing.recorded_acks()[0].status, AsyncCompletionAckStatus::Accepted);
    }

    #[tokio::test]
    async fn consumer_persists_already_applied_in_flight_retryable_and_unknown_claims() {
        let cases = [
            (
                AsyncCompletionReceiptClaim::AlreadyCompleted {
                    turn_id: "turn-existing".to_owned(),
                },
                CommandEveAsyncCompletionResult::AlreadyCompleted {
                    turn_id: "turn-existing".to_owned(),
                },
                AsyncCompletionAckStatus::AlreadyApplied,
                None,
            ),
            (
                AsyncCompletionReceiptClaim::InFlight {
                    turn_id: "turn-in-flight".to_owned(),
                },
                CommandEveAsyncCompletionResult::RetryableBusy {
                    code: "receipt_in_flight".to_owned(),
                },
                AsyncCompletionAckStatus::Retryable,
                Some("receipt_in_flight"),
            ),
            (
                AsyncCompletionReceiptClaim::Unknown {
                    turn_id: "turn-unknown".to_owned(),
                },
                CommandEveAsyncCompletionResult::PersistedUnknown {
                    code: "outcome_unknown_receipt".to_owned(),
                },
                AsyncCompletionAckStatus::ExplicitUnknown,
                Some("outcome_unknown_receipt"),
            ),
        ];

        for (claim, expected_result, expected_status, expected_code) in cases {
            let repo = Arc::new(RecordingReceiptRepo::new(claim));
            let (consumer, runner) = consumer_with(repo.clone(), StubTurnResult::Completed, Some("session-1")).await;
            let (case_dispatch, _receiver) = dispatch("session-1").await;
            assert_eq!(consumer.consume(&case_dispatch).await, expected_result);
            assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                repo.recorded_acks(),
                vec![RecordedAck {
                    status: expected_status,
                    code: expected_code.map(ToOwned::to_owned),
                }]
            );
        }
    }

    #[tokio::test]
    async fn consumer_persists_wire_exact_explicit_unknown_codes() {
        for (turn_result, mark_completed_applied, error_code, outcome_code) in [
            (
                StubTurnResult::Completed,
                false,
                "complete_transition_failed",
                "outcome_unknown_complete_transition",
            ),
            (
                StubTurnResult::Failed,
                true,
                "turn_failed",
                "outcome_unknown_turn_failed",
            ),
            (StubTurnResult::Error, true, "turn_error", "outcome_unknown_turn_error"),
        ] {
            let mut recording = RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-unknown".to_owned(),
            });
            recording.mark_completed_applied = mark_completed_applied;
            let repo = Arc::new(recording);
            let (consumer, _) = consumer_with(repo.clone(), turn_result, Some("session-1")).await;
            let (completion, _receiver) = dispatch("session-1").await;

            assert_eq!(
                consumer.consume(&completion).await,
                CommandEveAsyncCompletionResult::PersistedUnknown {
                    code: outcome_code.to_owned()
                }
            );
            assert_eq!(repo.unknown_error_codes(), vec![error_code]);
            assert_eq!(
                repo.recorded_acks(),
                vec![RecordedAck {
                    status: AsyncCompletionAckStatus::ExplicitUnknown,
                    code: Some(outcome_code.to_owned()),
                }]
            );
        }

        let repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
            turn_id: "turn-timeout".to_owned(),
        }));
        let (mut consumer, _) = consumer_with(repo.clone(), StubTurnResult::Pending, Some("session-1")).await;
        consumer.turn_timeout = Duration::from_millis(1);
        consumer.kill_timeout = Duration::from_millis(1);
        let (completion, _receiver) = dispatch("session-1").await;

        assert_eq!(
            consumer.consume(&completion).await,
            CommandEveAsyncCompletionResult::PersistedUnknown {
                code: "outcome_unknown_turn_timeout".to_owned()
            }
        );
        assert_eq!(repo.unknown_error_codes(), vec!["turn_timeout"]);
        assert_eq!(
            repo.recorded_acks(),
            vec![RecordedAck {
                status: AsyncCompletionAckStatus::ExplicitUnknown,
                code: Some("outcome_unknown_turn_timeout".to_owned()),
            }]
        );
    }

    #[tokio::test]
    async fn consumer_persists_busy_retry_and_rejects_identity_conflict_without_poisoning_ack_state() {
        let busy_repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Claimed {
            turn_id: "turn-busy".to_owned(),
        }));
        let (consumer, runner) = consumer_with(busy_repo.clone(), StubTurnResult::Busy, Some("session-1")).await;
        let (busy_dispatch, _receiver) = dispatch("session-1").await;
        assert_eq!(
            consumer.consume(&busy_dispatch).await,
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "conversation_busy".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            busy_repo.recorded_acks(),
            vec![RecordedAck {
                status: AsyncCompletionAckStatus::Retryable,
                code: Some("conversation_busy".to_owned())
            }]
        );

        let conflict_repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Conflict));
        let (consumer, runner) =
            consumer_with(conflict_repo.clone(), StubTurnResult::Completed, Some("session-1")).await;
        let (conflict_dispatch, _receiver) = dispatch("session-1").await;
        assert_eq!(
            consumer.consume(&conflict_dispatch).await,
            CommandEveAsyncCompletionResult::Rejected {
                code: "receipt_identity_conflict".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        assert!(conflict_repo.recorded_acks().is_empty());
        assert_eq!(
            conflict_repo.recorded_rejections(),
            vec![RecordedRejection {
                completion_id: "completion-1".to_owned(),
                conversation_id: "conversation-1".to_owned(),
                bound_acp_session_id: "session-1".to_owned(),
                requested_acp_session_id: "session-1".to_owned(),
                code: "receipt_identity_conflict".to_owned(),
            }]
        );

        let mut refusing_repo = RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Conflict);
        refusing_repo.rejected_applied = false;
        let refusing_repo = Arc::new(refusing_repo);
        let (consumer, _) = consumer_with(refusing_repo, StubTurnResult::Completed, Some("session-1")).await;
        let (refusing_dispatch, _receiver) = dispatch("session-1").await;
        assert_eq!(
            consumer.consume(&refusing_dispatch).await,
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "rejection_persistence_failed".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn persisted_session_lag_and_pre_bind_remain_retryable_after_router_binding() {
        let stale_repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Conflict));
        let (consumer, runner) =
            consumer_with(stale_repo.clone(), StubTurnResult::Completed, Some("session-previous")).await;
        let (rebound_dispatch, _receiver) = dispatch("session-current").await;
        assert_eq!(
            consumer.consume(&rebound_dispatch).await,
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "session_not_bound".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        assert!(stale_repo.recorded_rejections().is_empty());

        let pre_bind_repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Conflict));
        let (consumer, runner) = consumer_with(pre_bind_repo.clone(), StubTurnResult::Completed, None).await;
        let (pre_bind_dispatch, _receiver) = dispatch("session-pending-load").await;
        assert_eq!(
            consumer.consume(&pre_bind_dispatch).await,
            CommandEveAsyncCompletionResult::RetryableBusy {
                code: "session_not_bound".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        assert!(pre_bind_repo.recorded_rejections().is_empty());
    }

    #[tokio::test]
    async fn route_bound_session_mismatch_is_durably_rejected_before_turn_execution() {
        let repo = Arc::new(RecordingReceiptRepo::new(AsyncCompletionReceiptClaim::Conflict));
        let (consumer, runner) = consumer_with(repo.clone(), StubTurnResult::Completed, Some("session-previous")).await;
        let (mut mismatch, _receiver) = dispatch("session-foreign").await;
        mismatch.kind = CommandEveAsyncCompletionDispatchKind::RejectSessionMismatch {
            bound_session_id: "session-current".to_owned(),
        };

        assert_eq!(
            consumer.consume(&mismatch).await,
            CommandEveAsyncCompletionResult::Rejected {
                code: "session_mismatch".to_owned()
            }
        );
        assert_eq!(runner.calls.load(Ordering::SeqCst), 0);
        assert!(repo.recorded_acks().is_empty());
        assert_eq!(
            repo.recorded_rejections(),
            vec![RecordedRejection {
                completion_id: "completion-1".to_owned(),
                conversation_id: "conversation-1".to_owned(),
                bound_acp_session_id: "session-current".to_owned(),
                requested_acp_session_id: "session-foreign".to_owned(),
                code: "session_mismatch".to_owned(),
            }]
        );
    }
}
