use std::sync::Arc;
use std::time::Duration;

use aionui_ai_agent::{CommandEveAsyncCompletionDispatch, CommandEveAsyncCompletionResult, IWorkerTaskManager};
use aionui_common::AgentKillReason;
use aionui_conversation::{
    ConversationAgentTurnRequest, ConversationAgentTurnStatus, ConversationError, ConversationService,
};
use aionui_db::{
    AsyncCompletionReceiptClaim, ClaimAsyncCompletionReceiptParams, IAcpSessionRepository,
    IAsyncCompletionReceiptRepository, IConversationRepository,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};

const ASYNC_COMPLETION_MAX_CONCURRENCY: usize = 4;
const ASYNC_COMPLETION_TURN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const ASYNC_COMPLETION_KILL_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct CommandEveAsyncCompletionConsumer {
    conversation_service: ConversationService,
    conversation_repo: Arc<dyn IConversationRepository>,
    acp_session_repo: Arc<dyn IAcpSessionRepository>,
    receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
    task_manager: Arc<dyn IWorkerTaskManager>,
    owner_instance_id: String,
    turn_timeout: Duration,
    kill_timeout: Duration,
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
        Self {
            conversation_service,
            conversation_repo,
            acp_session_repo,
            receipt_repo,
            task_manager,
            owner_instance_id,
            turn_timeout: ASYNC_COMPLETION_TURN_TIMEOUT,
            kill_timeout: ASYNC_COMPLETION_KILL_TIMEOUT,
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
        let conversation = match self.conversation_repo.get(&dispatch.conversation_id).await {
            Ok(Some(conversation)) => conversation,
            Ok(None) => return rejected("conversation_not_found"),
            Err(error) => {
                warn!(error = %error, "ACP async completion conversation lookup failed");
                return rejected("conversation_lookup_failed");
            }
        };
        let session = match self.acp_session_repo.get(&dispatch.conversation_id).await {
            Ok(Some(session)) => session,
            Ok(None) => return rejected("session_not_found"),
            Err(error) => {
                warn!(error = %error, "ACP async completion session lookup failed");
                return rejected("session_lookup_failed");
            }
        };
        if session.session_id.as_deref() != Some(dispatch.request.session_id.as_str()) {
            return rejected("session_mismatch");
        }

        let payload_sha256 = hex_sha256(dispatch.request.content.as_bytes());
        let proposed_turn_id = ConversationService::mint_turn_id();
        let claim = match self
            .receipt_repo
            .claim(&ClaimAsyncCompletionReceiptParams {
                completion_id: &dispatch.request.completion_id,
                conversation_id: &dispatch.conversation_id,
                acp_session_id: &dispatch.request.session_id,
                payload_sha256: &payload_sha256,
                owner_instance_id: &self.owner_instance_id,
                turn_id: &proposed_turn_id,
            })
            .await
        {
            Ok(claim) => claim,
            Err(error) => {
                warn!(error = %error, "ACP async completion receipt claim failed");
                return rejected("receipt_claim_failed");
            }
        };

        let turn_id = match claim {
            AsyncCompletionReceiptClaim::AlreadyCompleted { turn_id } => {
                return CommandEveAsyncCompletionResult::AlreadyCompleted { turn_id };
            }
            AsyncCompletionReceiptClaim::InFlight { .. } => return retryable("receipt_in_flight"),
            AsyncCompletionReceiptClaim::Unknown { turn_id } => {
                warn!(
                    conversation_id = %dispatch.conversation_id,
                    turn_id = %turn_id,
                    "ACP async completion replay has an explicitly unknown outcome"
                );
                return unknown("outcome_unknown_receipt");
            }
            AsyncCompletionReceiptClaim::Conflict => return rejected("receipt_identity_conflict"),
            AsyncCompletionReceiptClaim::Claimed { turn_id } => turn_id,
        };

        let turn = self.conversation_service.run_command_eve_async_completion_turn(
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
                self.mark_unknown(&dispatch.request.completion_id, "turn_timeout").await;
                return unknown("outcome_unknown_turn_timeout");
            }
        };

        match outcome {
            Err(ConversationError::Busy { .. }) => {
                match self
                    .receipt_repo
                    .mark_retryable(
                        &dispatch.request.completion_id,
                        &self.owner_instance_id,
                        "conversation_busy",
                    )
                    .await
                {
                    Ok(true) => retryable("conversation_busy"),
                    Ok(false) | Err(_) => unknown("outcome_unknown_retry_transition"),
                }
            }
            Ok(outcome) if outcome.status == ConversationAgentTurnStatus::Completed => {
                match self
                    .receipt_repo
                    .mark_completed(&dispatch.request.completion_id, &self.owner_instance_id, &turn_id)
                    .await
                {
                    Ok(true) => {
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
                        self.mark_unknown(&dispatch.request.completion_id, "complete_transition_failed")
                            .await;
                        unknown("outcome_unknown_complete_transition")
                    }
                }
            }
            Ok(_) => {
                self.mark_unknown(&dispatch.request.completion_id, "turn_failed").await;
                unknown("outcome_unknown_turn_failed")
            }
            Err(error) => {
                warn!(error = %error, "ACP async completion turn failed");
                self.mark_unknown(&dispatch.request.completion_id, "turn_error").await;
                unknown("outcome_unknown_turn_error")
            }
        }
    }

    async fn mark_unknown(&self, completion_id: &str, code: &str) {
        if let Err(error) = self
            .receipt_repo
            .mark_unknown(completion_id, &self.owner_instance_id, code)
            .await
        {
            warn!(error = %error, "ACP async completion unknown transition failed");
        }
    }
}

fn retryable(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::RetryableBusy { code: code.to_owned() }
}

fn rejected(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::Rejected { code: code.to_owned() }
}

fn unknown(code: &str) -> CommandEveAsyncCompletionResult {
    CommandEveAsyncCompletionResult::Unknown { code: code.to_owned() }
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_hash_is_stable_and_content_sensitive() {
        assert_eq!(
            hex_sha256(b"wake"),
            "51391bf0ab33e8272bcfca0d61b5ab242391822f331fe51ac5930b58da8e5b25"
        );
        assert_ne!(hex_sha256(b"wake"), hex_sha256(b"wake "));
    }
}
