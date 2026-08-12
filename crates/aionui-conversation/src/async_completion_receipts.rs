use std::sync::Arc;

use aionui_api_types::{
    AcpAsyncCompletionReceiptListResponse, AcpAsyncCompletionReceiptOutcome, AcpAsyncCompletionReceiptResponse,
    AcpAsyncCompletionReceiptState, COMMAND_EVE_ASYNC_COMPLETION_RECEIPTS_VERSION,
};
use aionui_common::now_ms;
use aionui_db::{AsyncCompletionReceiptRecord, IAsyncCompletionReceiptRepository};

use crate::{ConversationError, ConversationService};

#[derive(Clone)]
pub struct AsyncCompletionReceiptService {
    conversation_service: ConversationService,
    receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
}

impl AsyncCompletionReceiptService {
    pub fn new(
        conversation_service: ConversationService,
        receipt_repo: Arc<dyn IAsyncCompletionReceiptRepository>,
    ) -> Self {
        Self {
            conversation_service,
            receipt_repo,
        }
    }

    pub async fn list(
        &self,
        user_id: &str,
        conversation_id: &str,
    ) -> Result<AcpAsyncCompletionReceiptListResponse, ConversationError> {
        // Ownership is checked before receipt lookup so an authenticated user
        // cannot use completion ids or session ids as a cross-user oracle.
        self.conversation_service.get(user_id, conversation_id).await?;
        let receipts = self
            .receipt_repo
            .list_for_conversation(conversation_id)
            .await?
            .into_iter()
            .map(map_receipt)
            .collect();
        Ok(AcpAsyncCompletionReceiptListResponse {
            version: COMMAND_EVE_ASYNC_COMPLETION_RECEIPTS_VERSION.to_owned(),
            conversation_id: conversation_id.to_owned(),
            reconstructed_from: "persistent_receipts".to_owned(),
            generated_at: now_ms(),
            receipts,
        })
    }
}

fn map_receipt(row: AsyncCompletionReceiptRecord) -> AcpAsyncCompletionReceiptResponse {
    let state = match row.state.as_str() {
        "processing" => AcpAsyncCompletionReceiptState::Processing,
        "pending" => AcpAsyncCompletionReceiptState::Pending,
        "completed" => AcpAsyncCompletionReceiptState::Completed,
        "rejected" => AcpAsyncCompletionReceiptState::Rejected,
        _ => AcpAsyncCompletionReceiptState::ExplicitUnknown,
    };
    let last_outcome = match row.last_ack_status.as_deref() {
        Some("accepted") => Some(AcpAsyncCompletionReceiptOutcome::Accepted),
        Some("already_applied") => Some(AcpAsyncCompletionReceiptOutcome::AlreadyApplied),
        Some("retryable") => Some(AcpAsyncCompletionReceiptOutcome::Retryable),
        Some("rejected") => Some(AcpAsyncCompletionReceiptOutcome::Rejected),
        Some("explicit_unknown") => Some(AcpAsyncCompletionReceiptOutcome::ExplicitUnknown),
        _ if state == AcpAsyncCompletionReceiptState::ExplicitUnknown => {
            Some(AcpAsyncCompletionReceiptOutcome::ExplicitUnknown)
        }
        _ => None,
    };
    AcpAsyncCompletionReceiptResponse {
        projection_id: row.projection_id,
        completion_id: row.completion_id,
        acp_session_id: row.acp_session_id,
        state,
        turn_id: row.turn_id,
        attempt_count: u64::try_from(row.attempt_count).unwrap_or_default(),
        last_error_code: row.last_error_code,
        last_outcome,
        last_outcome_code: row.last_ack_code,
        created_at: row.created_at,
        updated_at: row.updated_at,
        completed_at: row.completed_at,
        last_outcome_at: row.last_ack_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_database_states_fail_closed_to_explicit_unknown() {
        let mapped = map_receipt(AsyncCompletionReceiptRecord {
            projection_id: "execution:completion-1".into(),
            completion_id: "completion-1".into(),
            conversation_id: "conversation-1".into(),
            acp_session_id: "session-1".into(),
            state: "future_state".into(),
            turn_id: Some("turn-1".into()),
            attempt_count: -1,
            last_error_code: Some("owner_changed".into()),
            last_ack_status: Some("future_outcome".into()),
            last_ack_code: None,
            created_at: 1,
            updated_at: 2,
            completed_at: None,
            last_ack_at: None,
        });

        assert_eq!(mapped.state, AcpAsyncCompletionReceiptState::ExplicitUnknown);
        assert_eq!(
            mapped.last_outcome,
            Some(AcpAsyncCompletionReceiptOutcome::ExplicitUnknown)
        );
        assert_eq!(mapped.attempt_count, 0);
    }

    #[test]
    fn pre_claim_rejection_projects_without_a_fake_turn() {
        let mapped = map_receipt(AsyncCompletionReceiptRecord {
            projection_id: "rejection:7".into(),
            completion_id: "completion-foreign".into(),
            conversation_id: "conversation-1".into(),
            acp_session_id: "session-bound".into(),
            state: "rejected".into(),
            turn_id: None,
            attempt_count: 2,
            last_error_code: Some("session_mismatch".into()),
            last_ack_status: Some("rejected".into()),
            last_ack_code: Some("session_mismatch".into()),
            created_at: 1,
            updated_at: 2,
            completed_at: None,
            last_ack_at: Some(2),
        });

        assert_eq!(mapped.projection_id, "rejection:7");
        assert_eq!(mapped.state, AcpAsyncCompletionReceiptState::Rejected);
        assert_eq!(mapped.last_outcome, Some(AcpAsyncCompletionReceiptOutcome::Rejected));
        assert_eq!(mapped.turn_id, None);
    }
}
