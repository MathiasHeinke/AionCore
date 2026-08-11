use crate::DbError;

pub struct ClaimAsyncCompletionReceiptParams<'a> {
    pub completion_id: &'a str,
    pub conversation_id: &'a str,
    pub acp_session_id: &'a str,
    pub payload_sha256: &'a str,
    pub owner_instance_id: &'a str,
    /// Stable turn identity minted before the atomic receipt claim. Existing
    /// receipts always win over a caller's newly proposed value.
    pub turn_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncCompletionReceiptClaim {
    Claimed { turn_id: String },
    AlreadyCompleted { turn_id: String },
    InFlight { turn_id: String },
    Unknown { turn_id: String },
    Conflict,
}

#[async_trait::async_trait]
pub trait IAsyncCompletionReceiptRepository: Send + Sync {
    async fn claim(
        &self,
        params: &ClaimAsyncCompletionReceiptParams<'_>,
    ) -> Result<AsyncCompletionReceiptClaim, DbError>;

    async fn mark_retryable(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        error_code: &str,
    ) -> Result<bool, DbError>;

    async fn mark_completed(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        turn_id: &str,
    ) -> Result<bool, DbError>;

    async fn mark_unknown(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        error_code: &str,
    ) -> Result<bool, DbError>;
}
