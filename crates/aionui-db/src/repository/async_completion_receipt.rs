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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncCompletionAckStatus {
    Accepted,
    AlreadyApplied,
    Retryable,
    ExplicitUnknown,
}

impl AsyncCompletionAckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AlreadyApplied => "already_applied",
            Self::Retryable => "retryable",
            Self::ExplicitUnknown => "explicit_unknown",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecordAsyncCompletionAckParams<'a> {
    pub completion_id: &'a str,
    pub conversation_id: &'a str,
    pub acp_session_id: &'a str,
    pub payload_sha256: &'a str,
    pub status: AsyncCompletionAckStatus,
    pub code: Option<&'a str>,
}

/// Durable terminal rejection recorded before a completion can enter the
/// ordinary claim/turn lifecycle (for example, a positively bound route that
/// receives a completion from a different ACP session).
///
/// The repository must insert this identity atomically or confirm an
/// idempotent match. It must never mutate a row owned by another conversation,
/// session or payload.
#[derive(Debug, Clone, Copy)]
pub struct RecordRejectedAsyncCompletionReceiptParams<'a> {
    pub completion_id: &'a str,
    pub conversation_id: &'a str,
    pub bound_acp_session_id: &'a str,
    pub requested_acp_session_id: &'a str,
    pub payload_sha256: &'a str,
    pub code: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncCompletionReceiptClaim {
    Claimed { turn_id: String },
    AlreadyCompleted { turn_id: String },
    InFlight { turn_id: String },
    Unknown { turn_id: String },
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AsyncCompletionReceiptRecord {
    pub projection_id: String,
    pub completion_id: String,
    pub conversation_id: String,
    pub acp_session_id: String,
    pub state: String,
    pub turn_id: Option<String>,
    pub attempt_count: i64,
    pub last_error_code: Option<String>,
    pub last_ack_status: Option<String>,
    pub last_ack_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
    pub last_ack_at: Option<i64>,
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

    async fn record_ack(&self, params: &RecordAsyncCompletionAckParams<'_>) -> Result<bool, DbError>;

    async fn record_rejected(&self, params: &RecordRejectedAsyncCompletionReceiptParams<'_>) -> Result<bool, DbError>;

    async fn list_for_conversation(&self, conversation_id: &str) -> Result<Vec<AsyncCompletionReceiptRecord>, DbError>;
}
