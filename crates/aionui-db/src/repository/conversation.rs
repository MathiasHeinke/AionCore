use aionui_common::{PaginatedResult, TimestampMs, constants::MAX_SAFE_PROJECT_BINDING_REVISION};
use serde::{Deserialize, Serialize};

use crate::error::DbError;
use crate::models::{
    ConversationArtifactRow, ConversationAssistantSnapshotRow, ConversationRow, MessageRow,
    UpsertConversationAssistantSnapshotParams,
};

/// Conversation + message data access abstraction.
///
/// Covers conversation CRUD, extended queries (source/chat, cron-job,
/// associated workspace), and message operations (list, insert, update,
/// delete, search).
///
/// Object-safe via `async_trait` to support `Arc<dyn IConversationRepository>`.
#[async_trait::async_trait]
pub trait IConversationRepository: Send + Sync {
    // ── Conversation CRUD ───────────────────────────────────────────

    /// Returns a conversation by ID, or `None` if not found.
    async fn get(&self, id: &str) -> Result<Option<ConversationRow>, DbError>;

    /// Inserts a new conversation row.
    async fn create(&self, row: &ConversationRow) -> Result<(), DbError>;

    /// Partially updates a conversation. Returns `DbError::NotFound` if ID is missing.
    async fn update(&self, id: &str, updates: &ConversationRowUpdate) -> Result<(), DbError>;

    /// Atomically updates a conversation only while its portable project
    /// binding equals `expected`. SQLite overrides this with a single
    /// conditional UPDATE and returns the exact row written by that statement.
    /// Other adapters fail closed until they provide a genuinely atomic CAS.
    async fn update_project_binding_cas(
        &self,
        id: &str,
        updates: &ConversationRowUpdate,
        expected: &ConversationProjectBindingExpectation,
    ) -> Result<ConversationRow, DbError> {
        let _ = (id, updates, expected);
        Err(DbError::Conflict("PROJECT_BINDING_CAS_UNSUPPORTED".to_owned()))
    }

    /// Atomically applies only the requested top-level `extra` keys while
    /// preserving every concurrent sibling mutation. If `expected_binding`
    /// is present, the same compare-and-swap also guards the portable project
    /// binding. Adapters must override this with a genuine CAS/retry loop;
    /// the default fails closed.
    async fn update_with_extra_patch_cas(
        &self,
        id: &str,
        updates: &ConversationRowUpdate,
        extra_patch: &ConversationExtraPatch,
        expected_binding: Option<&ConversationProjectBindingExpectation>,
    ) -> Result<ConversationRow, DbError> {
        let _ = (id, updates, extra_patch, expected_binding);
        Err(DbError::Conflict("CONVERSATION_EXTRA_PATCH_CAS_UNSUPPORTED".to_owned()))
    }

    /// Deletes a conversation (messages cascade via FK).
    /// Returns `DbError::NotFound` if ID is missing.
    async fn delete(&self, id: &str) -> Result<(), DbError>;

    /// Lists conversations with cursor-based pagination and optional filters.
    async fn list_paginated(
        &self,
        user_id: &str,
        filters: &ConversationFilters,
    ) -> Result<PaginatedResult<ConversationRow>, DbError>;

    // ── Extended queries ────────────────────────────────────────────

    /// Finds a conversation by source, channel chat ID, and agent type.
    async fn find_by_source_and_chat(
        &self,
        user_id: &str,
        source: &str,
        chat_id: &str,
        agent_type: &str,
    ) -> Result<Option<ConversationRow>, DbError>;

    /// Lists conversations whose `extra.cronJobId` matches.
    async fn list_by_cron_job(&self, user_id: &str, cron_job_id: &str) -> Result<Vec<ConversationRow>, DbError>;

    /// Lists conversations sharing the same `extra.workspace` value.
    /// The conversation identified by `conversation_id` is excluded.
    async fn list_associated(&self, user_id: &str, conversation_id: &str) -> Result<Vec<ConversationRow>, DbError>;

    /// Returns the persisted assistant snapshot for a conversation, if any.
    async fn get_assistant_snapshot(
        &self,
        _conversation_id: &str,
    ) -> Result<Option<ConversationAssistantSnapshotRow>, DbError> {
        Ok(None)
    }

    /// Inserts or updates a persisted assistant snapshot for a conversation.
    async fn upsert_assistant_snapshot(
        &self,
        _params: &UpsertConversationAssistantSnapshotParams<'_>,
    ) -> Result<Option<ConversationAssistantSnapshotRow>, DbError> {
        Ok(None)
    }

    /// Deletes the assistant snapshot bound to a conversation.
    async fn delete_assistant_snapshot(&self, _conversation_id: &str) -> Result<bool, DbError> {
        Ok(false)
    }

    // ── Message operations ──────────────────────────────────────────

    /// Returns cursor-paginated messages for a conversation in ascending display order.
    async fn list_messages_page(&self, conv_id: &str, params: &MessagePageParams)
    -> Result<MessagePageResult, DbError>;

    /// Returns a single message scoped to a conversation.
    async fn get_message(&self, _conv_id: &str, _message_id: &str) -> Result<Option<MessageRow>, DbError> {
        Ok(None)
    }

    /// Inserts a new message row.
    async fn insert_message(&self, message: &MessageRow) -> Result<(), DbError>;

    /// Inserts a message row, or merges mutable fields into the existing row with the same ID.
    async fn upsert_message(&self, message: &MessageRow) -> Result<(), DbError> {
        match self.insert_message(message).await {
            Ok(()) => Ok(()),
            Err(DbError::Conflict(_)) => {
                self.update_message(
                    &message.id,
                    &MessageRowUpdate {
                        content: Some(message.content.clone()),
                        status: Some(message.status.clone()),
                        hidden: Some(message.hidden),
                    },
                )
                .await
            }
            Err(err) => Err(err),
        }
    }

    /// Partially updates a message. Returns `DbError::NotFound` if ID is missing.
    async fn update_message(&self, id: &str, updates: &MessageRowUpdate) -> Result<(), DbError>;

    /// Deletes one message scoped to its conversation. Grounded prompt
    /// admission uses this to roll back a provisional user row when the final
    /// ACP response was not delivered.
    async fn delete_message(&self, _conv_id: &str, _message_id: &str) -> Result<(), DbError> {
        Err(DbError::Conflict("MESSAGE_DELETE_UNSUPPORTED".to_owned()))
    }

    /// Deletes all messages belonging to a conversation.
    async fn delete_messages_by_conversation(&self, conv_id: &str) -> Result<(), DbError>;

    /// Finds a message by (conversation_id, msg_id, type) triple.
    async fn get_message_by_msg_id(
        &self,
        conv_id: &str,
        msg_id: &str,
        msg_type: &str,
    ) -> Result<Option<MessageRow>, DbError>;

    /// Lists stale assistant-side runtime messages plus hidden provisional
    /// grounded user rows left in a non-terminal state by a previous process.
    async fn list_stale_runtime_messages(&self) -> Result<Vec<MessageRow>, DbError> {
        Ok(Vec::new())
    }

    /// Full-text search across messages, joining conversation name.
    async fn search_messages(
        &self,
        user_id: &str,
        keyword: &str,
        page: u32,
        page_size: u32,
    ) -> Result<PaginatedResult<MessageSearchRow>, DbError>;

    /// Returns persisted conversation artifacts ordered by `created_at`.
    async fn list_artifacts(&self, _conversation_id: &str) -> Result<Vec<ConversationArtifactRow>, DbError> {
        Ok(Vec::new())
    }

    /// Returns a conversation artifact by ID scoped to a conversation.
    async fn get_artifact(
        &self,
        _conversation_id: &str,
        _artifact_id: &str,
    ) -> Result<Option<ConversationArtifactRow>, DbError> {
        Ok(None)
    }

    /// Inserts or updates a conversation artifact by primary key.
    async fn upsert_artifact(&self, artifact: &ConversationArtifactRow) -> Result<ConversationArtifactRow, DbError> {
        Ok(artifact.clone())
    }

    /// Updates artifact status and returns the updated row if found.
    async fn update_artifact_status(
        &self,
        _conversation_id: &str,
        _artifact_id: &str,
        _status: &str,
        _updated_at: TimestampMs,
    ) -> Result<Option<ConversationArtifactRow>, DbError> {
        Ok(None)
    }

    /// Marks all skill suggestion artifacts for a cron job as saved.
    async fn mark_skill_suggest_artifacts_saved(
        &self,
        _cron_job_id: &str,
        _updated_at: TimestampMs,
    ) -> Result<Vec<ConversationArtifactRow>, DbError> {
        Ok(Vec::new())
    }

    /// Deletes all artifacts belonging to a conversation.
    async fn delete_artifacts_by_conversation(&self, _conversation_id: &str) -> Result<(), DbError> {
        Ok(())
    }

    /// Returns legacy persisted cron trigger rows so callers can synthesize
    /// artifact cards for historical conversations created before artifact migration.
    async fn list_legacy_cron_trigger_messages(&self, _conversation_id: &str) -> Result<Vec<MessageRow>, DbError> {
        Ok(Vec::new())
    }
}

// ── Supporting types ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePageCursor {
    pub created_at: TimestampMs,
    pub id: String,
}

impl From<&MessageRow> for MessagePageCursor {
    fn from(row: &MessageRow) -> Self {
        Self {
            created_at: row.created_at,
            id: row.id.clone(),
        }
    }
}

/// Direction for cursor-based message pagination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessagePageDirection {
    InitialLatest,
    Before { cursor: MessagePageCursor },
    After { cursor: MessagePageCursor },
    Anchor { message_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePageParams {
    pub limit: u32,
    pub direction: MessagePageDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePageResult {
    pub items: Vec<MessageRow>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

/// Filters for paginated conversation listing.
#[derive(Debug, Clone, Default)]
pub struct ConversationFilters {
    /// Cursor: the ID of the last conversation from the previous page.
    pub cursor: Option<String>,
    /// Max items per page (default 20).
    pub limit: u32,
    /// Filter by conversation source.
    pub source: Option<String>,
    /// Filter by `extra.cronJobId`.
    pub cron_job_id: Option<String>,
    /// Filter by pinned status.
    pub pinned: Option<bool>,
}

impl ConversationFilters {
    pub fn effective_limit(&self) -> u32 {
        if self.limit == 0 { 20 } else { self.limit }
    }
}

/// Partial update payload for a conversation row.
///
/// `None` = keep existing value; `Some(v)` = set to `v`.
#[derive(Debug, Clone, Default)]
pub struct ConversationRowUpdate {
    pub name: Option<String>,
    pub pinned: Option<bool>,
    pub pinned_at: Option<Option<TimestampMs>>,
    pub model: Option<Option<String>>,
    pub extra: Option<String>,
    pub status: Option<String>,
    pub updated_at: Option<TimestampMs>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConversationExtraPatch {
    pub set: serde_json::Map<String, serde_json::Value>,
    pub remove: Vec<String>,
}

impl ConversationExtraPatch {
    pub fn touches_project_binding(&self) -> bool {
        const KEYS: [&str; 4] = [
            "project_id",
            "workspace_root_ref",
            "project_binding_revision",
            "project_binding_receipt_id",
        ];
        KEYS.iter()
            .any(|key| self.set.contains_key(*key) || self.remove.iter().any(|removed| removed == key))
    }
}

pub const PROJECT_BINDING_CONFLICT: &str = "PROJECT_BINDING_CONFLICT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationProjectBindingExpectation {
    pub project_id: Option<String>,
    pub workspace_root_ref: Option<String>,
    pub project_binding_revision: u64,
    pub project_binding_receipt_id: Option<String>,
}

impl ConversationProjectBindingExpectation {
    pub fn unbound() -> Self {
        Self::unbound_at(0)
    }

    pub fn unbound_at(project_binding_revision: u64) -> Self {
        Self {
            project_id: None,
            workspace_root_ref: None,
            project_binding_revision,
            project_binding_receipt_id: None,
        }
    }

    pub fn unbound_with_receipt(project_binding_revision: u64, project_binding_receipt_id: Option<String>) -> Self {
        Self {
            project_id: None,
            workspace_root_ref: None,
            project_binding_revision,
            project_binding_receipt_id,
        }
    }

    pub fn bound(
        project_id: impl Into<String>,
        workspace_root_ref: impl Into<String>,
        project_binding_revision: u64,
        project_binding_receipt_id: Option<String>,
    ) -> Self {
        Self {
            project_id: Some(project_id.into()),
            workspace_root_ref: Some(workspace_root_ref.into()),
            project_binding_revision,
            project_binding_receipt_id,
        }
    }

    pub fn matches_extra(&self, extra: &str) -> bool {
        let Ok(extra) = serde_json::from_str::<serde_json::Value>(extra) else {
            return false;
        };
        let project_id = extra.get("project_id").and_then(serde_json::Value::as_str);
        let workspace_root_ref = extra.get("workspace_root_ref").and_then(serde_json::Value::as_str);
        let project_binding_revision = match extra.get("project_binding_revision") {
            Some(value) => value.as_u64(),
            None => Some(0),
        };
        if project_binding_revision != Some(self.project_binding_revision) {
            return false;
        }
        if self.project_binding_revision > MAX_SAFE_PROJECT_BINDING_REVISION {
            return false;
        }
        let project_binding_receipt_id = match extra.get("project_binding_receipt_id") {
            Some(serde_json::Value::String(value)) => Some(value.as_str()),
            Some(serde_json::Value::Null) | None => None,
            Some(_) => return false,
        };
        if project_binding_receipt_id != self.project_binding_receipt_id.as_deref() {
            return false;
        }
        match (&self.project_id, &self.workspace_root_ref) {
            (None, None) => project_id.is_none() && workspace_root_ref.is_none(),
            (Some(expected_project), Some(expected_root)) => {
                project_id == Some(expected_project.as_str()) && workspace_root_ref == Some(expected_root.as_str())
            }
            _ => false,
        }
    }
}

/// Partial update payload for a message row.
#[derive(Debug, Clone, Default)]
pub struct MessageRowUpdate {
    pub content: Option<String>,
    pub status: Option<Option<String>>,
    pub hidden: Option<bool>,
}

/// A single result row from cross-conversation message search.
/// Includes full conversation fields for building nested response.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MessageSearchRow {
    // Message fields
    pub message_id: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub content: String,
    pub created_at: TimestampMs,
    // Conversation fields
    pub conversation_id: String,
    pub conversation_name: String,
    pub conversation_type: String,
    pub conversation_extra: String,
    pub conversation_model: Option<String>,
    pub conversation_status: Option<String>,
    pub conversation_source: Option<String>,
    pub conversation_channel_chat_id: Option<String>,
    pub conversation_pinned: bool,
    pub conversation_pinned_at: Option<TimestampMs>,
    pub conversation_created_at: TimestampMs,
    pub conversation_updated_at: TimestampMs,
}
