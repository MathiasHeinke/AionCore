use aionui_common::now_ms;
use sqlx::{FromRow, SqlitePool};

use super::async_completion_receipt::{
    AsyncCompletionAckStatus, AsyncCompletionReceiptClaim, AsyncCompletionReceiptRecord,
    ClaimAsyncCompletionReceiptParams, IAsyncCompletionReceiptRepository, RecordAsyncCompletionAckParams,
    RecordRejectedAsyncCompletionReceiptParams,
};
use crate::DbError;

pub struct SqliteAsyncCompletionReceiptRepository {
    pool: SqlitePool,
}

impl SqliteAsyncCompletionReceiptRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct ReceiptIdentityRow {
    conversation_id: String,
    acp_session_id: String,
    payload_sha256: String,
    state: String,
    owner_instance_id: Option<String>,
    turn_id: String,
}

#[async_trait::async_trait]
impl IAsyncCompletionReceiptRepository for SqliteAsyncCompletionReceiptRepository {
    async fn claim(
        &self,
        params: &ClaimAsyncCompletionReceiptParams<'_>,
    ) -> Result<AsyncCompletionReceiptClaim, DbError> {
        let now = now_ms();
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO command_eve_async_completion_receipts \
             (completion_id, conversation_id, acp_session_id, payload_sha256, state, \
              owner_instance_id, turn_id, attempt_count, created_at, updated_at) \
             VALUES (?, ?, ?, ?, 'processing', ?, ?, 1, ?, ?)",
        )
        .bind(params.completion_id)
        .bind(params.conversation_id)
        .bind(params.acp_session_id)
        .bind(params.payload_sha256)
        .bind(params.owner_instance_id)
        .bind(params.turn_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 1 {
            tx.commit().await?;
            return Ok(AsyncCompletionReceiptClaim::Claimed {
                turn_id: params.turn_id.to_owned(),
            });
        }

        let existing = sqlx::query_as::<_, ReceiptIdentityRow>(
            "SELECT conversation_id, acp_session_id, payload_sha256, state, owner_instance_id, turn_id \
             FROM command_eve_async_completion_receipts WHERE completion_id = ?",
        )
        .bind(params.completion_id)
        .fetch_one(&mut *tx)
        .await?;

        if existing.conversation_id != params.conversation_id
            || existing.acp_session_id != params.acp_session_id
            || existing.payload_sha256 != params.payload_sha256
        {
            tx.commit().await?;
            return Ok(AsyncCompletionReceiptClaim::Conflict);
        }

        let outcome = match existing.state.as_str() {
            "completed" => AsyncCompletionReceiptClaim::AlreadyCompleted {
                turn_id: existing.turn_id,
            },
            "unknown" => AsyncCompletionReceiptClaim::Unknown {
                turn_id: existing.turn_id,
            },
            "processing" if existing.owner_instance_id.as_deref() == Some(params.owner_instance_id) => {
                AsyncCompletionReceiptClaim::InFlight {
                    turn_id: existing.turn_id,
                }
            }
            "processing" => {
                sqlx::query(
                    "UPDATE command_eve_async_completion_receipts \
                     SET state = 'unknown', owner_instance_id = NULL, last_error_code = 'owner_changed', updated_at = ? \
                     WHERE completion_id = ? AND state = 'processing'",
                )
                .bind(now)
                .bind(params.completion_id)
                .execute(&mut *tx)
                .await?;
                AsyncCompletionReceiptClaim::Unknown {
                    turn_id: existing.turn_id,
                }
            }
            "pending" => {
                let claimed = sqlx::query(
                    "UPDATE command_eve_async_completion_receipts \
                     SET state = 'processing', owner_instance_id = ?, last_error_code = NULL, \
                         attempt_count = attempt_count + 1, updated_at = ? \
                     WHERE completion_id = ? AND state = 'pending'",
                )
                .bind(params.owner_instance_id)
                .bind(now)
                .bind(params.completion_id)
                .execute(&mut *tx)
                .await?;
                if claimed.rows_affected() == 1 {
                    AsyncCompletionReceiptClaim::Claimed {
                        turn_id: existing.turn_id,
                    }
                } else {
                    AsyncCompletionReceiptClaim::InFlight {
                        turn_id: existing.turn_id,
                    }
                }
            }
            _ => AsyncCompletionReceiptClaim::Unknown {
                turn_id: existing.turn_id,
            },
        };
        tx.commit().await?;
        Ok(outcome)
    }

    async fn mark_retryable(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        error_code: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE command_eve_async_completion_receipts \
             SET state = 'pending', owner_instance_id = NULL, last_error_code = ?, updated_at = ? \
             WHERE completion_id = ? AND state = 'processing' AND owner_instance_id = ?",
        )
        .bind(error_code)
        .bind(now_ms())
        .bind(completion_id)
        .bind(owner_instance_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn mark_completed(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        turn_id: &str,
    ) -> Result<bool, DbError> {
        let now = now_ms();
        let result = sqlx::query(
            "UPDATE command_eve_async_completion_receipts \
             SET state = 'completed', owner_instance_id = NULL, last_error_code = NULL, \
                 updated_at = ?, completed_at = ? \
             WHERE completion_id = ? AND state = 'processing' AND owner_instance_id = ? AND turn_id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(completion_id)
        .bind(owner_instance_id)
        .bind(turn_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn mark_unknown(
        &self,
        completion_id: &str,
        owner_instance_id: &str,
        error_code: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE command_eve_async_completion_receipts \
             SET state = 'unknown', owner_instance_id = NULL, last_error_code = ?, updated_at = ? \
             WHERE completion_id = ? AND state = 'processing' AND owner_instance_id = ?",
        )
        .bind(error_code)
        .bind(now_ms())
        .bind(completion_id)
        .bind(owner_instance_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn record_ack(&self, params: &RecordAsyncCompletionAckParams<'_>) -> Result<bool, DbError> {
        let now = now_ms();
        let allowed_previous = match params.status {
            AsyncCompletionAckStatus::Accepted => &["", "retryable", "accepted"][..],
            AsyncCompletionAckStatus::AlreadyApplied => &["", "retryable", "accepted", "already_applied"][..],
            AsyncCompletionAckStatus::Retryable => &["", "retryable"][..],
            AsyncCompletionAckStatus::ExplicitUnknown => &["", "retryable", "explicit_unknown"][..],
        };
        let allowed_state = match params.status {
            AsyncCompletionAckStatus::Accepted | AsyncCompletionAckStatus::AlreadyApplied => "completed",
            AsyncCompletionAckStatus::Retryable => "processing_or_pending",
            AsyncCompletionAckStatus::ExplicitUnknown => "unknown",
        };
        let result = sqlx::query(
            "UPDATE command_eve_async_completion_receipts \
             SET last_ack_status = ?, last_ack_code = ?, last_ack_at = ?, updated_at = ? \
             WHERE completion_id = ? AND conversation_id = ? AND acp_session_id = ? AND payload_sha256 = ? \
               AND ((? = 'processing_or_pending' AND state IN ('processing', 'pending')) OR state = ?) \
               AND COALESCE(last_ack_status, '') IN (?, ?, ?, ?)",
        )
        .bind(params.status.as_str())
        .bind(params.code)
        .bind(now)
        .bind(now)
        .bind(params.completion_id)
        .bind(params.conversation_id)
        .bind(params.acp_session_id)
        .bind(params.payload_sha256)
        .bind(allowed_state)
        .bind(allowed_state)
        .bind(allowed_previous.first().copied().unwrap_or("__none__"))
        .bind(allowed_previous.get(1).copied().unwrap_or("__none__"))
        .bind(allowed_previous.get(2).copied().unwrap_or("__none__"))
        .bind(allowed_previous.get(3).copied().unwrap_or("__none__"))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn record_rejected(&self, params: &RecordRejectedAsyncCompletionReceiptParams<'_>) -> Result<bool, DbError> {
        let now = now_ms();
        let recorded = sqlx::query(
            "INSERT INTO command_eve_async_completion_rejections \
             (conversation_id, bound_acp_session_id, requested_acp_session_id, completion_id, \
              payload_sha256, code, attempt_count, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) \
             ON CONFLICT (conversation_id, bound_acp_session_id, requested_acp_session_id, \
                          completion_id, payload_sha256, code) \
             DO UPDATE SET attempt_count = attempt_count + 1, updated_at = excluded.updated_at",
        )
        .bind(params.conversation_id)
        .bind(params.bound_acp_session_id)
        .bind(params.requested_acp_session_id)
        .bind(params.completion_id)
        .bind(params.payload_sha256)
        .bind(params.code)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(recorded.rows_affected() == 1)
    }

    async fn list_for_conversation(&self, conversation_id: &str) -> Result<Vec<AsyncCompletionReceiptRecord>, DbError> {
        let rows = sqlx::query_as::<_, AsyncCompletionReceiptRecord>(
            "SELECT 'execution:' || completion_id AS projection_id, completion_id, conversation_id, \
                    acp_session_id, state, turn_id, attempt_count, last_error_code, \
                    last_ack_status, last_ack_code, created_at, updated_at, completed_at, last_ack_at \
             FROM command_eve_async_completion_receipts WHERE conversation_id = ? \
             UNION ALL \
             SELECT 'rejection:' || CAST(id AS TEXT) AS projection_id, completion_id, conversation_id, \
                    bound_acp_session_id AS acp_session_id, 'rejected' AS state, NULL AS turn_id, \
                    attempt_count, code AS last_error_code, 'rejected' AS last_ack_status, \
                    code AS last_ack_code, created_at, updated_at, NULL AS completed_at, updated_at AS last_ack_at \
             FROM command_eve_async_completion_rejections WHERE conversation_id = ? \
             ORDER BY updated_at DESC, projection_id ASC \
             LIMIT 100",
        )
        .bind(conversation_id)
        .bind(conversation_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_database_memory;

    async fn setup() -> SqliteAsyncCompletionReceiptRepository {
        let db = init_database_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at, updated_at) \
             VALUES ('user-1', 'receipt-test', 'none', 1, 1)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO conversations (id, user_id, name, type, extra, status, created_at, updated_at) \
             VALUES ('conversation-1', 'user-1', 'test', 'acp', '{}', 'pending', 1, 1)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        SqliteAsyncCompletionReceiptRepository::new(db.pool().clone())
    }

    fn claim_params<'a>(
        completion_id: &'a str,
        owner: &'a str,
        turn_id: &'a str,
    ) -> ClaimAsyncCompletionReceiptParams<'a> {
        ClaimAsyncCompletionReceiptParams {
            completion_id,
            conversation_id: "conversation-1",
            acp_session_id: "session-1",
            payload_sha256: "payload-1",
            owner_instance_id: owner,
            turn_id,
        }
    }

    #[tokio::test]
    async fn busy_retry_reuses_the_atomically_assigned_turn_id() {
        let repo = setup().await;
        assert_eq!(
            repo.claim(&claim_params("completion-1", "owner-1", "turn-1"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-1".to_owned()
            }
        );
        assert_eq!(
            repo.claim(&claim_params("completion-1", "owner-1", "turn-discarded"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::InFlight {
                turn_id: "turn-1".to_owned()
            }
        );
        assert!(repo.mark_retryable("completion-1", "owner-1", "busy").await.unwrap());
        assert_eq!(
            repo.claim(&claim_params("completion-1", "owner-2", "turn-discarded"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-1".to_owned()
            }
        );
        assert!(
            !repo
                .mark_completed("completion-1", "owner-2", "turn-discarded")
                .await
                .unwrap()
        );
        assert!(repo.mark_completed("completion-1", "owner-2", "turn-1").await.unwrap());
        assert_eq!(
            repo.claim(&claim_params("completion-1", "owner-3", "turn-discarded"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::AlreadyCompleted {
                turn_id: "turn-1".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn owner_change_after_possible_start_is_durable_unknown_and_never_reruns() {
        let repo = setup().await;
        assert_eq!(
            repo.claim(&claim_params("completion-2", "owner-1", "turn-2"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-2".to_owned()
            }
        );
        assert_eq!(
            repo.claim(&claim_params("completion-2", "owner-2", "turn-discarded"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Unknown {
                turn_id: "turn-2".to_owned()
            }
        );
        assert_eq!(
            repo.claim(&claim_params("completion-2", "owner-3", "turn-discarded-again"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Unknown {
                turn_id: "turn-2".to_owned()
            }
        );
        assert!(!repo.mark_retryable("completion-2", "owner-3", "unsafe").await.unwrap());
        assert!(!repo.mark_completed("completion-2", "owner-3", "turn-2").await.unwrap());

        let mut conflicting = claim_params("completion-2", "owner-2", "turn-2");
        conflicting.payload_sha256 = "different";
        assert_eq!(
            repo.claim(&conflicting).await.unwrap(),
            AsyncCompletionReceiptClaim::Conflict
        );
    }

    #[tokio::test]
    async fn acknowledgement_outcomes_are_persistent_and_conversation_scoped() {
        let repo = setup().await;
        let claim = claim_params("completion-ack", "owner-1", "turn-ack");
        assert!(matches!(
            repo.claim(&claim).await.unwrap(),
            AsyncCompletionReceiptClaim::Claimed { .. }
        ));
        assert!(
            repo.mark_retryable("completion-ack", "owner-1", "conversation_busy")
                .await
                .unwrap()
        );
        assert!(
            repo.record_ack(&RecordAsyncCompletionAckParams {
                completion_id: "completion-ack",
                conversation_id: "conversation-1",
                acp_session_id: "session-1",
                payload_sha256: "payload-1",
                status: AsyncCompletionAckStatus::Retryable,
                code: Some("conversation_busy"),
            })
            .await
            .unwrap()
        );

        let rows = repo.list_for_conversation("conversation-1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].completion_id, "completion-ack");
        assert_eq!(rows[0].state, "pending");
        assert_eq!(rows[0].last_ack_status.as_deref(), Some("retryable"));
        assert_eq!(rows[0].last_ack_code.as_deref(), Some("conversation_busy"));
        assert!(rows[0].last_ack_at.is_some());
        assert!(
            repo.list_for_conversation("conversation-foreign")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn acknowledgement_updates_are_identity_scoped_and_monotone() {
        let repo = setup().await;
        let claim = claim_params("completion-monotone", "owner-1", "turn-monotone");
        assert!(matches!(
            repo.claim(&claim).await.unwrap(),
            AsyncCompletionReceiptClaim::Claimed { .. }
        ));
        assert!(
            repo.mark_completed("completion-monotone", "owner-1", "turn-monotone")
                .await
                .unwrap()
        );

        let accepted = RecordAsyncCompletionAckParams {
            completion_id: "completion-monotone",
            conversation_id: "conversation-1",
            acp_session_id: "session-1",
            payload_sha256: "payload-1",
            status: AsyncCompletionAckStatus::Accepted,
            code: None,
        };
        assert!(repo.record_ack(&accepted).await.unwrap());
        assert!(
            repo.record_ack(&RecordAsyncCompletionAckParams {
                status: AsyncCompletionAckStatus::AlreadyApplied,
                ..accepted
            })
            .await
            .unwrap()
        );
        assert!(!repo.record_ack(&accepted).await.unwrap());
        assert!(
            !repo
                .record_ack(&RecordAsyncCompletionAckParams {
                    conversation_id: "conversation-foreign",
                    status: AsyncCompletionAckStatus::AlreadyApplied,
                    ..accepted
                })
                .await
                .unwrap()
        );

        let rows = repo.list_for_conversation("conversation-1").await.unwrap();
        assert_eq!(rows[0].last_ack_status.as_deref(), Some("already_applied"));
    }

    #[tokio::test]
    async fn rejected_receipts_are_real_idempotent_and_never_poison_foreign_identity() {
        let repo = setup().await;
        let rejected = RecordRejectedAsyncCompletionReceiptParams {
            completion_id: "completion-rejected",
            conversation_id: "conversation-1",
            bound_acp_session_id: "session-1",
            requested_acp_session_id: "foreign-session",
            payload_sha256: "rejected-payload",
            code: "session_mismatch",
        };
        assert!(repo.record_rejected(&rejected).await.unwrap());
        assert!(repo.record_rejected(&rejected).await.unwrap());

        // A rejection event has a separate identity domain and therefore
        // cannot reserve the completion id used by a later legitimate wake.
        assert_eq!(
            repo.claim(&claim_params("completion-rejected", "owner-1", "turn-legitimate"))
                .await
                .unwrap(),
            AsyncCompletionReceiptClaim::Claimed {
                turn_id: "turn-legitimate".to_owned()
            }
        );

        let rows = repo.list_for_conversation("conversation-1").await.unwrap();
        assert_eq!(rows.len(), 2);
        let rejection = rows
            .iter()
            .find(|row| row.state == "rejected")
            .expect("rejection projection");
        assert!(rejection.projection_id.starts_with("rejection:"));
        assert_eq!(rejection.completion_id, "completion-rejected");
        assert_eq!(rejection.acp_session_id, "foreign-session");
        assert_eq!(rejection.turn_id, None);
        assert_eq!(rejection.attempt_count, 2);
        assert_eq!(rejection.last_error_code.as_deref(), Some("session_mismatch"));
        assert_eq!(rejection.last_ack_status.as_deref(), Some("rejected"));
        assert_eq!(rejection.last_ack_code.as_deref(), Some("session_mismatch"));

        let legitimate = rows
            .iter()
            .find(|row| row.state == "processing")
            .expect("legitimate execution receipt");
        assert_eq!(legitimate.projection_id, "execution:completion-rejected");
        assert_eq!(legitimate.turn_id.as_deref(), Some("turn-legitimate"));
    }

    #[tokio::test]
    async fn explicit_unknown_ack_is_persisted_for_the_matching_unknown_receipt() {
        let repo = setup().await;
        let claim = claim_params("completion-unknown", "owner-1", "turn-unknown");
        assert!(matches!(
            repo.claim(&claim).await.unwrap(),
            AsyncCompletionReceiptClaim::Claimed { .. }
        ));
        assert!(
            repo.mark_unknown("completion-unknown", "owner-1", "turn_timeout")
                .await
                .unwrap()
        );
        assert!(
            repo.record_ack(&RecordAsyncCompletionAckParams {
                completion_id: "completion-unknown",
                conversation_id: "conversation-1",
                acp_session_id: "session-1",
                payload_sha256: "payload-1",
                status: AsyncCompletionAckStatus::ExplicitUnknown,
                code: Some("turn_timeout"),
            })
            .await
            .unwrap()
        );

        let rows = repo.list_for_conversation("conversation-1").await.unwrap();
        assert_eq!(rows[0].state, "unknown");
        assert_eq!(rows[0].last_ack_status.as_deref(), Some("explicit_unknown"));
        assert_eq!(rows[0].last_ack_code.as_deref(), Some("turn_timeout"));
    }
}
