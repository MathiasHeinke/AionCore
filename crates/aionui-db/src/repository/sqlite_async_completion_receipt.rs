use aionui_common::now_ms;
use sqlx::{FromRow, SqlitePool};

use super::async_completion_receipt::{
    AsyncCompletionReceiptClaim, ClaimAsyncCompletionReceiptParams, IAsyncCompletionReceiptRepository,
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
}
