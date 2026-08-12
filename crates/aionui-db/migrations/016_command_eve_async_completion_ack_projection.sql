ALTER TABLE command_eve_async_completion_receipts
    ADD COLUMN last_ack_status TEXT;

ALTER TABLE command_eve_async_completion_receipts
    ADD COLUMN last_ack_code TEXT;

ALTER TABLE command_eve_async_completion_receipts
    ADD COLUMN last_ack_at INTEGER;

CREATE INDEX IF NOT EXISTS idx_command_eve_async_completion_conversation_updated
    ON command_eve_async_completion_receipts(conversation_id, updated_at DESC);

-- Terminal rejections that occur before the execution receipt can be claimed
-- live in a separate immutable identity domain. A wrong-session attempt must
-- never reserve or mutate the completion_id used by a later legitimate wake.
CREATE TABLE IF NOT EXISTS command_eve_async_completion_rejections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    bound_acp_session_id TEXT NOT NULL,
    requested_acp_session_id TEXT NOT NULL,
    completion_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    code TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    UNIQUE (
        conversation_id,
        bound_acp_session_id,
        requested_acp_session_id,
        completion_id,
        payload_sha256,
        code
    )
);

CREATE INDEX IF NOT EXISTS idx_command_eve_async_completion_rejections_conversation_updated
    ON command_eve_async_completion_rejections(conversation_id, updated_at DESC);
