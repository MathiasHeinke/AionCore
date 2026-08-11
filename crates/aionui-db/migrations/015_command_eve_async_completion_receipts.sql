CREATE TABLE IF NOT EXISTS command_eve_async_completion_receipts (
    completion_id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL,
    acp_session_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'processing', 'completed', 'unknown')),
    owner_instance_id TEXT,
    turn_id TEXT NOT NULL,
    last_error_code TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_command_eve_async_completion_conversation
    ON command_eve_async_completion_receipts(conversation_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_command_eve_async_completion_turn
    ON command_eve_async_completion_receipts(conversation_id, turn_id);
