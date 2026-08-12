use std::sync::Arc;

use crate::AsyncCompletionReceiptService;
use crate::service::ConversationService;
use aionui_ai_agent::IWorkerTaskManager;

/// Shared state for conversation route handlers.
#[derive(Clone)]
pub struct ConversationRouterState {
    pub service: ConversationService,
    pub async_completion_receipts: AsyncCompletionReceiptService,
    pub task_manager: Arc<dyn IWorkerTaskManager>,
}
