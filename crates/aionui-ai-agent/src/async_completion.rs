use aionui_api_types::AcpAsyncCompletionRequest;
use tokio::sync::{mpsc, oneshot};

use crate::types::BuildTaskOptions;

/// Transient, in-process routing state for the verified Hermes completion
/// extension. Project build options are copied from the already-attested task
/// build and are never serialized or persisted.
#[derive(Clone)]
pub struct CommandEveAsyncCompletionRoute {
    pub conversation_id: String,
    pub sender: CommandEveAsyncCompletionSender,
    pub project_build_options: Option<BuildTaskOptions>,
}

/// One Hermes background completion, already bound to the canonical host
/// conversation by the ACP client extension router.
pub struct CommandEveAsyncCompletionDispatch {
    pub conversation_id: String,
    pub request: AcpAsyncCompletionRequest,
    pub project_build_options: Option<BuildTaskOptions>,
    pub reply: oneshot::Sender<CommandEveAsyncCompletionResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEveAsyncCompletionResult {
    Completed { turn_id: String },
    AlreadyCompleted { turn_id: String },
    RetryableBusy { code: String },
    Rejected { code: String },
    Unknown { code: String },
}

pub type CommandEveAsyncCompletionSender = mpsc::Sender<CommandEveAsyncCompletionDispatch>;
