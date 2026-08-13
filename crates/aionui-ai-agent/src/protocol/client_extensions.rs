//! Fail-closed agent-to-client ACP extension handling.
//!
//! This is intentionally not a generic renderer RPC. The only accepted
//! methods are Hermes' bounded `read_preview` and `read_terminal` requests,
//! and each public response path consumes one matching request exactly once.

mod read_terminal;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_client_protocol::schema::{AgentRequest, ExtRequest};
use agent_client_protocol::{Error as JsonRpcError, Responder};
use aionui_api_types::{
    AcpAsyncCompletionAckStatus, AcpAsyncCompletionRequest, AcpAsyncCompletionResponse, AcpReadPreviewRequestEventData,
    AcpReadPreviewResponse, AcpReadPreviewResponseRequest, AcpReadPreviewResult, COMMAND_EVE_ASYNC_COMPLETION_VERSION,
    COMMAND_EVE_READ_PREVIEW_VERSION,
};
use regex::Regex;
use tokio::sync::{Semaphore, broadcast, mpsc::error::TrySendError, oneshot};
use tracing::{info, warn};

use crate::error::AgentError;
use crate::prompt_admission::{
    COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD, COMMAND_EVE_PROMPT_ADMISSION_VERSION,
    CommandEvePromptAdmissionClaimResult, CommandEvePromptAdmissionDecision,
    CommandEvePromptAdmissionFinalizeClaimResult, CommandEvePromptAdmissionPeerAckClaimResult,
    CommandEvePromptAdmissionPhase, CommandEvePromptAdmissionResponse, CommandEvePromptAdmissionStatus,
    CommandEvePromptAdmissionWireRequest, acknowledge_command_eve_prompt_admission, admit_command_eve_prompt_admission,
    claim_command_eve_prompt_admission, complete_command_eve_prompt_admission,
    complete_command_eve_prompt_admission_commit, finalize_command_eve_prompt_admission,
    mark_command_eve_prompt_finalize_response, reject_command_eve_prompt_admissions_for_session,
};
use crate::protocol::error::AcpError;
use crate::protocol::events::AgentStreamEvent;
use crate::{
    AcpSessionBinding, CommandEveAsyncCompletionDispatch, CommandEveAsyncCompletionDispatchKind,
    CommandEveAsyncCompletionResult, CommandEveAsyncCompletionRoute,
};

use read_terminal::{COMMAND_EVE_READ_TERMINAL_EXT_METHOD, PendingReadTerminal, cancel_pending_terminal};

pub(crate) const COMMAND_EVE_READ_PREVIEW_EXT_METHOD: &str = "command_eve/read_preview";
pub(crate) const COMMAND_EVE_READ_PREVIEW_WIRE_METHOD: &str = "_command_eve/read_preview";
pub(crate) const COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD: &str = "command_eve/async_completion";
pub(crate) const COMMAND_EVE_ASYNC_COMPLETION_WIRE_METHOD: &str = "_command_eve/async_completion";

const CLIENT_EXTENSION_TIMEOUT: Duration = Duration::from_secs(45);
const ASYNC_COMPLETION_REPLY_TIMEOUT: Duration = Duration::from_secs(31 * 60);
const ASYNC_COMPLETION_MAX_CONCURRENCY: usize = 4;
const MAX_REQUEST_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_ASYNC_COMPLETION_PAYLOAD_BYTES: usize = 96 * 1024;
const MAX_ASYNC_COMPLETION_CONTENT_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_PAYLOAD_BYTES: usize = 32 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_START: u32 = 10_000_000;
const MAX_COUNT: u32 = 24_000;
const MAX_TOTAL_CHARS: u32 = 10_000_000;
const MAX_TEXT_CHARS: usize = 24_000;
const MAX_URL_BYTES: usize = 4 * 1024;
const MAX_TITLE_BYTES: usize = 512;
const MAX_NOTE_BYTES: usize = 2 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_PROMPT_ADMISSION_PAYLOAD_BYTES: usize = 2 * 1024;

type ResponseSender =
    Box<dyn FnOnce(Result<serde_json::Value, JsonRpcError>) -> Result<(), JsonRpcError> + Send + 'static>;

struct PendingReadPreview {
    session_id: String,
    start: Option<u32>,
    count: Option<u32>,
    respond: ResponseSender,
}

#[derive(Default)]
struct ExtensionState {
    read_preview_enabled: bool,
    read_terminal_enabled: bool,
    async_completion_enabled: bool,
    pending: HashMap<String, PendingReadPreview>,
    pending_terminal: HashMap<String, PendingReadTerminal>,
}

#[derive(Clone)]
pub(crate) struct AcpClientExtensionRouter {
    event_tx: broadcast::Sender<AgentStreamEvent>,
    state: Arc<Mutex<ExtensionState>>,
    session_binding: AcpSessionBinding,
    timeout: Duration,
    async_completion_reply_timeout: Duration,
    async_completion_slots: Arc<Semaphore>,
    async_completion_route: Option<CommandEveAsyncCompletionRoute>,
}

impl AcpClientExtensionRouter {
    pub(crate) fn new(event_tx: broadcast::Sender<AgentStreamEvent>) -> Self {
        Self::with_timeout(event_tx, CLIENT_EXTENSION_TIMEOUT)
    }

    fn with_timeout(event_tx: broadcast::Sender<AgentStreamEvent>, timeout: Duration) -> Self {
        Self {
            event_tx,
            state: Arc::new(Mutex::new(ExtensionState::default())),
            session_binding: AcpSessionBinding::default(),
            timeout,
            async_completion_reply_timeout: ASYNC_COMPLETION_REPLY_TIMEOUT,
            async_completion_slots: Arc::new(Semaphore::new(ASYNC_COMPLETION_MAX_CONCURRENCY)),
            async_completion_route: None,
        }
    }

    pub(crate) fn with_async_completion(mut self, route: CommandEveAsyncCompletionRoute) -> Self {
        self.session_binding = route.session_binding.clone();
        self.async_completion_route = Some(route);
        self
    }

    #[cfg(test)]
    fn with_async_completion_limits(mut self, reply_timeout: Duration, max_concurrency: usize) -> Self {
        self.async_completion_reply_timeout = reply_timeout;
        self.async_completion_slots = Arc::new(Semaphore::new(max_concurrency));
        self
    }

    pub(crate) fn enable_async_completion(&self) -> Result<(), AcpError> {
        if self.async_completion_route.is_none() {
            return Err(local_binding_error());
        }
        let mut state = self.state.lock().map_err(|_| local_binding_error())?;
        state.async_completion_enabled = true;
        Ok(())
    }

    /// Enable the single allowlisted extension for a verified Hermes backend.
    pub(crate) fn enable_read_preview(&self) -> Result<(), AcpError> {
        let mut state = self.state.lock().map_err(|_| local_binding_error())?;
        state.read_preview_enabled = true;
        Ok(())
    }

    /// Bind extension requests to the canonical session acknowledged by ACP.
    /// Rebinding cancels every request from the previous session and advances
    /// the binding generation so previously minted completion leases become
    /// stale. A same-session bind is idempotent only when no begin-binding
    /// transition occurred.
    pub(crate) async fn bind_session(&self, session_id: &str) -> Result<(), AcpError> {
        validate_identifier(session_id).map_err(|_| local_binding_error())?;
        let previous_session = self.session_binding.bound_session_id();
        match self.session_binding.bind(session_id).await {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(()) => return Err(local_binding_error()),
        }
        if let Some(previous_session) = previous_session {
            reject_command_eve_prompt_admissions_for_session(
                &previous_session,
                "ATTACHMENT_PROMPT_FINALIZE_PEER_ACK_UNAVAILABLE",
            );
        }
        let (cancelled, cancelled_terminal) = {
            let mut state = self.state.lock().map_err(|_| local_binding_error())?;
            (
                state.pending.drain().map(|(_, pending)| pending).collect::<Vec<_>>(),
                state
                    .pending_terminal
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>(),
            )
        };
        cancel_pending(cancelled, "session_rebound");
        cancel_pending_terminal(cancelled_terminal, "session_rebound");
        Ok(())
    }

    /// Invalidate the live binding at the beginning of every
    /// `session/new|load|resume` attempt. While the request is in flight the
    /// route is unbound: async completions stay retryable
    /// (`session_not_bound`), pending renderer reads from the previous
    /// session are cancelled, and every lease minted before this transition
    /// is stale. A failed request leaves the route unbound until a later
    /// successful bind.
    pub(crate) async fn begin_session_binding(&self) {
        let previous_session = self.session_binding.bound_session_id();
        if self.session_binding.invalidate().await.is_err() {
            warn!("ACP binding admission gate unavailable while beginning session binding");
            return;
        }
        if let Some(previous_session) = previous_session {
            reject_command_eve_prompt_admissions_for_session(
                &previous_session,
                "ATTACHMENT_PROMPT_FINALIZE_PEER_ACK_UNAVAILABLE",
            );
        }
        let (cancelled, cancelled_terminal) = {
            let Ok(mut state) = self.state.lock() else {
                warn!("ACP client extension state unavailable while beginning session binding");
                return;
            };
            (
                state.pending.drain().map(|(_, pending)| pending).collect::<Vec<_>>(),
                state
                    .pending_terminal
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>(),
            )
        };
        cancel_pending(cancelled, "session_rebinding");
        cancel_pending_terminal(cancelled_terminal, "session_rebinding");
    }

    /// Fence a close before its RPC crosses the transport. The original
    /// session id is retained by the caller for that RPC, while completion
    /// admission is already fail-closed and every pre-close lease is stale.
    /// A failed close leaves the route unbound; reopening must be a positive
    /// `session/new|load|resume` bind, never restoration of an old lease.
    pub(crate) async fn begin_session_close(&self, session_id: &str) -> Result<(), AcpError> {
        if !self
            .session_binding
            .unbind_matching(session_id)
            .await
            .map_err(|_| local_binding_error())?
        {
            return Ok(());
        }
        reject_command_eve_prompt_admissions_for_session(session_id, "ATTACHMENT_PROMPT_FINALIZE_PEER_ACK_UNAVAILABLE");
        let (cancelled, cancelled_terminal) = {
            let mut state = self.state.lock().map_err(|_| local_binding_error())?;
            (
                state.pending.drain().map(|(_, pending)| pending).collect::<Vec<_>>(),
                state
                    .pending_terminal
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>(),
            )
        };
        cancel_pending(cancelled, "session_closed");
        cancel_pending_terminal(cancelled_terminal, "session_closed");
        Ok(())
    }

    /// Cancel all pending requests before transport shutdown/disconnect.
    pub(crate) fn cancel_all(&self, reason: &'static str) {
        let cancelled_session = self.session_binding.bound_session_id();
        self.session_binding.close_admissions();
        if let Some(cancelled_session) = cancelled_session {
            reject_command_eve_prompt_admissions_for_session(
                &cancelled_session,
                "ATTACHMENT_PROMPT_FINALIZE_PEER_ACK_UNAVAILABLE",
            );
        }
        let (cancelled, cancelled_terminal) = {
            let Ok(mut state) = self.state.lock() else {
                warn!("ACP client extension state unavailable during cancellation");
                return;
            };
            state.read_preview_enabled = false;
            state.read_terminal_enabled = false;
            state.async_completion_enabled = false;
            (
                state.pending.drain().map(|(_, pending)| pending).collect::<Vec<_>>(),
                state
                    .pending_terminal
                    .drain()
                    .map(|(_, pending)| pending)
                    .collect::<Vec<_>>(),
            )
        };
        cancel_pending(cancelled, reason);
        cancel_pending_terminal(cancelled_terminal, reason);
    }

    /// Handle one SDK extension request. Unknown methods fail closed.
    pub(crate) fn handle_agent_request(&self, request: AgentRequest, responder: Responder<serde_json::Value>) {
        let respond: ResponseSender = Box::new(move |result| responder.respond_with_result(result));
        match request {
            AgentRequest::ExtMethodRequest(request) => {
                self.handle_ext_request(request, respond);
            }
            _ => {
                warn!("Rejected non-allowlisted ACP agent request");
                respond_ignoring_transport(respond, Err(JsonRpcError::method_not_found()));
            }
        }
    }

    /// Correlate and consume a renderer response exactly once.
    pub(crate) fn respond_read_preview(
        &self,
        response: AcpReadPreviewResponseRequest,
    ) -> Result<AcpReadPreviewResponse, AgentError> {
        validate_response_envelope(&response)?;

        let mut result = response.result;
        let response_for_wire = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| AgentError::internal("ACP read_preview state unavailable"))?;
            let pending = state.pending.get(&response.request_id).ok_or_else(|| {
                AgentError::conflict("ACP read_preview request is unknown, expired, or already answered")
            })?;
            if self.session_binding.bound_session_id().as_deref() != Some(response.session_id.as_str())
                || pending.session_id != response.session_id
            {
                return Err(AgentError::conflict("ACP read_preview session binding mismatch"));
            }
            if let Some(value) = result.as_ref() {
                validate_result(value, pending)?;
            }
            redact_result(result.as_mut());

            let wire = AcpReadPreviewResponseRequest {
                version: response.version,
                request_id: response.request_id.clone(),
                session_id: response.session_id.clone(),
                result,
            };
            let wire_value = serde_json::to_value(&wire)
                .map_err(|_| AgentError::internal("Failed to encode ACP read_preview response"))?;
            let payload_bytes = serde_json::to_vec(&wire_value)
                .map_err(|_| AgentError::internal("Failed to encode ACP read_preview response"))?;
            if payload_bytes.len() > MAX_RESPONSE_PAYLOAD_BYTES {
                return Err(AgentError::bad_request(
                    "ACP read_preview response exceeds the payload cap",
                ));
            }

            let pending = state
                .pending
                .remove(&response.request_id)
                .expect("pending request was checked while holding the same lock");
            (wire_value, pending.respond)
        };

        let (wire_value, respond) = response_for_wire;
        respond(Ok(wire_value)).map_err(|_| AgentError::bad_gateway("ACP read_preview response transport failed"))?;
        info!(
            method = COMMAND_EVE_READ_PREVIEW_WIRE_METHOD,
            request_id_bytes = response.request_id.len(),
            session_id_bytes = response.session_id.len(),
            "ACP read_preview response consumed"
        );
        Ok(AcpReadPreviewResponse { accepted: true })
    }

    fn handle_ext_request(&self, request: ExtRequest, respond: ResponseSender) {
        if request.method.as_ref() == COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD {
            self.handle_prompt_admission_request(request.params.get(), respond);
            return;
        }
        self.handle_raw_request(request.method.as_ref(), request.params.get(), respond);
    }

    fn handle_prompt_admission_request(&self, raw_params: &str, respond: ResponseSender) {
        if raw_params.len() > MAX_PROMPT_ADMISSION_PAYLOAD_BYTES {
            respond_ignoring_transport(respond, Err(rpc_internal("payload_too_large")));
            return;
        }
        let wire = match serde_json::from_str::<CommandEvePromptAdmissionWireRequest>(raw_params) {
            Ok(wire) => wire,
            Err(_) => {
                respond_ignoring_transport(respond, Err(rpc_internal("invalid_shape")));
                return;
            }
        };
        let bound_session_matches = self
            .session_binding
            .bound_session_id()
            .is_some_and(|session_id| session_id == wire.session_id);
        if !bound_session_matches {
            respond_prompt_admission(respond, &wire.request_id, false);
            return;
        }

        let request = wire.request();
        match wire.phase {
            CommandEvePromptAdmissionPhase::Accept => {
                let accepted = admit_command_eve_prompt_admission(&request, &wire.session_id).is_ok();
                let transport_ok = respond_prompt_admission(respond, &wire.request_id, accepted);
                if !accepted || !transport_ok {
                    complete_command_eve_prompt_admission(&wire.request_id, &wire.session_id, false);
                }
            }
            CommandEvePromptAdmissionPhase::Commit => {
                match claim_command_eve_prompt_admission(&request, &wire.session_id) {
                    Ok(CommandEvePromptAdmissionClaimResult::AlreadyAccepted) => {
                        respond_prompt_admission(respond, &wire.request_id, true);
                    }
                    Ok(CommandEvePromptAdmissionClaimResult::AwaitingDecision(decision_rx)) => {
                        let request_id = wire.request_id;
                        let session_id = wire.session_id;
                        tokio::spawn(async move {
                            let accepted = matches!(decision_rx.await, Ok(CommandEvePromptAdmissionDecision::Accepted));
                            if accepted {
                                // Publish the committed state before enqueueing
                                // the response so an immediate peer finalize
                                // cannot race the local state transition.
                                complete_command_eve_prompt_admission_commit(&request_id, &session_id, true);
                            }
                            let transport_ok = respond_prompt_admission(respond, &request_id, accepted);
                            if !accepted || !transport_ok {
                                complete_command_eve_prompt_admission_commit(&request_id, &session_id, false);
                            }
                        });
                    }
                    Err(_) => {
                        respond_prompt_admission(respond, &wire.request_id, false);
                    }
                }
            }
            CommandEvePromptAdmissionPhase::Finalize => {
                match finalize_command_eve_prompt_admission(&request, &wire.session_id) {
                    Ok(CommandEvePromptAdmissionFinalizeClaimResult::AlreadyAccepted) => {
                        respond_prompt_admission(respond, &wire.request_id, true);
                    }
                    Ok(CommandEvePromptAdmissionFinalizeClaimResult::AwaitingDecision(decision_rx)) => {
                        let request_id = wire.request_id;
                        let session_id = wire.session_id;
                        tokio::spawn(async move {
                            let accepted = matches!(decision_rx.await, Ok(CommandEvePromptAdmissionDecision::Accepted));
                            let response_queued = respond_prompt_admission(respond, &request_id, accepted);
                            let _ = mark_command_eve_prompt_finalize_response(
                                &request_id,
                                &session_id,
                                accepted && response_queued,
                            );
                        });
                    }
                    Err(_) => {
                        respond_prompt_admission(respond, &wire.request_id, false);
                    }
                }
            }
            CommandEvePromptAdmissionPhase::Ack => {
                match acknowledge_command_eve_prompt_admission(&request, &wire.session_id) {
                    Ok(CommandEvePromptAdmissionPeerAckClaimResult::AlreadyAccepted) => {
                        respond_prompt_admission(respond, &wire.request_id, true);
                    }
                    Ok(CommandEvePromptAdmissionPeerAckClaimResult::AwaitingDecision(decision_rx)) => {
                        let request_id = wire.request_id;
                        tokio::spawn(async move {
                            let accepted = matches!(decision_rx.await, Ok(CommandEvePromptAdmissionDecision::Accepted));
                            respond_prompt_admission(respond, &request_id, accepted);
                        });
                    }
                    Err(_) => {
                        respond_prompt_admission(respond, &wire.request_id, false);
                    }
                }
            }
        }
    }

    fn handle_raw_request(&self, method: &str, raw_params: &str, respond: ResponseSender) {
        if method == COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD {
            self.handle_async_completion_request(raw_params, respond);
            return;
        }
        if method == COMMAND_EVE_READ_TERMINAL_EXT_METHOD {
            self.handle_read_terminal_request(raw_params, respond);
            return;
        }
        if method != COMMAND_EVE_READ_PREVIEW_EXT_METHOD {
            warn!("Rejected non-allowlisted ACP extension request");
            respond_ignoring_transport(respond, Err(JsonRpcError::method_not_found()));
            return;
        }
        if !self.state.lock().is_ok_and(|state| state.read_preview_enabled) {
            warn!("Rejected ACP read_preview request for a disabled backend");
            respond_ignoring_transport(respond, Err(JsonRpcError::method_not_found()));
            return;
        }
        if raw_params.len() > MAX_REQUEST_PAYLOAD_BYTES {
            reject_request(respond, "payload_too_large");
            return;
        }
        let request = match serde_json::from_str::<AcpReadPreviewRequestEventData>(raw_params) {
            Ok(request) => request,
            Err(_) => {
                reject_request(respond, "invalid_shape");
                return;
            }
        };
        if let Err(reason) = validate_request(&request) {
            reject_request(respond, reason);
            return;
        }

        {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(_) => {
                    respond_ignoring_transport(respond, Err(rpc_internal("state_unavailable")));
                    return;
                }
            };
            if self.session_binding.bound_session_id().as_deref() != Some(request.session_id.as_str()) {
                reject_request(respond, "session_mismatch");
                return;
            }
            if state.pending.contains_key(&request.request_id)
                || state.pending_terminal.contains_key(&request.request_id)
            {
                reject_request(respond, "duplicate_request_id");
                return;
            }
            state.pending.insert(
                request.request_id.clone(),
                PendingReadPreview {
                    session_id: request.session_id.clone(),
                    start: request.start,
                    count: request.count,
                    respond,
                },
            );
        }

        if self
            .event_tx
            .send(AgentStreamEvent::AcpReadPreviewRequest(request.clone()))
            .is_err()
        {
            self.reject_pending(&request.request_id, "renderer_unavailable");
            return;
        }

        info!(
            method = COMMAND_EVE_READ_PREVIEW_WIRE_METHOD,
            request_id_bytes = request.request_id.len(),
            session_id_bytes = request.session_id.len(),
            "Accepted ACP read_preview request"
        );
        let state = Arc::clone(&self.state);
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            expire_pending(state, &request.request_id, &request.session_id);
        });
    }

    fn handle_async_completion_request(&self, raw_params: &str, respond: ResponseSender) {
        let enabled = self.state.lock().is_ok_and(|state| state.async_completion_enabled);
        if !enabled {
            if self.async_completion_route.is_some() {
                respond_async_completion_retryable(respond, "session_not_bound");
                return;
            }
            warn!(
                method = COMMAND_EVE_ASYNC_COMPLETION_WIRE_METHOD,
                "Rejected disabled ACP async completion"
            );
            respond_ignoring_transport(respond, Err(JsonRpcError::method_not_found()));
            return;
        }
        if raw_params.len() > MAX_ASYNC_COMPLETION_PAYLOAD_BYTES {
            respond_async_completion_rejected(respond, "payload_too_large");
            return;
        }
        let request = match serde_json::from_str::<AcpAsyncCompletionRequest>(raw_params) {
            Ok(request) => request,
            Err(_) => {
                respond_async_completion_rejected(respond, "invalid_shape");
                return;
            }
        };
        if request.version != COMMAND_EVE_ASYNC_COMPLETION_VERSION {
            respond_async_completion_rejected(respond, "unsupported_version");
            return;
        }
        if validate_identifier(&request.completion_id).is_err() {
            respond_async_completion_rejected(respond, "invalid_completion_id");
            return;
        }
        if validate_identifier(&request.session_id).is_err() {
            respond_async_completion_rejected(respond, "invalid_session_id");
            return;
        }
        if request.content.trim().is_empty() || request.content.len() > MAX_ASYNC_COMPLETION_CONTENT_BYTES {
            respond_async_completion_rejected(respond, "invalid_content");
            return;
        }
        let Some(lease) = self.session_binding.lease() else {
            respond_async_completion_retryable(respond, "session_not_bound");
            return;
        };

        let Some(route) = self.async_completion_route.clone() else {
            respond_async_completion_retryable(respond, "consumer_unavailable");
            return;
        };
        let kind = if lease.session_id() == request.session_id.as_str() {
            CommandEveAsyncCompletionDispatchKind::Apply
        } else {
            // A genuine post-bind mismatch becomes terminal only after the
            // existing consumer has durably recorded it in the canonical
            // conversation's rejection receipt domain.
            CommandEveAsyncCompletionDispatchKind::RejectSessionMismatch {
                bound_session_id: lease.session_id().to_owned(),
            }
        };
        let permit = match Arc::clone(&self.async_completion_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                respond_async_completion_retryable(respond, "consumer_saturated");
                return;
            }
        };
        let (reply, reply_rx) = oneshot::channel();
        let dispatch = CommandEveAsyncCompletionDispatch {
            conversation_id: route.conversation_id,
            request,
            kind,
            turn_gate: crate::AcpSessionBindingTurnGate::new(self.session_binding.clone(), lease.clone()),
            lease,
            project_build_options: route.project_build_options,
            reply,
        };
        match route.sender.try_send(dispatch) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                respond_async_completion_retryable(respond, "consumer_saturated");
                return;
            }
            Err(TrySendError::Closed(_)) => {
                respond_async_completion_retryable(respond, "consumer_unavailable");
                return;
            }
        }
        let reply_timeout = self.async_completion_reply_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            // Transport gaps between router and consumer are never terminal:
            // the receipt ledger remains the sole authority that may record
            // an explicit-unknown outcome, so Hermes retains and retries.
            let result = match tokio::time::timeout(reply_timeout, reply_rx).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => CommandEveAsyncCompletionResult::RetryableBusy {
                    code: "consumer_reply_dropped".to_owned(),
                },
                Err(_) => CommandEveAsyncCompletionResult::RetryableBusy {
                    code: "consumer_reply_timeout".to_owned(),
                },
            };
            let response = match result {
                CommandEveAsyncCompletionResult::Completed { turn_id } => AcpAsyncCompletionResponse {
                    status: AcpAsyncCompletionAckStatus::Accepted,
                    turn_id: Some(turn_id),
                    code: None,
                },
                CommandEveAsyncCompletionResult::AlreadyCompleted { turn_id } => AcpAsyncCompletionResponse {
                    status: AcpAsyncCompletionAckStatus::AlreadyApplied,
                    turn_id: Some(turn_id),
                    code: None,
                },
                CommandEveAsyncCompletionResult::RetryableBusy { code } => AcpAsyncCompletionResponse {
                    status: AcpAsyncCompletionAckStatus::Retryable,
                    turn_id: None,
                    code: Some(code),
                },
                CommandEveAsyncCompletionResult::Rejected { code } => AcpAsyncCompletionResponse {
                    status: AcpAsyncCompletionAckStatus::Rejected,
                    turn_id: None,
                    code: Some(code),
                },
                CommandEveAsyncCompletionResult::PersistedUnknown { code } => AcpAsyncCompletionResponse {
                    status: AcpAsyncCompletionAckStatus::Rejected,
                    turn_id: None,
                    code: Some(code),
                },
            };
            respond_ignoring_transport(
                respond,
                serde_json::to_value(response).map_err(|_| rpc_internal("response_encode_failed")),
            );
        });
    }

    fn reject_pending(&self, request_id: &str, reason: &'static str) {
        let pending = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.pending.remove(request_id));
        if let Some(pending) = pending {
            respond_ignoring_transport(pending.respond, Err(rpc_internal(reason)));
        }
    }

    #[cfg(test)]
    pub(crate) fn bound_session_id(&self) -> Option<String> {
        self.session_binding.bound_session_id()
    }

    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.state.lock().map(|state| state.pending.len()).unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn pending_terminal_count(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.pending_terminal.len())
            .unwrap_or_default()
    }
}

fn validate_request(request: &AcpReadPreviewRequestEventData) -> Result<(), &'static str> {
    if request.version != COMMAND_EVE_READ_PREVIEW_VERSION {
        return Err("unsupported_version");
    }
    validate_identifier(&request.request_id).map_err(|_| "invalid_request_id")?;
    validate_identifier(&request.session_id).map_err(|_| "invalid_session_id")?;
    if request.start.is_some_and(|start| start > MAX_START) {
        return Err("start_out_of_range");
    }
    if request.count.is_some_and(|count| count == 0 || count > MAX_COUNT) {
        return Err("count_out_of_range");
    }
    Ok(())
}

fn validate_response_envelope(response: &AcpReadPreviewResponseRequest) -> Result<(), AgentError> {
    if response.version != COMMAND_EVE_READ_PREVIEW_VERSION {
        return Err(AgentError::bad_request("Unsupported ACP read_preview response version"));
    }
    validate_identifier(&response.request_id)
        .map_err(|_| AgentError::bad_request("Invalid ACP read_preview request_id"))?;
    validate_identifier(&response.session_id)
        .map_err(|_| AgentError::bad_request("Invalid ACP read_preview session_id"))?;
    Ok(())
}

fn validate_result(result: &AcpReadPreviewResult, pending: &PendingReadPreview) -> Result<(), AgentError> {
    bounded_field(&result.url, MAX_URL_BYTES, "url")?;
    bounded_field(&result.title, MAX_TITLE_BYTES, "title")?;
    if result.text.chars().count() > MAX_TEXT_CHARS {
        return Err(AgentError::bad_request(
            "ACP read_preview text exceeds the character cap",
        ));
    }
    if let Some(note) = result.note.as_deref() {
        bounded_field(note, MAX_NOTE_BYTES, "note")?;
    }
    if let Some(path) = result.path.as_deref() {
        bounded_field(path, MAX_PATH_BYTES, "path")?;
    }
    if result.total_chars > MAX_TOTAL_CHARS || result.end > result.total_chars || result.start > result.end {
        return Err(AgentError::bad_request(
            "ACP read_preview result offsets are out of range",
        ));
    }
    let expected_start = pending.start.unwrap_or(0).min(result.total_chars);
    if result.start != expected_start {
        return Err(AgentError::conflict(
            "ACP read_preview result start does not match the request",
        ));
    }
    let requested_count = pending.count.unwrap_or(MAX_COUNT);
    let span = result.end - result.start;
    if span > requested_count || result.text.chars().count() > requested_count as usize {
        return Err(AgentError::bad_request(
            "ACP read_preview result exceeds the requested window",
        ));
    }
    Ok(())
}

fn bounded_field(value: &str, max_bytes: usize, field: &'static str) -> Result<(), AgentError> {
    if value.len() > max_bytes {
        Err(AgentError::bad_request(format!(
            "ACP read_preview {field} exceeds the payload cap"
        )))
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

fn redact_result(result: Option<&mut AcpReadPreviewResult>) {
    let Some(result) = result else { return };
    result.url = strip_url_secret_parts(&result.url);
    result.title = redact_secret_text(&result.title);
    result.text = redact_secret_text(&result.text);
    result.note = result.note.as_deref().map(redact_secret_text);
}

fn strip_url_secret_parts(value: &str) -> String {
    let end = value.find(['?', '#']).unwrap_or(value.len());
    value[..end].to_owned()
}

fn redact_secret_text(value: &str) -> String {
    let assignment = Regex::new(
        r"(?i)(authorization\s*:\s*bearer|x-api-key\s*:|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|client[_-]?secret\s*[:=]|password\s*[:=])\s*[^\s,;]+",
    )
    .expect("static secret assignment regex");
    let token =
        Regex::new(r"(?i)\b(?:sk-[a-z0-9_-]{8,}|ghp_[a-z0-9]{8,}|github_pat_[a-z0-9_]{8,}|xox[baprs]-[a-z0-9-]{8,})\b")
            .expect("static secret token regex");
    let assignments_redacted = assignment.replace_all(value, "${1} [redacted]");
    let tokens_redacted = token.replace_all(&assignments_redacted, "[redacted]");
    redact_url_queries_in_text(&tokens_redacted)
}

fn redact_url_queries_in_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for chunk in value.split_inclusive(char::is_whitespace) {
        let trailing_ws_len = chunk
            .chars()
            .last()
            .filter(|ch| ch.is_whitespace())
            .map(char::len_utf8)
            .unwrap_or(0);
        let token_end = chunk.len() - trailing_ws_len;
        let token = &chunk[..token_end];
        if (token.starts_with("http://") || token.starts_with("https://")) && token.contains('?') {
            let base = token.split_once('?').map(|(base, _)| base).unwrap_or(token);
            output.push_str(base);
            output.push_str("?[redacted]");
        } else {
            output.push_str(token);
        }
        output.push_str(&chunk[token_end..]);
    }
    output
}

fn expire_pending(state: Arc<Mutex<ExtensionState>>, request_id: &str, session_id: &str) {
    let pending = state.lock().ok().and_then(|mut state| {
        let matches = state
            .pending
            .get(request_id)
            .is_some_and(|pending| pending.session_id == session_id);
        matches.then(|| state.pending.remove(request_id)).flatten()
    });
    if let Some(pending) = pending {
        warn!(
            method = COMMAND_EVE_READ_PREVIEW_WIRE_METHOD,
            request_id_bytes = request_id.len(),
            session_id_bytes = session_id.len(),
            "ACP read_preview request timed out"
        );
        respond_ignoring_transport(pending.respond, Err(rpc_internal("timeout")));
    }
}

fn cancel_pending(pending: Vec<PendingReadPreview>, reason: &'static str) {
    for pending in pending {
        respond_ignoring_transport(pending.respond, Err(rpc_internal(reason)));
    }
}

fn reject_request(respond: ResponseSender, reason: &'static str) {
    warn!(
        method = COMMAND_EVE_READ_PREVIEW_WIRE_METHOD,
        reason, "Rejected ACP read_preview request"
    );
    respond_ignoring_transport(
        respond,
        Err(JsonRpcError::invalid_params().data(serde_json::json!({ "reason": reason }))),
    );
}

fn respond_async_completion_rejected(respond: ResponseSender, code: &'static str) {
    warn!(
        method = COMMAND_EVE_ASYNC_COMPLETION_WIRE_METHOD,
        code, "Rejected ACP async completion"
    );
    let response = AcpAsyncCompletionResponse {
        status: AcpAsyncCompletionAckStatus::Rejected,
        turn_id: None,
        code: Some(code.to_owned()),
    };
    respond_ignoring_transport(
        respond,
        serde_json::to_value(response).map_err(|_| rpc_internal("response_encode_failed")),
    );
}

fn respond_async_completion_retryable(respond: ResponseSender, code: &'static str) {
    let response = AcpAsyncCompletionResponse {
        status: AcpAsyncCompletionAckStatus::Retryable,
        turn_id: None,
        code: Some(code.to_owned()),
    };
    respond_ignoring_transport(
        respond,
        serde_json::to_value(response).map_err(|_| rpc_internal("response_encode_failed")),
    );
}

fn respond_prompt_admission(respond: ResponseSender, request_id: &str, accepted: bool) -> bool {
    let response = CommandEvePromptAdmissionResponse {
        version: COMMAND_EVE_PROMPT_ADMISSION_VERSION.to_owned(),
        request_id: request_id.to_owned(),
        status: if accepted {
            CommandEvePromptAdmissionStatus::Accepted
        } else {
            CommandEvePromptAdmissionStatus::Rejected
        },
    };
    let Ok(value) = serde_json::to_value(response) else {
        respond_ignoring_transport(respond, Err(rpc_internal("response_encoding_failed")));
        return false;
    };
    let queued = respond(Ok(value)).is_ok();
    info!(
        method = COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD,
        accepted, queued, "ACP prompt admission decision queued"
    );
    queued
}

fn rpc_internal(reason: &'static str) -> JsonRpcError {
    JsonRpcError::internal_error().data(serde_json::json!({ "reason": reason }))
}

fn respond_ignoring_transport(respond: ResponseSender, result: Result<serde_json::Value, JsonRpcError>) {
    if respond(result).is_err() {
        warn!("Failed to deliver bounded ACP extension response");
    }
}

fn local_binding_error() -> AcpError {
    AcpError::AgentInternal {
        message: "Client extension session binding unavailable".to_owned(),
        code: -32603,
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt_admission::{
        command_eve_prompt_admission_for_turn, forget_command_eve_prompt_admission,
        register_command_eve_prompt_admission,
    };
    use agent_client_protocol::JsonRpcMessage;
    use aionui_api_types::AcpReadPreviewResultKind;
    use tokio::sync::oneshot;

    fn request(request_id: &str, session_id: &str) -> AcpReadPreviewRequestEventData {
        AcpReadPreviewRequestEventData {
            version: COMMAND_EVE_READ_PREVIEW_VERSION.to_owned(),
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            start: Some(4),
            count: Some(12),
        }
    }

    fn response(request_id: &str, session_id: &str) -> AcpReadPreviewResponseRequest {
        AcpReadPreviewResponseRequest {
            version: COMMAND_EVE_READ_PREVIEW_VERSION.to_owned(),
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            result: Some(AcpReadPreviewResult {
                kind: AcpReadPreviewResultKind::Url,
                url: "https://example.test/preview?token=secret#frag".to_owned(),
                title: "Preview".to_owned(),
                text: "hello world".to_owned(),
                start: 4,
                end: 15,
                total_chars: 50,
                note: None,
                path: None,
            }),
        }
    }

    fn dispatch(
        router: &AcpClientExtensionRouter,
        method: &str,
        request: serde_json::Value,
    ) -> oneshot::Receiver<Result<serde_json::Value, JsonRpcError>> {
        let (tx, rx) = oneshot::channel();
        let sender: ResponseSender =
            Box::new(move |result| tx.send(result).map_err(|_| JsonRpcError::internal_error()));
        router.handle_raw_request(method, &request.to_string(), sender);
        rx
    }

    fn dispatch_prompt_raw(
        router: &AcpClientExtensionRouter,
        raw: &str,
    ) -> oneshot::Receiver<Result<serde_json::Value, JsonRpcError>> {
        let (tx, rx) = oneshot::channel();
        let sender: ResponseSender =
            Box::new(move |result| tx.send(result).map_err(|_| JsonRpcError::internal_error()));
        router.handle_prompt_admission_request(raw, sender);
        rx
    }

    fn dispatch_prompt(
        router: &AcpClientExtensionRouter,
        wire: &CommandEvePromptAdmissionWireRequest,
    ) -> oneshot::Receiver<Result<serde_json::Value, JsonRpcError>> {
        dispatch_prompt_raw(router, &serde_json::to_string(wire).unwrap())
    }

    fn failing_prompt_delivery(router: &AcpClientExtensionRouter, wire: &CommandEvePromptAdmissionWireRequest) {
        let sender: ResponseSender = Box::new(|_| Err(JsonRpcError::internal_error()));
        router.handle_prompt_admission_request(&serde_json::to_string(wire).unwrap(), sender);
    }

    fn admission_wire(
        turn_id: &str,
        session_id: &str,
        phase: CommandEvePromptAdmissionPhase,
    ) -> CommandEvePromptAdmissionWireRequest {
        let request = command_eve_prompt_admission_for_turn(turn_id).expect("registered admission");
        CommandEvePromptAdmissionWireRequest {
            version: request.version,
            request_id: request.request_id,
            turn_id: request.turn_id,
            receipt_sha256: request.receipt_sha256,
            session_id: session_id.to_owned(),
            phase,
        }
    }

    fn accepted_prompt_response(value: serde_json::Value) -> bool {
        serde_json::from_value::<CommandEvePromptAdmissionResponse>(value)
            .is_ok_and(|response| response.status == CommandEvePromptAdmissionStatus::Accepted)
    }

    fn enable(router: &AcpClientExtensionRouter) {
        router.enable_read_preview().unwrap();
    }

    fn completion_request(session_id: &str) -> AcpAsyncCompletionRequest {
        AcpAsyncCompletionRequest {
            version: COMMAND_EVE_ASYNC_COMPLETION_VERSION.to_owned(),
            completion_id: "completion-1".to_owned(),
            session_id: session_id.to_owned(),
            content: "Continue the conversation".to_owned(),
        }
    }

    fn completion_route(sender: crate::CommandEveAsyncCompletionSender) -> CommandEveAsyncCompletionRoute {
        CommandEveAsyncCompletionRoute {
            conversation_id: "conversation-1".to_owned(),
            sender,
            project_build_options: None,
            session_binding: AcpSessionBinding::default(),
        }
    }

    #[test]
    fn sdk_strips_private_wire_prefix_before_router_matching() {
        let parsed = AgentRequest::parse_message(
            COMMAND_EVE_ASYNC_COMPLETION_WIRE_METHOD,
            &serde_json::to_value(completion_request("session-1")).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            parsed,
            AgentRequest::ExtMethodRequest(request)
                if request.method.as_ref() == COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD
        ));
    }

    #[tokio::test]
    async fn async_completion_is_canonically_bound_and_acknowledged() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let response_rx = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let dispatched = completion_rx.recv().await.unwrap();
        assert_eq!(dispatched.conversation_id, "conversation-1");
        assert_eq!(dispatched.request.session_id, "session-1");
        assert!(matches!(&dispatched.kind, CommandEveAsyncCompletionDispatchKind::Apply));
        assert!(dispatched.project_build_options.is_none());
        dispatched
            .reply
            .send(CommandEveAsyncCompletionResult::Completed {
                turn_id: "turn-1".to_owned(),
            })
            .unwrap();
        let value = response_rx.await.unwrap().unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(value).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Accepted);
        assert_eq!(response.turn_id.as_deref(), Some("turn-1"));
    }

    #[tokio::test]
    async fn async_completion_is_retryable_until_session_binding_is_positive() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));

        for expected_phase in ["before enable", "before bind"] {
            let response = dispatch(
                &router,
                COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
                serde_json::to_value(completion_request("session-1")).unwrap(),
            );
            let response: AcpAsyncCompletionResponse =
                serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
            assert_eq!(
                response.status,
                AcpAsyncCompletionAckStatus::Retryable,
                "{expected_phase}"
            );
            assert_eq!(response.code.as_deref(), Some("session_not_bound"));
            assert!(completion_rx.try_recv().is_err(), "pre-bind wake must not dispatch");

            if expected_phase == "before enable" {
                router.enable_async_completion().unwrap();
            }
        }

        router.bind_session("session-1").await.unwrap();
        let mismatched = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-2")).unwrap(),
        );
        let rejected = completion_rx.recv().await.unwrap();
        assert!(matches!(
            &rejected.kind,
            CommandEveAsyncCompletionDispatchKind::RejectSessionMismatch { bound_session_id }
                if bound_session_id == "session-1"
        ));
        rejected
            .reply
            .send(CommandEveAsyncCompletionResult::Rejected {
                code: "session_mismatch".to_owned(),
            })
            .unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(mismatched.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Rejected);
        assert_eq!(response.code.as_deref(), Some("session_mismatch"));
    }

    #[tokio::test]
    async fn async_completion_rejects_session_mismatch_and_maps_busy_retryably() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let mismatched = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-2")).unwrap(),
        );
        let rejected = completion_rx.recv().await.unwrap();
        assert!(matches!(
            &rejected.kind,
            CommandEveAsyncCompletionDispatchKind::RejectSessionMismatch { bound_session_id }
                if bound_session_id == "session-1"
        ));
        rejected
            .reply
            .send(CommandEveAsyncCompletionResult::Rejected {
                code: "session_mismatch".to_owned(),
            })
            .unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(mismatched.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Rejected);
        assert_eq!(response.code.as_deref(), Some("session_mismatch"));

        let busy = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        completion_rx
            .recv()
            .await
            .unwrap()
            .reply
            .send(CommandEveAsyncCompletionResult::RetryableBusy {
                code: "conversation_busy".to_owned(),
            })
            .unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(busy.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("conversation_busy"));
    }

    #[tokio::test]
    async fn async_completion_concurrency_saturation_is_retryable_before_dispatch() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx)
            .with_async_completion(completion_route(completion_tx))
            .with_async_completion_limits(Duration::from_secs(1), 1);
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let first = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let first_dispatch = completion_rx.recv().await.unwrap();

        let mut second_request = completion_request("session-1");
        second_request.completion_id = "completion-2".to_owned();
        let second = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(second_request).unwrap(),
        );
        let response: AcpAsyncCompletionResponse = serde_json::from_value(second.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("consumer_saturated"));
        assert!(completion_rx.try_recv().is_err(), "saturated request must not dispatch");

        first_dispatch
            .reply
            .send(CommandEveAsyncCompletionResult::Completed {
                turn_id: "turn-1".to_owned(),
            })
            .unwrap();
        assert!(first.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn async_completion_reply_timeout_is_retryable_never_terminal_unknown() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
        let router = AcpClientExtensionRouter::new(event_tx)
            .with_async_completion(completion_route(completion_tx))
            .with_async_completion_limits(Duration::from_millis(20), 1);
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let in_flight = completion_rx.recv().await.unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("consumer_reply_timeout"));
        drop(in_flight);
    }

    #[tokio::test]
    async fn async_completion_dropped_consumer_reply_is_retryable_never_terminal_unknown() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
        let router = AcpClientExtensionRouter::new(event_tx)
            .with_async_completion(completion_route(completion_tx))
            .with_async_completion_limits(Duration::from_secs(5), 1);
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let in_flight = completion_rx.recv().await.unwrap();
        // Dropping the dispatch drops the reply oneshot: the consumer never
        // answered, so the outcome is unknown to the router but must stay
        // retryable — only the receipt ledger may record a terminal unknown.
        drop(in_flight);
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("consumer_reply_dropped"));
    }

    #[tokio::test]
    async fn async_completion_closed_consumer_channel_is_retryable() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, completion_rx) = tokio::sync::mpsc::channel(1);
        drop(completion_rx);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("consumer_unavailable"));
    }

    #[tokio::test]
    async fn binding_lease_generation_tracks_the_session_lifecycle() {
        let (event_tx, _) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        assert!(router.session_binding.lease().is_none());

        router.bind_session("session-1").await.unwrap();
        let first = router.session_binding.lease().unwrap();
        assert_eq!(first.session_id(), "session-1");
        assert!(router.session_binding.validate_lease(&first));

        // Same-session bind without an intervening begin-binding transition
        // is idempotent and keeps the generation.
        router.bind_session("session-1").await.unwrap();
        assert_eq!(router.session_binding.lease().unwrap(), first);

        // The session request interval invalidates the live binding and
        // every lease minted so far.
        router.begin_session_binding().await;
        assert!(router.session_binding.lease().is_none());
        assert!(!router.session_binding.validate_lease(&first));

        // Binding the same session id after the interval is a real bind with
        // a new, strictly greater generation.
        router.bind_session("session-1").await.unwrap();
        let second = router.session_binding.lease().unwrap();
        assert_eq!(second.session_id(), "session-1");
        assert!(second.generation() > first.generation());
        assert!(router.session_binding.validate_lease(&second));
        assert!(!router.session_binding.validate_lease(&first));

        // Rebind to a different session advances again and stales the lease.
        router.bind_session("session-2").await.unwrap();
        let third = router.session_binding.lease().unwrap();
        assert!(third.generation() > second.generation());
        assert!(!router.session_binding.validate_lease(&second));

        router.begin_session_close("session-2").await.unwrap();
        assert!(router.session_binding.lease().is_none());
        assert!(!router.session_binding.validate_lease(&third));

        router.bind_session("session-3").await.unwrap();
        let fourth = router.session_binding.lease().unwrap();
        router.cancel_all("test_cancel");
        assert!(router.session_binding.lease().is_none());
        assert!(!router.session_binding.validate_lease(&fourth));
    }

    #[tokio::test]
    async fn async_completion_stays_retryable_session_not_bound_during_the_binding_interval() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        // Between begin-binding (session/new|load|resume request start) and
        // the successful response, the route is unbound: completions remain
        // retryable and are never dispatched to the consumer.
        router.begin_session_binding().await;
        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("session_not_bound"));
        assert!(completion_rx.try_recv().is_err(), "unbound interval must not dispatch");

        // After the successful bind, the same completion routes again.
        router.bind_session("session-1").await.unwrap();
        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let in_flight = completion_rx.recv().await.unwrap();
        assert_eq!(in_flight.kind, CommandEveAsyncCompletionDispatchKind::Apply);
        in_flight
            .reply
            .send(CommandEveAsyncCompletionResult::Completed {
                turn_id: "turn-after-bind".to_owned(),
            })
            .unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Accepted);
    }

    #[tokio::test]
    async fn close_fence_blocks_a_deferred_completion_before_it_can_admit_a_turn() {
        let (event_tx, _) = broadcast::channel(4);
        let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx).with_async_completion(completion_route(completion_tx));
        router.enable_async_completion().unwrap();
        router.bind_session("session-1").await.unwrap();

        let response = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let deferred = completion_rx.recv().await.expect("routed completion");
        assert_eq!(deferred.kind, CommandEveAsyncCompletionDispatchKind::Apply);

        // `close_session` invokes this fence before its RPC. The dispatched
        // completion has not reached the synchronous turn insertion yet, so
        // it must be unable to cross the close boundary afterwards.
        router.begin_session_close("session-1").await.unwrap();
        assert!(router.session_binding.lease().is_none());
        assert!(deferred.turn_gate.try_admit_turn().is_none());

        deferred
            .reply
            .send(CommandEveAsyncCompletionResult::RetryableBusy {
                code: "session_not_bound".to_owned(),
            })
            .unwrap();
        let response: AcpAsyncCompletionResponse = serde_json::from_value(response.await.unwrap().unwrap()).unwrap();
        assert_eq!(response.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(response.code.as_deref(), Some("session_not_bound"));

        let post_close = dispatch(
            &router,
            COMMAND_EVE_ASYNC_COMPLETION_EXT_METHOD,
            serde_json::to_value(completion_request("session-1")).unwrap(),
        );
        let post_close: AcpAsyncCompletionResponse =
            serde_json::from_value(post_close.await.unwrap().unwrap()).unwrap();
        assert_eq!(post_close.status, AcpAsyncCompletionAckStatus::Retryable);
        assert_eq!(post_close.code.as_deref(), Some("session_not_bound"));
        assert!(completion_rx.try_recv().is_err(), "close must prevent another dispatch");
    }

    #[tokio::test]
    async fn prompt_admission_router_rejects_bad_binding_wire_and_payload_without_consuming_the_ticket() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-router").await.unwrap();
        let ticket = register_command_eve_prompt_admission("turn-router-wire", &"a".repeat(64)).unwrap();

        let wrong_session = admission_wire(
            "turn-router-wire",
            "session-other",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(!accepted_prompt_response(
            dispatch_prompt(&router, &wrong_session).await.unwrap().unwrap()
        ));
        assert!(command_eve_prompt_admission_for_turn("turn-router-wire").is_some());

        let oversized = "x".repeat(MAX_PROMPT_ADMISSION_PAYLOAD_BYTES + 1);
        assert_eq!(
            i32::from(
                dispatch_prompt_raw(&router, &oversized)
                    .await
                    .unwrap()
                    .unwrap_err()
                    .code
            ),
            -32603
        );
        for invalid in [
            "{".to_owned(),
            serde_json::json!({
                "version": COMMAND_EVE_PROMPT_ADMISSION_VERSION,
                "request_id": "request",
                "turn_id": "turn",
                "receipt_sha256": "a".repeat(64),
                "session_id": "session-router",
                "phase": "accept",
                "unexpected": true,
            })
            .to_string(),
            serde_json::json!({
                "version": COMMAND_EVE_PROMPT_ADMISSION_VERSION,
                "request_id": "request",
                "turn_id": "turn",
                "receipt_sha256": "a".repeat(64),
                "session_id": "session-router",
                "phase": "unknown",
            })
            .to_string(),
        ] {
            assert_eq!(
                i32::from(dispatch_prompt_raw(&router, &invalid).await.unwrap().unwrap_err().code),
                -32603
            );
        }

        let accepted = admission_wire(
            "turn-router-wire",
            "session-router",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(accepted_prompt_response(
            dispatch_prompt(&router, &accepted).await.unwrap().unwrap()
        ));
        forget_command_eve_prompt_admission("turn-router-wire");
        drop(ticket);
    }

    #[tokio::test]
    async fn prompt_admission_router_requires_peer_ack_after_finalize_before_acceptance() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-router-race").await.unwrap();
        let ticket = register_command_eve_prompt_admission("turn-router-race", &"b".repeat(64)).unwrap();

        let accept = admission_wire(
            "turn-router-race",
            "session-router-race",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(accepted_prompt_response(
            dispatch_prompt(&router, &accept).await.unwrap().unwrap()
        ));

        let commit = admission_wire(
            "turn-router-race",
            "session-router-race",
            CommandEvePromptAdmissionPhase::Commit,
        );
        let commit_response = dispatch_prompt(&router, &commit);
        let claim = ticket.wait().await.unwrap();
        let finalize_ticket = claim.accept().unwrap();
        assert!(accepted_prompt_response(commit_response.await.unwrap().unwrap()));

        let finalize = admission_wire(
            "turn-router-race",
            "session-router-race",
            CommandEvePromptAdmissionPhase::Finalize,
        );
        let finalize_response = dispatch_prompt(&router, &finalize);
        let finalize_claim = finalize_ticket.wait().await.unwrap();
        let peer_ack_ticket = finalize_claim.accept().unwrap();
        assert!(accepted_prompt_response(finalize_response.await.unwrap().unwrap()));
        assert!(matches!(
            claim_command_eve_prompt_admission(
                &command_eve_prompt_admission_for_turn("turn-router-race").unwrap(),
                "session-router-race",
            ),
            Err("request_in_progress")
        ));

        let ack = admission_wire(
            "turn-router-race",
            "session-router-race",
            CommandEvePromptAdmissionPhase::Ack,
        );
        let ack_response = dispatch_prompt(&router, &ack);
        let peer_ack_claim = peer_ack_ticket.wait().await.unwrap();
        peer_ack_claim.accept().unwrap();
        assert!(accepted_prompt_response(ack_response.await.unwrap().unwrap()));
        assert!(matches!(
            claim_command_eve_prompt_admission(
                &command_eve_prompt_admission_for_turn("turn-router-race").unwrap(),
                "session-router-race",
            ),
            Ok(CommandEvePromptAdmissionClaimResult::AlreadyAccepted)
        ));
        forget_command_eve_prompt_admission("turn-router-race");
    }

    #[tokio::test]
    async fn prompt_admission_router_rolls_back_accept_commit_and_finalize_delivery_failures() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-router-delivery").await.unwrap();

        let accept_ticket = register_command_eve_prompt_admission("turn-router-accept-fail", &"c".repeat(64)).unwrap();
        let accept = admission_wire(
            "turn-router-accept-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Accept,
        );
        failing_prompt_delivery(&router, &accept);
        assert!(accept_ticket.wait().await.is_err());
        assert!(command_eve_prompt_admission_for_turn("turn-router-accept-fail").is_none());

        let commit_ticket = register_command_eve_prompt_admission("turn-router-commit-fail", &"d".repeat(64)).unwrap();
        let accept = admission_wire(
            "turn-router-commit-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(accepted_prompt_response(
            dispatch_prompt(&router, &accept).await.unwrap().unwrap()
        ));
        let commit = admission_wire(
            "turn-router-commit-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Commit,
        );
        failing_prompt_delivery(&router, &commit);
        let claim = commit_ticket.wait().await.unwrap();
        let finalize_ticket = claim.accept().unwrap();
        assert!(finalize_ticket.wait().await.is_err());
        assert!(command_eve_prompt_admission_for_turn("turn-router-commit-fail").is_none());

        let finalize_ticket_source =
            register_command_eve_prompt_admission("turn-router-finalize-fail", &"e".repeat(64)).unwrap();
        let accept = admission_wire(
            "turn-router-finalize-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(accepted_prompt_response(
            dispatch_prompt(&router, &accept).await.unwrap().unwrap()
        ));
        let commit = admission_wire(
            "turn-router-finalize-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Commit,
        );
        let commit_response = dispatch_prompt(&router, &commit);
        let claim = finalize_ticket_source.wait().await.unwrap();
        let finalize_ticket = claim.accept().unwrap();
        assert!(accepted_prompt_response(commit_response.await.unwrap().unwrap()));
        let finalize = admission_wire(
            "turn-router-finalize-fail",
            "session-router-delivery",
            CommandEvePromptAdmissionPhase::Finalize,
        );
        failing_prompt_delivery(&router, &finalize);
        let claim = finalize_ticket.wait().await.unwrap();
        let peer_ack_ticket = claim.accept().unwrap();
        let error = match peer_ack_ticket.wait().await {
            Err(error) => error,
            Ok(_) => panic!("local finalize enqueue cannot substitute for a peer acknowledgement"),
        };
        assert!(error.to_string().contains("PEER_ACK_UNAVAILABLE"));
        assert!(command_eve_prompt_admission_for_turn("turn-router-finalize-fail").is_none());
    }

    #[tokio::test]
    async fn prompt_admission_router_connection_drop_before_peer_ack_is_typed_unavailable() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-router-drop").await.unwrap();
        let ticket = register_command_eve_prompt_admission("turn-router-drop", &"f".repeat(64)).unwrap();

        let accept = admission_wire(
            "turn-router-drop",
            "session-router-drop",
            CommandEvePromptAdmissionPhase::Accept,
        );
        assert!(accepted_prompt_response(
            dispatch_prompt(&router, &accept).await.unwrap().unwrap()
        ));
        let commit = admission_wire(
            "turn-router-drop",
            "session-router-drop",
            CommandEvePromptAdmissionPhase::Commit,
        );
        let commit_response = dispatch_prompt(&router, &commit);
        let claim = ticket.wait().await.unwrap();
        let finalize_ticket = claim.accept().unwrap();
        assert!(accepted_prompt_response(commit_response.await.unwrap().unwrap()));
        let finalize = admission_wire(
            "turn-router-drop",
            "session-router-drop",
            CommandEvePromptAdmissionPhase::Finalize,
        );
        let finalize_response = dispatch_prompt(&router, &finalize);
        let finalize_claim = finalize_ticket.wait().await.unwrap();
        let peer_ack_ticket = finalize_claim.accept().unwrap();
        assert!(accepted_prompt_response(finalize_response.await.unwrap().unwrap()));

        router.cancel_all("protocol_dropped");
        let error = match peer_ack_ticket.wait().await {
            Err(error) => error,
            Ok(_) => panic!("connection drop must reject the pending peer acknowledgement"),
        };
        assert!(error.to_string().contains("PEER_ACK_UNAVAILABLE"));
        assert!(command_eve_prompt_admission_for_turn("turn-router-drop").is_none());
    }

    #[tokio::test]
    async fn accepts_only_the_exact_allowlisted_method_and_emits_typed_event() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        let disabled = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-disabled", "session-1")).unwrap(),
        );
        assert_eq!(i32::from(disabled.await.unwrap().unwrap_err().code), -32601);
        enable(&router);
        router.bind_session("session-1").await.unwrap();

        let req = request("request-1", "session-1");
        let response_rx = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(&req).unwrap(),
        );
        let event = event_rx.recv().await.unwrap();
        assert!(matches!(
            event,
            AgentStreamEvent::AcpReadPreviewRequest(data) if data == req
        ));
        assert_eq!(router.pending_count(), 1);
        router.respond_read_preview(response("request-1", "session-1")).unwrap();
        assert!(response_rx.await.unwrap().is_ok());

        let unknown = dispatch(&router, "command_eve/other", serde_json::json!({}));
        let error = unknown.await.unwrap().unwrap_err();
        assert_eq!(i32::from(error.code), -32601);
    }

    #[tokio::test]
    async fn rejects_unknown_fields_versions_sessions_and_caps_without_pending_state() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();

        for invalid in [
            serde_json::json!({
                "version": COMMAND_EVE_READ_PREVIEW_VERSION,
                "request_id": "request-unknown-field",
                "session_id": "session-1",
                "surprise": true
            }),
            serde_json::json!({
                "version": "command-eve-read-preview/v2",
                "request_id": "request-version",
                "session_id": "session-1"
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_PREVIEW_VERSION,
                "request_id": "request-session",
                "session_id": "session-2"
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_PREVIEW_VERSION,
                "request_id": "request-start",
                "session_id": "session-1",
                "start": MAX_START + 1
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_PREVIEW_VERSION,
                "request_id": "request-count",
                "session_id": "session-1",
                "count": MAX_COUNT + 1
            }),
        ] {
            let error = dispatch(&router, COMMAND_EVE_READ_PREVIEW_EXT_METHOD, invalid)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(i32::from(error.code), -32602);
        }
        assert_eq!(router.pending_count(), 0);
    }

    #[tokio::test]
    async fn response_is_exactly_once_and_mismatch_does_not_consume_pending_request() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let rx = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-1", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();

        let mut mismatched = response("request-1", "session-2");
        assert!(router.respond_read_preview(mismatched.clone()).is_err());
        assert_eq!(router.pending_count(), 1);
        mismatched.session_id = "session-1".to_owned();
        assert!(router.respond_read_preview(mismatched.clone()).unwrap().accepted);
        assert!(rx.await.unwrap().is_ok());
        assert!(router.respond_read_preview(mismatched).is_err());
        assert_eq!(router.pending_count(), 0);
    }

    #[tokio::test]
    async fn duplicate_request_id_rejects_only_the_duplicate() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let value = serde_json::to_value(request("request-1", "session-1")).unwrap();
        let first = dispatch(&router, COMMAND_EVE_READ_PREVIEW_EXT_METHOD, value.clone());
        let _ = event_rx.recv().await.unwrap();
        let duplicate = dispatch(&router, COMMAND_EVE_READ_PREVIEW_EXT_METHOD, value);
        assert_eq!(i32::from(duplicate.await.unwrap().unwrap_err().code), -32602);
        assert_eq!(router.pending_count(), 1);
        router.respond_read_preview(response("request-1", "session-1")).unwrap();
        assert!(first.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn rebind_close_and_cancel_fail_pending_requests_closed() {
        let (event_tx, mut event_rx) = broadcast::channel(8);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let rebound = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-rebind", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.bind_session("session-2").await.unwrap();
        assert_eq!(router.bound_session_id().as_deref(), Some("session-2"));
        assert!(rebound.await.unwrap().is_err());

        let closed = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-close", "session-2")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.begin_session_close("session-2").await.unwrap();
        assert_eq!(router.bound_session_id(), None);
        assert!(closed.await.unwrap().is_err());

        router.bind_session("session-3").await.unwrap();
        let cancelled = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-cancel", "session-3")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.cancel_all("test_shutdown");
        assert!(cancelled.await.unwrap().is_err());
        assert_eq!(router.pending_count(), 0);
    }

    #[tokio::test]
    async fn timeout_consumes_request_once() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::with_timeout(event_tx, Duration::from_millis(5));
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let timed_out = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-timeout", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), timed_out)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(i32::from(error.code), -32603);
        assert_eq!(router.pending_count(), 0);
        assert!(
            router
                .respond_read_preview(response("request-timeout", "session-1"))
                .is_err()
        );
    }

    #[tokio::test]
    async fn response_redacts_secret_material_and_url_queries_before_acp_delivery() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let mut secret_request = request("request-secret", "session-1");
        secret_request.count = Some(200);
        let rx = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(secret_request).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();

        let mut value = response("request-secret", "session-1");
        let result = value.result.as_mut().unwrap();
        result.text = "Authorization: Bearer abcdefghijkl\nhttps://example.test/?api_key=hidden".to_owned();
        result.end = result.start + result.text.chars().count() as u32;
        result.total_chars = result.end;
        router.respond_read_preview(value).unwrap();

        let ext = rx.await.unwrap().unwrap();
        let raw = ext.to_string();
        assert!(!raw.contains("abcdefghijkl"));
        assert!(!raw.contains("api_key=hidden"));
        assert!(!raw.contains("token=secret"));
        assert!(raw.contains("[redacted]"));
    }

    #[tokio::test]
    async fn unicode_text_cap_counts_characters_while_json_cap_counts_bytes() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let mut unicode_request = request("request-unicode", "session-1");
        unicode_request.count = Some(MAX_COUNT);
        let rx = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(unicode_request).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();

        let mut value = response("request-unicode", "session-1");
        let result = value.result.as_mut().unwrap();
        result.text = "é".repeat(13_000);
        result.end = result.start + 13_000;
        result.total_chars = result.end;
        assert!(result.text.len() > 24_000, "fixture must exceed the old byte cap");
        router.respond_read_preview(value).unwrap();
        assert!(rx.await.unwrap().is_ok());
    }
}
