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
    AcpReadPreviewRequestEventData, AcpReadPreviewResponse, AcpReadPreviewResponseRequest, AcpReadPreviewResult,
    COMMAND_EVE_READ_PREVIEW_VERSION,
};
use regex::Regex;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::error::AgentError;
use crate::prompt_admission::{
    COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD, COMMAND_EVE_PROMPT_ADMISSION_VERSION,
    CommandEvePromptAdmissionClaimResult, CommandEvePromptAdmissionDecision,
    CommandEvePromptAdmissionFinalizeClaimResult, CommandEvePromptAdmissionPhase, CommandEvePromptAdmissionResponse,
    CommandEvePromptAdmissionStatus, CommandEvePromptAdmissionWireRequest, admit_command_eve_prompt_admission,
    claim_command_eve_prompt_admission, complete_command_eve_prompt_admission,
    complete_command_eve_prompt_admission_commit, finalize_command_eve_prompt_admission,
};
use crate::protocol::error::AcpError;
use crate::protocol::events::AgentStreamEvent;

use read_terminal::{COMMAND_EVE_READ_TERMINAL_EXT_METHOD, PendingReadTerminal, cancel_pending_terminal};

pub(crate) const COMMAND_EVE_READ_PREVIEW_EXT_METHOD: &str = "command_eve/read_preview";
pub(crate) const COMMAND_EVE_READ_PREVIEW_WIRE_METHOD: &str = "_command_eve/read_preview";

const CLIENT_EXTENSION_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_REQUEST_PAYLOAD_BYTES: usize = 4 * 1024;
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
    bound_session_id: Option<String>,
    pending: HashMap<String, PendingReadPreview>,
    pending_terminal: HashMap<String, PendingReadTerminal>,
}

#[derive(Clone)]
pub(crate) struct AcpClientExtensionRouter {
    event_tx: broadcast::Sender<AgentStreamEvent>,
    state: Arc<Mutex<ExtensionState>>,
    timeout: Duration,
}

impl AcpClientExtensionRouter {
    pub(crate) fn new(event_tx: broadcast::Sender<AgentStreamEvent>) -> Self {
        Self::with_timeout(event_tx, CLIENT_EXTENSION_TIMEOUT)
    }

    fn with_timeout(event_tx: broadcast::Sender<AgentStreamEvent>, timeout: Duration) -> Self {
        Self {
            event_tx,
            state: Arc::new(Mutex::new(ExtensionState::default())),
            timeout,
        }
    }

    /// Enable the single allowlisted extension for a verified Hermes backend.
    pub(crate) fn enable_read_preview(&self) -> Result<(), AcpError> {
        let mut state = self.state.lock().map_err(|_| local_binding_error())?;
        state.read_preview_enabled = true;
        Ok(())
    }

    /// Bind extension requests to the canonical session acknowledged by ACP.
    /// Rebinding cancels every request from the previous session.
    pub(crate) fn bind_session(&self, session_id: &str) -> Result<(), AcpError> {
        validate_identifier(session_id).map_err(|_| local_binding_error())?;
        let (cancelled, cancelled_terminal) = {
            let mut state = self.state.lock().map_err(|_| local_binding_error())?;
            if state.bound_session_id.as_deref() == Some(session_id) {
                return Ok(());
            }
            state.bound_session_id = Some(session_id.to_owned());
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

    /// Unbind a successfully closed session and cancel its outstanding reads.
    pub(crate) fn unbind_session(&self, session_id: &str) {
        let (cancelled, cancelled_terminal) = {
            let Ok(mut state) = self.state.lock() else {
                warn!("ACP client extension state unavailable while closing session");
                return;
            };
            if state.bound_session_id.as_deref() != Some(session_id) {
                return;
            }
            state.bound_session_id = None;
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
    }

    /// Cancel all pending requests before transport shutdown/disconnect.
    pub(crate) fn cancel_all(&self, reason: &'static str) {
        let (cancelled, cancelled_terminal) = {
            let Ok(mut state) = self.state.lock() else {
                warn!("ACP client extension state unavailable during cancellation");
                return;
            };
            state.read_preview_enabled = false;
            state.read_terminal_enabled = false;
            state.bound_session_id = None;
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
            if state.bound_session_id.as_deref() != Some(response.session_id.as_str())
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
            .state
            .lock()
            .is_ok_and(|state| state.bound_session_id.as_deref() == Some(wire.session_id.as_str()));
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
                            let transport_ok = respond_prompt_admission(respond, &request_id, accepted);
                            complete_command_eve_prompt_admission(&request_id, &session_id, accepted && transport_ok);
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
            if state.bound_session_id.as_deref() != Some(request.session_id.as_str()) {
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
        self.state.lock().ok().and_then(|state| state.bound_session_id.clone())
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
    let delivered = respond(Ok(value)).is_ok();
    info!(
        method = COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD,
        accepted, delivered, "ACP prompt admission decision delivered"
    );
    delivered
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

    fn enable(router: &AcpClientExtensionRouter) {
        router.enable_read_preview().unwrap();
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
        router.bind_session("session-1").unwrap();

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
        router.bind_session("session-1").unwrap();

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
        router.bind_session("session-1").unwrap();
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
        router.bind_session("session-1").unwrap();
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
        router.bind_session("session-1").unwrap();
        let rebound = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-rebind", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.bind_session("session-2").unwrap();
        assert_eq!(router.bound_session_id().as_deref(), Some("session-2"));
        assert!(rebound.await.unwrap().is_err());

        let closed = dispatch(
            &router,
            COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(request("request-close", "session-2")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.unbind_session("session-2");
        assert_eq!(router.bound_session_id(), None);
        assert!(closed.await.unwrap().is_err());

        router.bind_session("session-3").unwrap();
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
        router.bind_session("session-1").unwrap();
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
        router.bind_session("session-1").unwrap();
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
        router.bind_session("session-1").unwrap();
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
