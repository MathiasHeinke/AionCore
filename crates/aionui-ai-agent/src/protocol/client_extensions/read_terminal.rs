//! Strict `read_terminal` half of the bounded Command EVE client extension seam.

use std::sync::Arc;

use agent_client_protocol::Error as JsonRpcError;
use aionui_api_types::{
    AcpReadTerminalRequestEventData, AcpReadTerminalResponse, AcpReadTerminalResponseRequest, AcpReadTerminalResult,
    COMMAND_EVE_READ_TERMINAL_VERSION,
};
use tracing::{info, warn};

use super::{
    AcpClientExtensionRouter, AgentError, AgentStreamEvent, ExtensionState, MAX_COUNT, MAX_REQUEST_PAYLOAD_BYTES,
    MAX_RESPONSE_PAYLOAD_BYTES, MAX_START, MAX_TEXT_CHARS, ResponseSender, redact_secret_text,
    respond_ignoring_transport, rpc_internal, validate_identifier,
};
use crate::protocol::error::AcpError;

pub(crate) const COMMAND_EVE_READ_TERMINAL_EXT_METHOD: &str = "command_eve/read_terminal";
pub(crate) const COMMAND_EVE_READ_TERMINAL_WIRE_METHOD: &str = "_command_eve/read_terminal";

const MAX_TOTAL_LINES: u32 = 10_000_000;

pub(super) struct PendingReadTerminal {
    session_id: String,
    start: Option<u32>,
    count: Option<u32>,
    respond: ResponseSender,
}

impl AcpClientExtensionRouter {
    /// Enable the terminal extension only for a verified Hermes backend.
    pub(crate) fn enable_read_terminal(&self) -> Result<(), AcpError> {
        let mut state = self.state.lock().map_err(|_| super::local_binding_error())?;
        state.read_terminal_enabled = true;
        Ok(())
    }

    /// Correlate and consume a renderer terminal response exactly once.
    pub(crate) fn respond_read_terminal(
        &self,
        response: AcpReadTerminalResponseRequest,
    ) -> Result<AcpReadTerminalResponse, AgentError> {
        validate_terminal_response_envelope(&response)?;

        let mut result = response.result;
        let response_for_wire = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| AgentError::internal("ACP read_terminal state unavailable"))?;
            let pending = state.pending_terminal.get(&response.request_id).ok_or_else(|| {
                AgentError::conflict("ACP read_terminal request is unknown, expired, or already answered")
            })?;
            if self.session_binding.bound_session_id().as_deref() != Some(response.session_id.as_str())
                || pending.session_id != response.session_id
            {
                return Err(AgentError::conflict("ACP read_terminal session binding mismatch"));
            }
            if let Some(value) = result.as_ref() {
                validate_terminal_result(value, pending)?;
            }
            if let Some(value) = result.as_mut() {
                value.text = redact_secret_text(&value.text);
            }

            let wire = AcpReadTerminalResponseRequest {
                version: response.version,
                request_id: response.request_id.clone(),
                session_id: response.session_id.clone(),
                result,
            };
            let wire_value = serde_json::to_value(&wire)
                .map_err(|_| AgentError::internal("Failed to encode ACP read_terminal response"))?;
            let payload_bytes = serde_json::to_vec(&wire_value)
                .map_err(|_| AgentError::internal("Failed to encode ACP read_terminal response"))?;
            if payload_bytes.len() > MAX_RESPONSE_PAYLOAD_BYTES {
                return Err(AgentError::bad_request(
                    "ACP read_terminal response exceeds the payload cap",
                ));
            }

            let pending = state
                .pending_terminal
                .remove(&response.request_id)
                .expect("pending terminal request was checked while holding the same lock");
            (wire_value, pending.respond)
        };

        let (wire_value, respond) = response_for_wire;
        respond(Ok(wire_value)).map_err(|_| AgentError::bad_gateway("ACP read_terminal response transport failed"))?;
        info!(
            method = COMMAND_EVE_READ_TERMINAL_WIRE_METHOD,
            request_id_bytes = response.request_id.len(),
            session_id_bytes = response.session_id.len(),
            "ACP read_terminal response consumed"
        );
        Ok(AcpReadTerminalResponse { accepted: true })
    }

    pub(super) fn handle_read_terminal_request(&self, raw_params: &str, respond: ResponseSender) {
        if !self.state.lock().is_ok_and(|state| state.read_terminal_enabled) {
            warn!("Rejected ACP read_terminal request for a disabled backend");
            respond_ignoring_transport(respond, Err(JsonRpcError::method_not_found()));
            return;
        }
        if raw_params.len() > MAX_REQUEST_PAYLOAD_BYTES {
            reject_terminal_request(respond, "payload_too_large");
            return;
        }
        let request = match serde_json::from_str::<AcpReadTerminalRequestEventData>(raw_params) {
            Ok(request) => request,
            Err(_) => {
                reject_terminal_request(respond, "invalid_shape");
                return;
            }
        };
        if let Err(reason) = validate_terminal_request(&request) {
            reject_terminal_request(respond, reason);
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
                reject_terminal_request(respond, "session_mismatch");
                return;
            }
            if state.pending.contains_key(&request.request_id)
                || state.pending_terminal.contains_key(&request.request_id)
            {
                reject_terminal_request(respond, "duplicate_request_id");
                return;
            }
            state.pending_terminal.insert(
                request.request_id.clone(),
                PendingReadTerminal {
                    session_id: request.session_id.clone(),
                    start: request.start,
                    count: request.count,
                    respond,
                },
            );
        }

        if self
            .event_tx
            .send(AgentStreamEvent::AcpReadTerminalRequest(request.clone()))
            .is_err()
        {
            self.reject_terminal_pending(&request.request_id, "renderer_unavailable");
            return;
        }

        info!(
            method = COMMAND_EVE_READ_TERMINAL_WIRE_METHOD,
            request_id_bytes = request.request_id.len(),
            session_id_bytes = request.session_id.len(),
            "Accepted ACP read_terminal request"
        );
        let state = Arc::clone(&self.state);
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            expire_pending_terminal(state, &request.request_id, &request.session_id);
        });
    }

    fn reject_terminal_pending(&self, request_id: &str, reason: &'static str) {
        let pending = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.pending_terminal.remove(request_id));
        if let Some(pending) = pending {
            respond_ignoring_transport(pending.respond, Err(rpc_internal(reason)));
        }
    }
}

fn validate_terminal_request(request: &AcpReadTerminalRequestEventData) -> Result<(), &'static str> {
    if request.version != COMMAND_EVE_READ_TERMINAL_VERSION {
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

fn validate_terminal_response_envelope(response: &AcpReadTerminalResponseRequest) -> Result<(), AgentError> {
    if response.version != COMMAND_EVE_READ_TERMINAL_VERSION {
        return Err(AgentError::bad_request(
            "Unsupported ACP read_terminal response version",
        ));
    }
    validate_identifier(&response.request_id)
        .map_err(|_| AgentError::bad_request("Invalid ACP read_terminal request_id"))?;
    validate_identifier(&response.session_id)
        .map_err(|_| AgentError::bad_request("Invalid ACP read_terminal session_id"))?;
    Ok(())
}

fn validate_terminal_result(result: &AcpReadTerminalResult, pending: &PendingReadTerminal) -> Result<(), AgentError> {
    if result.text.chars().count() > MAX_TEXT_CHARS {
        return Err(AgentError::bad_request(
            "ACP read_terminal text exceeds the character cap",
        ));
    }
    if result
        .text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(AgentError::bad_request(
            "ACP read_terminal text contains unsupported control characters",
        ));
    }
    if result.total_lines > MAX_TOTAL_LINES
        || result.start > result.end
        || result.end > result.total_lines
        || result.cursor_row > result.total_lines
        || result.viewport_rows == 0
        || result.viewport_rows > MAX_COUNT
    {
        return Err(AgentError::bad_request(
            "ACP read_terminal result offsets are out of range",
        ));
    }
    if let Some(requested_start) = pending.start {
        let expected_start = requested_start.min(result.total_lines);
        if result.start != expected_start {
            return Err(AgentError::conflict(
                "ACP read_terminal result start does not match the request",
            ));
        }
    }
    let requested_count = pending.count.unwrap_or(result.viewport_rows);
    let span = result.end - result.start;
    if span > requested_count || result.text.lines().count() > span as usize {
        return Err(AgentError::bad_request(
            "ACP read_terminal result exceeds the requested window",
        ));
    }
    Ok(())
}

fn expire_pending_terminal(state: Arc<std::sync::Mutex<ExtensionState>>, request_id: &str, session_id: &str) {
    let pending = state.lock().ok().and_then(|mut state| {
        let matches = state
            .pending_terminal
            .get(request_id)
            .is_some_and(|pending| pending.session_id == session_id);
        matches.then(|| state.pending_terminal.remove(request_id)).flatten()
    });
    if let Some(pending) = pending {
        warn!(
            method = COMMAND_EVE_READ_TERMINAL_WIRE_METHOD,
            request_id_bytes = request_id.len(),
            session_id_bytes = session_id.len(),
            "ACP read_terminal request timed out"
        );
        respond_ignoring_transport(pending.respond, Err(rpc_internal("timeout")));
    }
}

pub(super) fn cancel_pending_terminal(pending: Vec<PendingReadTerminal>, reason: &'static str) {
    for pending in pending {
        respond_ignoring_transport(pending.respond, Err(rpc_internal(reason)));
    }
}

fn reject_terminal_request(respond: ResponseSender, reason: &'static str) {
    warn!(
        method = COMMAND_EVE_READ_TERMINAL_WIRE_METHOD,
        reason, "Rejected ACP read_terminal request"
    );
    respond_ignoring_transport(
        respond,
        Err(JsonRpcError::invalid_params().data(serde_json::json!({ "reason": reason }))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_api_types::{AcpReadPreviewRequestEventData, COMMAND_EVE_READ_PREVIEW_VERSION};
    use std::time::Duration;
    use tokio::sync::{broadcast, oneshot};

    fn request(request_id: &str, session_id: &str) -> AcpReadTerminalRequestEventData {
        AcpReadTerminalRequestEventData {
            version: COMMAND_EVE_READ_TERMINAL_VERSION.to_owned(),
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            start: Some(4),
            count: Some(12),
        }
    }

    fn response(request_id: &str, session_id: &str) -> AcpReadTerminalResponseRequest {
        AcpReadTerminalResponseRequest {
            version: COMMAND_EVE_READ_TERMINAL_VERSION.to_owned(),
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            result: Some(AcpReadTerminalResult {
                total_lines: 50,
                start: 4,
                end: 7,
                viewport_rows: 24,
                cursor_row: 6,
                text: "line one\nline two\nline three".to_owned(),
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
        router.enable_read_terminal().unwrap();
    }

    #[tokio::test]
    async fn requires_explicit_enable_and_emits_the_typed_terminal_event() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        let disabled = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-disabled", "session-1")).unwrap(),
        );
        assert_eq!(i32::from(disabled.await.unwrap().unwrap_err().code), -32601);

        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let req = request("request-1", "session-1");
        let response_rx = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(&req).unwrap(),
        );
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::AcpReadTerminalRequest(data) if data == req
        ));
        assert_eq!(router.pending_terminal_count(), 1);
        assert!(
            router
                .respond_read_terminal(response("request-1", "session-1"))
                .unwrap()
                .accepted
        );
        assert!(response_rx.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn rejects_unknown_fields_versions_sessions_and_request_caps() {
        let (event_tx, _event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();

        for invalid in [
            serde_json::json!({
                "version": COMMAND_EVE_READ_TERMINAL_VERSION,
                "request_id": "request-unknown-field",
                "session_id": "session-1",
                "surprise": true
            }),
            serde_json::json!({
                "version": "command-eve-read-terminal/v2",
                "request_id": "request-version",
                "session_id": "session-1"
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_TERMINAL_VERSION,
                "request_id": "request-session",
                "session_id": "session-2"
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_TERMINAL_VERSION,
                "request_id": "request-start",
                "session_id": "session-1",
                "start": MAX_START + 1
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_TERMINAL_VERSION,
                "request_id": "request-count-zero",
                "session_id": "session-1",
                "count": 0
            }),
            serde_json::json!({
                "version": COMMAND_EVE_READ_TERMINAL_VERSION,
                "request_id": "request-count-high",
                "session_id": "session-1",
                "count": MAX_COUNT + 1
            }),
        ] {
            let error = dispatch(&router, COMMAND_EVE_READ_TERMINAL_EXT_METHOD, invalid)
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(i32::from(error.code), -32602);
        }
        assert_eq!(router.pending_terminal_count(), 0);
    }

    #[tokio::test]
    async fn duplicate_unknown_and_replayed_responses_fail_without_cross_method_confusion() {
        let (event_tx, mut event_rx) = broadcast::channel(8);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.enable_read_preview().unwrap();
        router.bind_session("session-1").await.unwrap();

        let value = serde_json::to_value(request("request-1", "session-1")).unwrap();
        let first = dispatch(&router, COMMAND_EVE_READ_TERMINAL_EXT_METHOD, value.clone());
        let _ = event_rx.recv().await.unwrap();
        let duplicate = dispatch(&router, COMMAND_EVE_READ_TERMINAL_EXT_METHOD, value);
        assert_eq!(i32::from(duplicate.await.unwrap().unwrap_err().code), -32602);

        let preview_collision = dispatch(
            &router,
            super::super::COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(AcpReadPreviewRequestEventData {
                version: COMMAND_EVE_READ_PREVIEW_VERSION.to_owned(),
                request_id: "request-1".to_owned(),
                session_id: "session-1".to_owned(),
                start: None,
                count: None,
            })
            .unwrap(),
        );
        assert_eq!(i32::from(preview_collision.await.unwrap().unwrap_err().code), -32602);

        let mut mismatched = response("request-1", "session-2");
        assert!(router.respond_read_terminal(mismatched.clone()).is_err());
        assert_eq!(router.pending_terminal_count(), 1);
        mismatched.session_id = "session-1".to_owned();
        assert!(router.respond_read_terminal(mismatched.clone()).unwrap().accepted);
        assert!(first.await.unwrap().is_ok());
        assert!(router.respond_read_terminal(mismatched).is_err());
        assert!(router.respond_read_terminal(response("unknown", "session-1")).is_err());
        assert_eq!(router.pending_terminal_count(), 0);

        let preview = dispatch(
            &router,
            super::super::COMMAND_EVE_READ_PREVIEW_EXT_METHOD,
            serde_json::to_value(AcpReadPreviewRequestEventData {
                version: COMMAND_EVE_READ_PREVIEW_VERSION.to_owned(),
                request_id: "request-preview".to_owned(),
                session_id: "session-1".to_owned(),
                start: None,
                count: None,
            })
            .unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        let terminal_collision = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-preview", "session-1")).unwrap(),
        );
        assert_eq!(i32::from(terminal_collision.await.unwrap().unwrap_err().code), -32602);
        router.cancel_all("test_complete");
        assert!(preview.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rebind_close_cancel_and_timeout_consume_terminal_requests_once() {
        let (event_tx, mut event_rx) = broadcast::channel(8);
        let router = AcpClientExtensionRouter::with_timeout(event_tx, Duration::from_millis(5));
        enable(&router);
        router.bind_session("session-1").await.unwrap();

        let rebound = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-rebind", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.bind_session("session-2").await.unwrap();
        assert!(rebound.await.unwrap().is_err());

        let closed = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-close", "session-2")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.unbind_session("session-2").await;
        assert!(closed.await.unwrap().is_err());

        router.bind_session("session-3").await.unwrap();
        let timed_out = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-timeout", "session-3")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), timed_out)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(i32::from(error.code), -32603);
        assert!(
            router
                .respond_read_terminal(response("request-timeout", "session-3"))
                .is_err()
        );

        let cancelled = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-cancel", "session-3")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();
        router.cancel_all("test_shutdown");
        assert!(cancelled.await.unwrap().is_err());
        assert_eq!(router.pending_terminal_count(), 0);
    }

    #[tokio::test]
    async fn result_bounds_payload_cap_and_redaction_fail_closed() {
        let (event_tx, mut event_rx) = broadcast::channel(8);
        let router = AcpClientExtensionRouter::new(event_tx);
        enable(&router);
        router.bind_session("session-1").await.unwrap();
        let rx = dispatch(
            &router,
            COMMAND_EVE_READ_TERMINAL_EXT_METHOD,
            serde_json::to_value(request("request-result", "session-1")).unwrap(),
        );
        let _ = event_rx.recv().await.unwrap();

        let mut invalid = response("request-result", "session-1");
        invalid.result.as_mut().unwrap().start = 5;
        assert!(router.respond_read_terminal(invalid).is_err());
        assert_eq!(router.pending_terminal_count(), 1);

        let mut control = response("request-result", "session-1");
        control.result.as_mut().unwrap().text = "plain\u{1b}[31m".to_owned();
        assert!(router.respond_read_terminal(control).is_err());
        assert_eq!(router.pending_terminal_count(), 1);

        let mut oversized = response("request-result", "session-1");
        oversized.result.as_mut().unwrap().text = "é".repeat(17_000);
        assert!(router.respond_read_terminal(oversized).is_err());
        assert_eq!(router.pending_terminal_count(), 1);

        let mut valid = response("request-result", "session-1");
        valid.result.as_mut().unwrap().text =
            "Authorization: Bearer abcdefghijkl\nhttps://example.test/?api_key=hidden".to_owned();
        assert!(router.respond_read_terminal(valid).unwrap().accepted);
        let wire = rx.await.unwrap().unwrap().to_string();
        assert!(!wire.contains("abcdefghijkl"));
        assert!(!wire.contains("api_key=hidden"));
        assert!(wire.contains("[redacted]"));
    }
}
