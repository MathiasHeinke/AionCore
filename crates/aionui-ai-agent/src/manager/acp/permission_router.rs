use crate::agent_runtime::AgentRuntime;
use crate::error::AgentError;
use crate::protocol::acp::{PermissionDecision, PermissionRequest};
use crate::protocol::events::{
    AcpPermissionEventData, AcpPermissionOptionKind, AgentStreamEvent, permission_request_to_event_data,
};
use agent_client_protocol::schema::{
    PermissionOption as SdkPermissionOption, PermissionOptionKind as SdkPermissionOptionKind, RequestPermissionRequest,
    ToolKind as SdkToolKind,
};
use aionui_api_types::TEAM_MCP_SERVER_NAME;
use aionui_common::Confirmation;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, info, warn};

use super::AcpAgentManager;

const TEAM_GUIDE_MCP_SERVER_NAME: &str = "aionui-team-guide";
const AUTO_APPROVE_MCP_SERVERS: &[&str] = &[TEAM_MCP_SERVER_NAME, TEAM_GUIDE_MCP_SERVER_NAME];
const HERMES_BACKEND: &str = "hermes";
const HERMES_EDIT_PERMISSION_TTL: Duration = Duration::from_secs(60);
const HERMES_COMMAND_PERMISSION_TTL: Duration = Duration::from_secs(300);
const CONFIRMATION_ACTION_EXPIRED: &str = "expired";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionDisposition {
    AllowOnce,
    ExactSession,
    RejectOnce,
    UnsupportedPermanent,
}

#[derive(Debug, Clone)]
struct CommandEveAuthority {
    grant_key: Option<String>,
    allow_once_option_id: Option<String>,
    option_dispositions: HashMap<String, OptionDisposition>,
}

struct PendingPermission {
    responder: Option<oneshot::Sender<PermissionDecision>>,
    confirmation: Confirmation,
    command_eve: Option<CommandEveAuthority>,
    expires_at: Option<Instant>,
    nonce: u64,
    runtime: AgentRuntime,
}

/// Routes ACP permission requests from the protocol layer to the user
/// (via `event_tx`) and back (via `confirm`). Owns the receiver channel
/// for incoming permission requests, the pending responder map, and the
/// `closing` flag that prevents new requests from being routed after a
/// graceful shutdown has started.
pub struct PermissionRouter {
    /// Receiver for permission requests from the protocol layer.
    permission_rx: Mutex<mpsc::Receiver<PermissionRequest>>,
    /// Pending ACP permission responders and recovery data keyed by tool call ID.
    pending_permissions: StdMutex<HashMap<String, PendingPermission>>,
    /// Exact transmitted-request grants. This store is process/session local
    /// and is cleared with the router; it never writes Hermes profile state.
    session_grants: StdMutex<HashSet<String>>,
    next_nonce: AtomicU64,
    /// Whether a graceful shutdown is in progress.
    closing: AtomicBool,
}

impl PermissionRouter {
    /// Create a new permission router.
    pub fn new(permission_rx: mpsc::Receiver<PermissionRequest>) -> Self {
        Self {
            permission_rx: Mutex::new(permission_rx),
            pending_permissions: StdMutex::new(HashMap::new()),
            session_grants: StdMutex::new(HashSet::new()),
            next_nonce: AtomicU64::new(1),
            closing: AtomicBool::new(false),
        }
    }

    /// Start the permission handler loop.
    ///
    /// This background task receives permission requests from the protocol
    /// layer, converts them to `Permission` events, and waits for user
    /// responses routed through the `confirm()` method.
    ///
    /// `runtime` is shared with the parent manager so permission
    /// arrivals count as activity (preventing idle timeouts) via
    /// `runtime.bump_activity()`.
    pub fn start(self: &Arc<Self>, runtime: AgentRuntime, manager: Weak<AcpAgentManager>, backend: Option<String>) {
        let this = Arc::clone(self);

        tokio::spawn(async move {
            let mut rx = this.permission_rx.lock().await;

            while let Some(perm_req) = rx.recv().await {
                runtime.bump_activity();

                let call_id = perm_req.request.tool_call.tool_call_id.to_string();
                let command_eve =
                    command_eve_authority(&manager, backend.as_deref(), &runtime, &perm_req.request).await;

                // Auto-approve team MCP tools without user interaction.
                let team_auto_approve_option = if command_eve.is_some() {
                    command_eve_team_auto_approve_option_id(&perm_req.request)
                } else {
                    auto_approve_option_id(&perm_req.request)
                };
                if let Some(option_id) = team_auto_approve_option {
                    info!(
                        conversation_id = %runtime.conversation_id(),
                        call_id,
                        option_id = %option_id,
                        server_name = ?extract_mcp_server_name(&perm_req.request),
                        "ACP team MCP permission auto-approved"
                    );
                    let _ = perm_req.response_tx.send(PermissionDecision::Selected { option_id });
                    continue;
                }

                if let Some(authority) = command_eve.as_ref()
                    && let (Some(grant_key), Some(allow_once_option_id)) =
                        (authority.grant_key.as_ref(), authority.allow_once_option_id.as_ref())
                    && this.session_grants.lock().unwrap().contains(grant_key)
                {
                    info!(
                        conversation_id = %runtime.conversation_id(),
                        call_id,
                        "Exact Command EVE session grant matched"
                    );
                    let _ = perm_req.response_tx.send(PermissionDecision::Selected {
                        option_id: allow_once_option_id.clone(),
                    });
                    continue;
                }

                let mut permission_event = permission_request_to_event_data(&perm_req.request);
                if let Some(authority) = command_eve.as_ref() {
                    contain_command_eve_options(&mut permission_event, authority.grant_key.is_some());
                }
                let confirmation = permission_event
                    .as_confirmation()
                    .expect("ACP permission events must be recoverable as confirmations");
                let nonce = this.next_nonce.fetch_add(1, Ordering::Relaxed);
                let ttl = command_eve.as_ref().map(|_| permission_ttl(&perm_req.request));

                let mut pending = this.pending_permissions.lock().unwrap();
                if let Some(previous) = pending.insert(
                    call_id.clone(),
                    PendingPermission {
                        responder: Some(perm_req.response_tx),
                        confirmation,
                        command_eve,
                        expires_at: ttl.map(|ttl| Instant::now() + ttl),
                        nonce,
                        runtime: runtime.clone(),
                    },
                ) && let Some(responder) = previous.responder
                {
                    let _ = responder.send(PermissionDecision::Cancelled);
                }
                drop(pending);
                debug!(
                    conversation_id = %runtime.conversation_id(),
                    call_id,
                    "ACP permission pending confirmation registered"
                );

                if runtime
                    .event_sender()
                    .send(AgentStreamEvent::AcpPermission(permission_event))
                    .is_err()
                    && let Some(pending) = this.pending_permissions.lock().unwrap().remove(&call_id)
                {
                    if let Some(responder) = pending.responder {
                        let _ = responder.send(PermissionDecision::Cancelled);
                    }
                    continue;
                }

                if let Some(ttl) = ttl {
                    let expiry_router = Arc::clone(&this);
                    let expiry_call_id = call_id.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(ttl).await;
                        expiry_router.expire_permission(&expiry_call_id, nonce);
                    });
                }
            }
        });
    }

    /// Pending permission items recoverable by conversation confirmation APIs.
    pub fn get_confirmations(&self) -> Vec<Confirmation> {
        self.expire_due_permissions();
        self.pending_permissions
            .lock()
            .unwrap()
            .values()
            .map(|pending| pending.confirmation.clone())
            .collect()
    }

    /// Resolve a pending permission request with the user's selected option.
    pub fn confirm(&self, call_id: &str, option_id: String, conversation_id: &str) -> Result<(), AgentError> {
        self.expire_due_permissions();

        let (mut pending, forwarded_option_id, grant_key) = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let pending = permissions
                .get(call_id)
                .ok_or_else(|| AgentError::bad_request(format!("Pending ACP permission not found: {call_id}")))?;
            if pending.responder.is_none()
                || pending.confirmation.action.as_deref() == Some(CONFIRMATION_ACTION_EXPIRED)
            {
                return Err(AgentError::bad_request(format!(
                    "Pending ACP permission expired: {call_id}"
                )));
            }

            let (forwarded_option_id, grant_key) = if let Some(authority) = pending.command_eve.as_ref() {
                match authority.option_dispositions.get(&option_id) {
                    Some(OptionDisposition::AllowOnce | OptionDisposition::RejectOnce) => (option_id.clone(), None),
                    Some(OptionDisposition::ExactSession) => {
                        let allow_once = authority.allow_once_option_id.clone().ok_or_else(|| {
                            AgentError::bad_request("Exact session grant is unavailable without an allow-once option")
                        })?;
                        let grant_key = authority.grant_key.clone().ok_or_else(|| {
                            AgentError::bad_request("Exact session grant is unavailable for this runtime request")
                        })?;
                        (allow_once, Some(grant_key))
                    }
                    Some(OptionDisposition::UnsupportedPermanent) => {
                        return Err(AgentError::bad_request(
                            "Permanent allow/deny is unavailable until exact durable grants are supported",
                        ));
                    }
                    None => {
                        return Err(AgentError::bad_request(format!(
                            "Unknown ACP permission option for this request: {option_id}"
                        )));
                    }
                }
            } else {
                (option_id.clone(), None)
            };

            let pending = permissions
                .remove(call_id)
                .expect("pending permission disappeared while its map lock was held");
            (pending, forwarded_option_id, grant_key)
        };

        let responder = pending
            .responder
            .take()
            .ok_or_else(|| AgentError::bad_request(format!("Pending ACP permission expired: {call_id}")))?;
        if responder
            .send(PermissionDecision::Selected {
                option_id: forwarded_option_id,
            })
            .is_err()
        {
            self.record_expired_history(call_id.to_owned(), pending);
            return Err(AgentError::bad_request(format!(
                "Pending ACP permission expired: {call_id}"
            )));
        }

        if let Some(grant_key) = grant_key {
            self.session_grants.lock().unwrap().insert(grant_key);
        }

        debug!(conversation_id = %conversation_id, call_id, "ACP permission response forwarded");
        Ok(())
    }

    fn expire_due_permissions(&self) {
        let due = {
            let permissions = self.pending_permissions.lock().unwrap();
            let now = Instant::now();
            permissions
                .iter()
                .filter_map(|(call_id, pending)| {
                    pending
                        .expires_at
                        .filter(|expires_at| *expires_at <= now && pending.responder.is_some())
                        .map(|_| (call_id.clone(), pending.nonce))
                })
                .collect::<Vec<_>>()
        };
        for (call_id, nonce) in due {
            self.expire_permission(&call_id, nonce);
        }
    }

    fn expire_permission(&self, call_id: &str, nonce: u64) {
        let expired = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let Some(pending) = permissions.get_mut(call_id) else {
                return;
            };
            if pending.nonce != nonce || pending.responder.is_none() {
                return;
            }
            if pending.expires_at.is_some_and(|expires_at| expires_at > Instant::now()) {
                return;
            }

            let responder = pending.responder.take();
            pending.confirmation.action = Some(CONFIRMATION_ACTION_EXPIRED.to_owned());
            pending.confirmation.options.clear();
            Some((responder, pending.confirmation.clone(), pending.runtime.clone()))
        };

        if let Some((responder, confirmation, runtime)) = expired {
            if let Some(responder) = responder {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
            debug!(
                conversation_id = %runtime.conversation_id(),
                call_id,
                "Command EVE permission expired before a user decision"
            );
        }
    }

    fn record_expired_history(&self, call_id: String, mut pending: PendingPermission) {
        pending.confirmation.action = Some(CONFIRMATION_ACTION_EXPIRED.to_owned());
        pending.confirmation.options.clear();
        pending.responder = None;
        let confirmation = pending.confirmation.clone();
        let runtime = pending.runtime.clone();
        let inserted = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            if permissions.contains_key(&call_id) {
                false
            } else {
                permissions.insert(call_id.clone(), pending);
                true
            }
        };
        if inserted {
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
            warn!(
                conversation_id = %runtime.conversation_id(),
                call_id,
                "ACP permission responder was no longer active; recorded as expired"
            );
        }
    }

    /// Cancel all pending permission requests. Called during `stop()` and `kill()`.
    pub fn cancel_all(&self) {
        for (_, pending) in self.pending_permissions.lock().unwrap().drain() {
            if let Some(responder) = pending.responder {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
        }
        self.session_grants.lock().unwrap().clear();
    }

    /// Whether a graceful shutdown is in progress.
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// Mark the router as closing (graceful shutdown in progress).
    pub fn set_closing(&self) {
        self.closing.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn insert_pending_for_test(
        &self,
        call_id: String,
        responder: oneshot::Sender<PermissionDecision>,
        confirmation: Confirmation,
    ) {
        self.pending_permissions.lock().unwrap().insert(
            call_id,
            PendingPermission {
                responder: Some(responder),
                confirmation,
                command_eve: None,
                expires_at: None,
                nonce: self.next_nonce.fetch_add(1, Ordering::Relaxed),
                runtime: AgentRuntime::new("test-conversation", "/tmp/test-workspace", 8),
            },
        );
    }

    #[cfg(test)]
    fn insert_command_eve_pending_for_test(
        &self,
        call_id: String,
        responder: oneshot::Sender<PermissionDecision>,
        confirmation: Confirmation,
        command_eve: CommandEveAuthority,
        expires_at: Option<Instant>,
        runtime: AgentRuntime,
    ) {
        self.pending_permissions.lock().unwrap().insert(
            call_id,
            PendingPermission {
                responder: Some(responder),
                confirmation,
                command_eve: Some(command_eve),
                expires_at,
                nonce: self.next_nonce.fetch_add(1, Ordering::Relaxed),
                runtime,
            },
        );
    }
}

async fn command_eve_authority(
    manager: &Weak<AcpAgentManager>,
    backend: Option<&str>,
    runtime: &AgentRuntime,
    request: &RequestPermissionRequest,
) -> Option<CommandEveAuthority> {
    if backend != Some(HERMES_BACKEND) {
        return None;
    }
    let (active_session_id, mode) = if let Some(manager) = manager.upgrade() {
        let session = manager.session.read().await;
        (
            session.session_id().map(str::to_owned),
            session
                .observed_mode()
                .map(str::to_owned)
                .or_else(|| session.current_mode_id()),
        )
    } else {
        (None, None)
    };

    build_command_eve_authority(
        backend,
        active_session_id.as_deref(),
        mode.as_deref(),
        runtime.workspace(),
        request,
    )
}

fn build_command_eve_authority(
    backend: Option<&str>,
    active_session_id: Option<&str>,
    mode: Option<&str>,
    workspace: &str,
    request: &RequestPermissionRequest,
) -> Option<CommandEveAuthority> {
    if backend != Some(HERMES_BACKEND) {
        return None;
    }

    let allow_once_option_id = request
        .options
        .iter()
        .find(|option| matches!(option.kind, SdkPermissionOptionKind::AllowOnce))
        .map(|option| option.option_id.to_string());
    let option_dispositions = request
        .options
        .iter()
        .map(|option| (option.option_id.to_string(), command_eve_option_disposition(option)))
        .collect();
    let request_session_id = request.session_id.to_string();
    let grant_key = active_session_id
        .is_some_and(|session_id| session_id == request_session_id)
        .then_some(mode)
        .flatten()
        .map(|mode| operation_digest(workspace, HERMES_BACKEND, mode, request));

    Some(CommandEveAuthority {
        grant_key,
        allow_once_option_id,
        option_dispositions,
    })
}

fn command_eve_option_disposition(option: &SdkPermissionOption) -> OptionDisposition {
    match option.kind {
        SdkPermissionOptionKind::AllowOnce => OptionDisposition::AllowOnce,
        SdkPermissionOptionKind::AllowAlways
            if is_session_scoped_option(&option.option_id.to_string(), &option.name) =>
        {
            OptionDisposition::ExactSession
        }
        SdkPermissionOptionKind::RejectOnce => OptionDisposition::RejectOnce,
        SdkPermissionOptionKind::AllowAlways | SdkPermissionOptionKind::RejectAlways => {
            OptionDisposition::UnsupportedPermanent
        }
        _ => OptionDisposition::UnsupportedPermanent,
    }
}

fn is_session_scoped_option(option_id: &str, name: &str) -> bool {
    let id = option_id.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    id == "allow_session"
        || id.contains("for-session")
        || id.contains("for_session")
        || name.contains("for session")
        || name.contains("this session")
}

fn contain_command_eve_options(event: &mut AcpPermissionEventData, exact_session_available: bool) {
    let AcpPermissionEventData::Request(request) = event else {
        return;
    };
    request.options.retain_mut(|option| match option.kind {
        AcpPermissionOptionKind::AllowOnce | AcpPermissionOptionKind::RejectOnce => true,
        AcpPermissionOptionKind::AllowAlways
            if exact_session_available && is_session_scoped_option(&option.option_id, &option.name) =>
        {
            option.name = "Allow this exact request for this session".to_owned();
            true
        }
        AcpPermissionOptionKind::AllowAlways | AcpPermissionOptionKind::RejectAlways => false,
    });
}

fn permission_ttl(request: &RequestPermissionRequest) -> Duration {
    if matches!(request.tool_call.fields.kind.as_ref(), Some(SdkToolKind::Edit)) {
        HERMES_EDIT_PERMISSION_TTL
    } else {
        HERMES_COMMAND_PERMISSION_TTL
    }
}

fn operation_digest(workspace: &str, backend: &str, mode: &str, request: &RequestPermissionRequest) -> String {
    let mut options = request
        .options
        .iter()
        .map(|option| {
            json!({
                "option_id": option.option_id.to_string(),
                "kind": option.kind,
            })
        })
        .collect::<Vec<_>>();
    options.sort_by(|left, right| left["option_id"].as_str().cmp(&right["option_id"].as_str()));

    let payload = canonicalize_json(json!({
        "version": 1,
        "backend": backend,
        "session_id": request.session_id.to_string(),
        "workspace": canonical_workspace(workspace),
        "mode": mode,
        "tool_kind": request.tool_call.fields.kind,
        "title": request.tool_call.fields.title,
        "raw_input": request.tool_call.fields.raw_input,
        "options": options,
    }));
    format!("{:x}", Sha256::digest(serde_json::to_vec(&payload).unwrap_or_default()))
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        other => other,
    }
}

fn canonical_workspace(workspace: &str) -> String {
    std::fs::canonicalize(Path::new(workspace))
        .unwrap_or_else(|_| PathBuf::from(workspace))
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
fn is_auto_approve_tool(request: &agent_client_protocol::schema::RequestPermissionRequest) -> bool {
    auto_approve_option_id(request).is_some()
}

fn auto_approve_option_id(request: &agent_client_protocol::schema::RequestPermissionRequest) -> Option<String> {
    let server_name = extract_mcp_server_name(request)?;
    if !AUTO_APPROVE_MCP_SERVERS.contains(&server_name.as_str()) {
        return None;
    }
    select_allow_option_id(request)
}

fn command_eve_team_auto_approve_option_id(request: &RequestPermissionRequest) -> Option<String> {
    let server_name = extract_mcp_server_name(request)?;
    if !AUTO_APPROVE_MCP_SERVERS.contains(&server_name.as_str()) {
        return None;
    }
    request
        .options
        .iter()
        .find(|option| matches!(option.kind, SdkPermissionOptionKind::AllowOnce))
        .map(|option| option.option_id.to_string())
}

fn select_allow_option_id(request: &agent_client_protocol::schema::RequestPermissionRequest) -> Option<String> {
    request
        .options
        .iter()
        .find(|option| matches!(option.kind, SdkPermissionOptionKind::AllowAlways))
        .or_else(|| {
            request
                .options
                .iter()
                .find(|option| matches!(option.kind, SdkPermissionOptionKind::AllowOnce))
        })
        .map(|option| option.option_id.to_string())
}

fn extract_mcp_server_name(request: &agent_client_protocol::schema::RequestPermissionRequest) -> Option<String> {
    extract_mcp_server_from_raw_input(request).or_else(|| {
        request
            .tool_call
            .fields
            .title
            .as_deref()
            .and_then(extract_mcp_server_from_prefixed_title)
            .map(str::to_owned)
    })
}

fn extract_mcp_server_from_raw_input(
    request: &agent_client_protocol::schema::RequestPermissionRequest,
) -> Option<String> {
    request
        .tool_call
        .fields
        .raw_input
        .as_ref()
        .and_then(|raw_input| raw_input.get("server_name"))
        .and_then(serde_json::Value::as_str)
        .filter(|server_name| !server_name.is_empty())
        .map(str::to_owned)
}

fn extract_mcp_server_from_prefixed_title(title: &str) -> Option<&str> {
    let rest = title.strip_prefix("mcp__")?;
    let (server_name, tool_name) = rest.split_once("__")?;
    if server_name.is_empty() || tool_name.is_empty() {
        return None;
    }
    Some(server_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::events::AgentStreamEvent;
    use agent_client_protocol::schema::{
        PermissionOption, PermissionOptionKind as SdkPermissionOptionKind, RequestPermissionRequest,
        ToolCallUpdate as SdkToolCallUpdate, ToolCallUpdateFields, ToolKind as SdkToolKind,
    };
    use aionui_common::Confirmation;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn permission_request_with_title_and_raw_input(
        title: &str,
        raw_input: Option<serde_json::Value>,
        options: Vec<PermissionOption>,
    ) -> RequestPermissionRequest {
        RequestPermissionRequest::new(
            "session-1",
            SdkToolCallUpdate::new(
                "tool-1",
                ToolCallUpdateFields::new()
                    .kind(SdkToolKind::Other)
                    .title(title.to_owned())
                    .raw_input(raw_input),
            ),
            options,
        )
    }

    fn allow_always_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(
            option_id,
            "Allow for this session",
            SdkPermissionOptionKind::AllowAlways,
        )
    }

    fn allow_once_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(option_id, "Allow", SdkPermissionOptionKind::AllowOnce)
    }

    fn allow_session_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(option_id, "Allow for session", SdkPermissionOptionKind::AllowAlways)
    }

    fn allow_permanent_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(option_id, "Allow always", SdkPermissionOptionKind::AllowAlways)
    }

    fn reject_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(option_id, "Reject", SdkPermissionOptionKind::RejectOnce)
    }

    fn reject_always_option(option_id: &'static str) -> PermissionOption {
        PermissionOption::new(option_id, "Reject always", SdkPermissionOptionKind::RejectAlways)
    }

    fn command_eve_authority_for_test(grant_key: Option<&str>) -> CommandEveAuthority {
        CommandEveAuthority {
            grant_key: grant_key.map(str::to_owned),
            allow_once_option_id: Some("allow_once".to_owned()),
            option_dispositions: HashMap::from([
                ("allow_once".to_owned(), OptionDisposition::AllowOnce),
                ("allow_session".to_owned(), OptionDisposition::ExactSession),
                ("allow_always".to_owned(), OptionDisposition::UnsupportedPermanent),
                ("deny".to_owned(), OptionDisposition::RejectOnce),
                ("deny_always".to_owned(), OptionDisposition::UnsupportedPermanent),
            ]),
        }
    }

    fn sample_confirmation(call_id: &str) -> Confirmation {
        Confirmation {
            id: call_id.to_owned(),
            call_id: call_id.to_owned(),
            title: Some("Write file".to_owned()),
            action: None,
            description: "Write /tmp/current_time.txt".to_owned(),
            command_type: Some("edit".to_owned()),
            options: vec![aionui_common::ConfirmationOption {
                label: "Allow".to_owned(),
                value: json!("allow_once"),
                params: None,
            }],
        }
    }

    #[test]
    fn get_confirmations_returns_pending_acp_permission() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, _response_rx) = oneshot::channel();

        router.insert_pending_for_test("tool-1".to_owned(), response_tx, sample_confirmation("tool-1"));

        let confirmations = router.get_confirmations();
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].id, "tool-1");
        assert_eq!(confirmations[0].call_id, "tool-1");
        assert_eq!(confirmations[0].description, "Write /tmp/current_time.txt");
    }

    #[test]
    fn confirm_removes_pending_confirmation_and_forwards_option() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, mut response_rx) = oneshot::channel();
        router.insert_pending_for_test("tool-1".to_owned(), response_tx, sample_confirmation("tool-1"));

        router
            .confirm("tool-1", "allow_once".to_owned(), "conv-1")
            .expect("confirm should succeed");

        assert!(router.get_confirmations().is_empty());
        assert!(matches!(
            response_rx.try_recv(),
            Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
        ));
    }

    #[test]
    fn command_eve_containment_removes_permanent_options_but_keeps_exact_session_intent() {
        let request = permission_request_with_title_and_raw_input(
            "Execute command",
            Some(json!({ "command": "echo bounded" })),
            vec![
                allow_once_option("allow_once"),
                allow_session_option("allow_session"),
                allow_permanent_option("allow_always"),
                reject_option("deny"),
                reject_always_option("deny_always"),
            ],
        );
        let mut event = permission_request_to_event_data(&request);

        contain_command_eve_options(&mut event, true);

        let AcpPermissionEventData::Request(event) = event else {
            panic!("permission translation must keep the Request variant");
        };
        let option_ids = event
            .options
            .iter()
            .map(|option| option.option_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(option_ids, vec!["allow_once", "allow_session", "deny"]);
        assert_eq!(event.options[1].name, "Allow this exact request for this session");
    }

    #[test]
    fn exact_session_intent_forwards_allow_once_and_records_only_the_local_digest() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, mut response_rx) = oneshot::channel();
        router.insert_command_eve_pending_for_test(
            "tool-1".to_owned(),
            response_tx,
            sample_confirmation("tool-1"),
            command_eve_authority_for_test(Some("digest-1")),
            None,
            AgentRuntime::new("conv-1", "/tmp/workspace", 8),
        );

        router
            .confirm("tool-1", "allow_session".to_owned(), "conv-1")
            .expect("exact-session intent should succeed");

        assert!(matches!(
            response_rx.try_recv(),
            Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
        ));
        assert!(router.session_grants.lock().unwrap().contains("digest-1"));
        assert!(router.get_confirmations().is_empty());
    }

    #[test]
    fn permanent_intent_is_rejected_without_consuming_the_pending_request() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, mut response_rx) = oneshot::channel();
        router.insert_command_eve_pending_for_test(
            "tool-1".to_owned(),
            response_tx,
            sample_confirmation("tool-1"),
            command_eve_authority_for_test(Some("digest-1")),
            None,
            AgentRuntime::new("conv-1", "/tmp/workspace", 8),
        );

        let error = router
            .confirm("tool-1", "allow_always".to_owned(), "conv-1")
            .expect_err("permanent intent must fail closed");

        assert!(error.to_string().contains("Permanent allow/deny is unavailable"));
        assert_eq!(router.get_confirmations().len(), 1);
        assert!(matches!(
            response_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn expired_command_eve_permission_is_disabled_and_rejects_late_confirmation() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
        let mut event_rx = runtime.subscribe();
        let (response_tx, mut response_rx) = oneshot::channel();
        router.insert_command_eve_pending_for_test(
            "tool-1".to_owned(),
            response_tx,
            sample_confirmation("tool-1"),
            command_eve_authority_for_test(Some("digest-1")),
            Some(Instant::now() - Duration::from_millis(1)),
            runtime,
        );

        let confirmations = router.get_confirmations();
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].action.as_deref(), Some("expired"));
        assert!(confirmations[0].options.is_empty());
        assert!(matches!(response_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
        assert!(matches!(
            event_rx.try_recv(),
            Ok(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(confirmation)))
                if confirmation.action.as_deref() == Some("expired")
        ));

        let error = router
            .confirm("tool-1", "allow_once".to_owned(), "conv-1")
            .expect_err("late confirmation must not report success");
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn operation_digest_ignores_call_id_but_binds_payload_workspace_mode_and_session() {
        fn request(
            tool_call_id: &'static str,
            session_id: &'static str,
            command: &'static str,
        ) -> RequestPermissionRequest {
            RequestPermissionRequest::new(
                session_id,
                SdkToolCallUpdate::new(
                    tool_call_id,
                    ToolCallUpdateFields::new()
                        .kind(SdkToolKind::Execute)
                        .title("Execute command")
                        .raw_input(json!({ "command": command })),
                ),
                vec![allow_once_option("allow_once"), allow_session_option("allow_session")],
            )
        }

        let first = request("call-1", "session-1", "echo bounded");
        let repeated = request("call-2", "session-1", "echo bounded");
        let changed = request("call-3", "session-1", "echo changed");

        let first_digest = operation_digest("/tmp/workspace", "hermes", "default", &first);
        assert_eq!(
            first_digest,
            operation_digest("/tmp/workspace", "hermes", "default", &repeated)
        );
        assert_ne!(
            first_digest,
            operation_digest("/tmp/workspace", "hermes", "default", &changed)
        );
        assert_ne!(
            first_digest,
            operation_digest("/tmp/other", "hermes", "default", &first)
        );
        assert_ne!(
            first_digest,
            operation_digest("/tmp/workspace", "hermes", "dont_ask", &first)
        );
        assert_ne!(
            first_digest,
            operation_digest(
                "/tmp/workspace",
                "hermes",
                "default",
                &request("call-4", "session-2", "echo bounded"),
            )
        );
    }

    #[test]
    fn command_eve_authority_is_hermes_scoped_and_requires_matching_acknowledged_session_state() {
        let request = permission_request_with_title_and_raw_input(
            "Execute command",
            Some(json!({ "command": "echo bounded" })),
            vec![allow_once_option("allow_once"), allow_session_option("allow_session")],
        );

        assert!(
            build_command_eve_authority(
                Some("codex"),
                Some("session-1"),
                Some("default"),
                "/tmp/workspace",
                &request,
            )
            .is_none(),
            "shared ACP backends must retain their existing manual semantics"
        );

        let authority = build_command_eve_authority(
            Some("hermes"),
            Some("session-1"),
            Some("default"),
            "/tmp/workspace",
            &request,
        )
        .expect("Hermes is the authenticated Command EVE backend");
        assert!(authority.grant_key.is_some());

        let wrong_session = build_command_eve_authority(
            Some("hermes"),
            Some("session-other"),
            Some("default"),
            "/tmp/workspace",
            &request,
        )
        .expect("Hermes request still remains visible and manual");
        assert!(wrong_session.grant_key.is_none());

        let unknown_mode =
            build_command_eve_authority(Some("hermes"), Some("session-1"), None, "/tmp/workspace", &request)
                .expect("missing classification/state asks rather than auto-approving");
        assert!(unknown_mode.grant_key.is_none());
    }

    #[test]
    fn auto_approve_matches_claude_team_mcp_title_prefix() {
        let request = permission_request_with_title_and_raw_input(
            "mcp__aionui-team__team_members",
            None,
            vec![allow_always_option("allow_always"), reject_option("reject")],
        );

        assert!(is_auto_approve_tool(&request));
    }

    #[test]
    fn auto_approve_matches_codex_raw_input_server_name() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({
                "server_name": "aionui-team",
                "request": {
                    "_meta": {
                        "codex_approval_kind": "mcp_tool_call"
                    }
                }
            })),
            vec![
                allow_once_option("approved"),
                allow_always_option("approved-for-session"),
                allow_always_option("approved-always"),
                reject_option("cancel"),
            ],
        );

        assert!(is_auto_approve_tool(&request));
    }

    #[test]
    fn auto_approve_rejects_non_team_mcp_server() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-image-generation" })),
            vec![allow_always_option("approved-for-session"), reject_option("cancel")],
        );

        assert!(!is_auto_approve_tool(&request));
    }

    #[test]
    fn auto_approve_selects_first_codex_allow_always_option() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-team" })),
            vec![
                allow_once_option("approved"),
                allow_always_option("approved-for-session"),
                allow_always_option("approved-always"),
                reject_option("cancel"),
            ],
        );

        // `approved-for-session` is selected because it is the first AllowAlways option,
        // not because the option id has special meaning in AionCore.
        assert_eq!(
            auto_approve_option_id(&request).as_deref(),
            Some("approved-for-session")
        );
    }

    #[test]
    fn command_eve_team_auto_approval_never_forwards_session_or_permanent_allow() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-team" })),
            vec![
                allow_once_option("allow_once"),
                allow_session_option("allow_session"),
                allow_permanent_option("allow_always"),
            ],
        );

        assert_eq!(
            command_eve_team_auto_approve_option_id(&request).as_deref(),
            Some("allow_once")
        );
    }

    #[test]
    fn auto_approve_selects_claude_allow_always_by_kind() {
        let request = permission_request_with_title_and_raw_input(
            "mcp__aionui-team-guide__guide_write_plan",
            None,
            vec![
                allow_always_option("allow_always"),
                allow_once_option("allow"),
                reject_option("reject"),
            ],
        );

        // `allow_always` is selected because it is the only AllowAlways option,
        // not because the option id has special meaning in AionCore.
        assert_eq!(auto_approve_option_id(&request).as_deref(), Some("allow_always"));
    }

    #[test]
    fn auto_approve_selects_first_available_allow_always_option() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-team" })),
            vec![
                allow_always_option("custom-allow-always"),
                allow_once_option("custom-allow-once"),
            ],
        );

        assert_eq!(auto_approve_option_id(&request).as_deref(), Some("custom-allow-always"));
    }

    #[test]
    fn auto_approve_returns_none_when_team_mcp_has_no_allow_option() {
        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-team" })),
            vec![reject_option("cancel")],
        );

        assert_eq!(auto_approve_option_id(&request), None);
    }

    #[test]
    fn confirm_missing_permission_returns_specific_error() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);

        let error = router
            .confirm("missing-tool", "allow_once".to_owned(), "conv-1")
            .expect_err("missing permission should fail");

        assert!(
            error
                .to_string()
                .contains("Pending ACP permission not found: missing-tool")
        );
    }

    #[test]
    fn cancel_all_removes_pending_confirmations() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, _response_rx) = oneshot::channel();
        router.insert_pending_for_test("tool-1".to_owned(), response_tx, sample_confirmation("tool-1"));

        router.cancel_all();

        assert!(router.get_confirmations().is_empty());
    }

    #[tokio::test]
    async fn start_routes_permission_request_and_exposes_recoverable_confirmation() {
        let (permission_tx, permission_rx) = mpsc::channel(1);
        let router = Arc::new(PermissionRouter::new(permission_rx));
        let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
        let mut event_rx = runtime.subscribe();
        router.start(runtime, Weak::new(), None);

        let request = RequestPermissionRequest::new(
            "session-1",
            SdkToolCallUpdate::new(
                "tool-1",
                ToolCallUpdateFields::new()
                    .title("Write file")
                    .kind(SdkToolKind::Edit)
                    .raw_input(json!({ "description": "Write /tmp/current_time.txt" })),
            ),
            vec![PermissionOption::new(
                "allow_once",
                "Allow",
                SdkPermissionOptionKind::AllowOnce,
            )],
        );
        let (response_tx, mut response_rx) = oneshot::channel();

        permission_tx
            .send(PermissionRequest { request, response_tx })
            .await
            .expect("permission request should be accepted");

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .expect("permission event should be emitted")
            .expect("permission event channel should stay open");
        assert!(matches!(event, AgentStreamEvent::AcpPermission(_)));

        let confirmations = router.get_confirmations();
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].id, "tool-1");
        assert_eq!(confirmations[0].call_id, "tool-1");
        assert_eq!(confirmations[0].command_type.as_deref(), Some("edit"));

        router
            .confirm("tool-1", "allow_once".to_owned(), "conv-1")
            .expect("confirm should resolve routed request");

        assert!(router.get_confirmations().is_empty());
        assert!(matches!(
            response_rx.try_recv(),
            Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
        ));
    }

    #[tokio::test]
    async fn start_auto_approves_team_mcp_with_existing_option_id() {
        let (permission_tx, permission_rx) = mpsc::channel(1);
        let router = Arc::new(PermissionRouter::new(permission_rx));
        let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
        router.start(runtime, Weak::new(), None);

        let request = permission_request_with_title_and_raw_input(
            "Approve MCP tool call",
            Some(json!({ "server_name": "aionui-team" })),
            vec![
                allow_once_option("approved"),
                allow_always_option("approved-for-session"),
                reject_option("cancel"),
            ],
        );
        let (response_tx, response_rx) = oneshot::channel();

        permission_tx
            .send(PermissionRequest { request, response_tx })
            .await
            .expect("permission request should be accepted");

        let decision = tokio::time::timeout(Duration::from_secs(1), response_rx)
            .await
            .expect("auto approval should respond")
            .expect("auto approval responder should stay open");

        assert!(matches!(
            decision,
            PermissionDecision::Selected { option_id } if option_id == "approved-for-session"
        ));
        assert!(router.get_confirmations().is_empty());
    }
}
