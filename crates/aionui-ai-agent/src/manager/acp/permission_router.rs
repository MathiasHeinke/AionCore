use crate::agent_runtime::AgentRuntime;
use crate::agent_task::{ConfirmationAuthorityLevel, ConfirmationPrincipalContext};
use crate::error::AgentError;
use crate::protocol::acp::{PermissionDecision, PermissionRequest};
use crate::protocol::events::{
    AcpPermissionEventData, AcpPermissionOptionKind, AgentStreamEvent, attach_confirmation_authority_metadata,
    permission_request_to_event_data,
};
use agent_client_protocol::schema::{
    PermissionOption as SdkPermissionOption, PermissionOptionKind as SdkPermissionOptionKind, RequestPermissionRequest,
    ToolKind as SdkToolKind,
};
use aionui_api_types::TEAM_MCP_SERVER_NAME;
use aionui_common::{Confirmation, ConfirmationAuthorityMetadata};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Barrier;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, info, warn};

use super::AcpAgentManager;
use super::permission_authority::{
    COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION, CommandEveCapabilities, DecisionInput, OperationClass,
    PermissionDecision as AuthorityDecision, PermissionMode, PolicySnapshot, RequiredAuthority, TrustedClassification,
    classify_request, decide,
};

const TEAM_GUIDE_MCP_SERVER_NAME: &str = "aionui-team-guide";
const AUTO_APPROVE_MCP_SERVERS: &[&str] = &[TEAM_MCP_SERVER_NAME, TEAM_GUIDE_MCP_SERVER_NAME];
const HERMES_BACKEND: &str = "hermes";
const HERMES_EDIT_PERMISSION_TTL: Duration = Duration::from_secs(60);
const HERMES_COMMAND_PERMISSION_TTL: Duration = Duration::from_secs(300);
const CONFIRMATION_ACTION_EXPIRED: &str = "expired";
const CONFIRMATION_ACTION_CANCELLED: &str = "cancelled";
const CONFIRMATION_ACTION_SUPERSEDED: &str = "superseded";
const CONFIRMATION_ACTION_ALLOWED: &str = "allowed";
const CONFIRMATION_ACTION_DENIED: &str = "denied";
const EXACT_SESSION_GRANT_TTL: Duration = Duration::from_secs(30 * 60);
const EXACT_SESSION_GRANT_LABEL: &str = "Allow this exact request for 30 minutes (this session)";
const MAX_TERMINAL_CONFIRMATION_HISTORY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionDisposition {
    AllowOnce,
    ExactSession,
    RejectOnce,
    UnsupportedPermanent,
}

#[derive(Debug, Clone)]
struct CommandEveAuthority {
    operation_digest: String,
    policy: Option<PolicySnapshot>,
    classification: TrustedClassification,
    decision: AuthorityDecision,
    grant_eligible: bool,
    authority_nonce: Option<String>,
    allow_once_option_id: Option<String>,
    reject_once_option_id: Option<String>,
    option_dispositions: HashMap<String, OptionDisposition>,
}

#[derive(Debug, Clone)]
struct SessionGrant {
    operation_digest: String,
    policy_revision: u64,
    session_epoch: u64,
    expires_at: Instant,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthorityReceipt {
    pub protocol_version: u32,
    pub operation_digest: String,
    pub required_level: RequiredAuthority,
    pub principal: String,
    pub policy_revision: u64,
    pub session_epoch: u64,
    pub decision: AuthorityReceiptDecision,
    pub expires_at_ms: u64,
    pub single_use_nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthorityReceiptDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmationResponseResult {
    Applied,
    IdempotentSameDecision,
    ConflictDifferentDecision,
    Expired,
    UnknownConfirmation,
    WrongSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmationLifecycle {
    Pending,
    Allowed,
    Denied,
    Expired,
    Cancelled,
    Superseded,
}

impl ConfirmationLifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }
}

struct PendingPermission {
    responder: Option<oneshot::Sender<PermissionDecision>>,
    confirmation: Confirmation,
    command_eve: Option<CommandEveAuthority>,
    expires_at: Option<Instant>,
    created_at_ms: u64,
    expires_at_ms: Option<u64>,
    confirmation_version: u64,
    lifecycle: ConfirmationLifecycle,
    decided_option: Option<String>,
    authority_receipt: Option<AuthorityReceipt>,
    nonce: u64,
    runtime: AgentRuntime,
}

#[cfg(test)]
struct PolicyRaceHook {
    entered: Barrier,
    release: Barrier,
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
    session_grants: StdMutex<HashMap<String, SessionGrant>>,
    /// Synchronous projection of the authoritative snapshot owned by
    /// `AcpSession`; used to make multiwindow confirmation responses atomic.
    current_policy: StdMutex<Option<PolicySnapshot>>,
    /// Linearizes policy changes with every side-effect-producing permission
    /// decision. One-shot responder sends are nonblocking, so this guard never
    /// spans an await or external runtime wait.
    policy_linearization: StdMutex<()>,
    #[cfg(test)]
    policy_race_hook: StdMutex<Option<Arc<PolicyRaceHook>>>,
    used_authority_nonces: StdMutex<HashSet<String>>,
    next_nonce: AtomicU64,
    next_confirmation_version: AtomicU64,
    /// Whether a graceful shutdown is in progress.
    closing: AtomicBool,
}

impl PermissionRouter {
    /// Create a new permission router.
    pub fn new(permission_rx: mpsc::Receiver<PermissionRequest>) -> Self {
        Self {
            permission_rx: Mutex::new(permission_rx),
            pending_permissions: StdMutex::new(HashMap::new()),
            session_grants: StdMutex::new(HashMap::new()),
            current_policy: StdMutex::new(None),
            policy_linearization: StdMutex::new(()),
            #[cfg(test)]
            policy_race_hook: StdMutex::new(None),
            used_authority_nonces: StdMutex::new(HashSet::new()),
            next_nonce: AtomicU64::new(1),
            next_confirmation_version: AtomicU64::new(1),
            closing: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn install_policy_race_hook(&self) -> Arc<PolicyRaceHook> {
        let hook = Arc::new(PolicyRaceHook {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        });
        *self.policy_race_hook.lock().unwrap() = Some(Arc::clone(&hook));
        hook
    }

    #[cfg(test)]
    fn wait_policy_race_hook(&self) {
        let hook = self.policy_race_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook.entered.wait();
            hook.release.wait();
        }
    }

    #[cfg(not(test))]
    fn wait_policy_race_hook(&self) {}

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

            while let Some(mut perm_req) = rx.recv().await {
                runtime.bump_activity();

                let call_id = perm_req.request.tool_call.tool_call_id.to_string();
                let mut command_eve =
                    command_eve_authority(&manager, backend.as_deref(), &runtime, &perm_req.request).await;

                // Shared ACP backends keep their historical internal-team MCP
                // behavior. Command EVE must always pass through the C7 engine.
                let team_auto_approve_option = command_eve
                    .is_none()
                    .then(|| auto_approve_option_id(&perm_req.request))
                    .flatten();
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

                if let Some(authority) = command_eve.as_mut() {
                    let exact_grant = this.has_valid_session_grant(authority);
                    authority.decision = decide_command_eve(authority, exact_grant);

                    match authority.decision {
                        AuthorityDecision::Allow => {
                            let mut responder = Some(perm_req.response_tx);
                            if this.resolve_command_eve_auto_allow(
                                &runtime,
                                &perm_req.request,
                                authority,
                                exact_grant,
                                &mut responder,
                            ) {
                                continue;
                            }
                            perm_req.response_tx = responder
                                .take()
                                .expect("expired exact grant must retain the permission responder");
                            authority.decision = AuthorityDecision::Ask;
                        }
                        AuthorityDecision::Block => {
                            let decision = authority
                                .reject_once_option_id
                                .clone()
                                .map(|option_id| PermissionDecision::Selected { option_id })
                                .unwrap_or(PermissionDecision::Cancelled);
                            let created_at_ms = now_epoch_ms();
                            let confirmation_version = this.next_confirmation_version.fetch_add(1, Ordering::Relaxed);
                            emit_terminal_decision(
                                &runtime,
                                &perm_req.request,
                                authority,
                                confirmation_version,
                                created_at_ms,
                                CONFIRMATION_ACTION_DENIED,
                            );
                            info!(
                                conversation_id = %runtime.conversation_id(),
                                call_id,
                                classification = ?authority.classification.class,
                                "Command EVE permission blocked by AionCore authority"
                            );
                            let _ = perm_req.response_tx.send(decision);
                            continue;
                        }
                        AuthorityDecision::RequireAuthority(_) => {
                            authority.authority_nonce = Some(uuid::Uuid::new_v4().to_string());
                        }
                        AuthorityDecision::Ask
                        | AuthorityDecision::AskWithOwner(_)
                        | AuthorityDecision::Unsupported => {}
                    }
                }

                let nonce = this.next_nonce.fetch_add(1, Ordering::Relaxed);
                let ttl = command_eve.as_ref().map(|_| permission_ttl(&perm_req.request));
                let created_at_ms = now_epoch_ms();
                let expires_at_ms = ttl.map(|ttl| created_at_ms.saturating_add(ttl.as_millis() as u64));
                let confirmation_version = this.next_confirmation_version.fetch_add(1, Ordering::Relaxed);
                let mut permission_event = permission_request_to_event_data(&perm_req.request);
                if let Some(authority) = command_eve.as_ref() {
                    contain_command_eve_options(
                        &mut permission_event,
                        authority.grant_eligible
                            && authority.policy.is_some()
                            && authority.allow_once_option_id.is_some(),
                        authority,
                    );
                    if let Some(metadata) = build_authority_metadata(
                        authority,
                        &call_id,
                        confirmation_version,
                        created_at_ms,
                        expires_at_ms.unwrap_or(created_at_ms),
                        ConfirmationLifecycle::Pending,
                    ) {
                        attach_confirmation_authority_metadata(&mut permission_event, &metadata);
                    }
                }
                let confirmation = permission_event
                    .as_confirmation()
                    .expect("ACP permission events must be recoverable as confirmations");

                let mut pending = this.pending_permissions.lock().unwrap();
                if let Some(previous) = pending.insert(
                    call_id.clone(),
                    PendingPermission {
                        responder: Some(perm_req.response_tx),
                        confirmation,
                        command_eve,
                        expires_at: ttl.map(|ttl| Instant::now() + ttl),
                        created_at_ms,
                        expires_at_ms,
                        confirmation_version,
                        lifecycle: ConfirmationLifecycle::Pending,
                        decided_option: None,
                        authority_receipt: None,
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

    fn resolve_command_eve_auto_allow(
        &self,
        runtime: &AgentRuntime,
        request: &RequestPermissionRequest,
        authority: &CommandEveAuthority,
        exact_grant: bool,
        responder: &mut Option<oneshot::Sender<PermissionDecision>>,
    ) -> bool {
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        self.wait_policy_race_hook();
        let policy_is_current = authority
            .policy
            .as_ref()
            .is_some_and(|policy| self.current_policy.lock().unwrap().as_ref() == Some(policy));
        if !policy_is_current {
            let created_at_ms = now_epoch_ms();
            let confirmation_version = self.next_confirmation_version.fetch_add(1, Ordering::Relaxed);
            emit_terminal_decision(
                runtime,
                request,
                authority,
                confirmation_version,
                created_at_ms,
                CONFIRMATION_ACTION_SUPERSEDED,
            );
            if let Some(responder) = responder.take() {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
            return true;
        }
        if exact_grant && !self.has_valid_session_grant(authority) {
            info!(
                conversation_id = %runtime.conversation_id(),
                call_id = %request.tool_call.tool_call_id,
                policy_revision = authority.policy.as_ref().map(|policy| policy.policy_revision),
                "Command EVE exact grant expired before side-effect dispatch; routing to visible Ask"
            );
            return false;
        }
        let decision = authority
            .allow_once_option_id
            .clone()
            .map(|option_id| PermissionDecision::Selected { option_id })
            .unwrap_or(PermissionDecision::Cancelled);
        info!(
            conversation_id = %runtime.conversation_id(),
            call_id = %request.tool_call.tool_call_id,
            policy_revision = authority.policy.as_ref().map(|policy| policy.policy_revision),
            classification = ?authority.classification.class,
            exact_grant,
            "Command EVE permission allowed by AionCore authority"
        );
        if let Some(responder) = responder.take() {
            let _ = responder.send(decision);
        }
        true
    }

    /// Pending permission items recoverable by conversation confirmation APIs.
    pub fn get_confirmations(&self) -> Vec<Confirmation> {
        self.expire_due_permissions();
        self.pending_permissions
            .lock()
            .unwrap()
            .values()
            .filter(|pending| {
                !matches!(
                    pending.lifecycle,
                    ConfirmationLifecycle::Allowed | ConfirmationLifecycle::Denied
                )
            })
            .map(|pending| pending.confirmation.clone())
            .collect()
    }

    /// Resolve a pending permission request with the user's selected option.
    pub fn confirm(&self, call_id: &str, option_id: String, conversation_id: &str) -> Result<(), AgentError> {
        match self.confirm_result(call_id, option_id, conversation_id) {
            ConfirmationResponseResult::Applied | ConfirmationResponseResult::IdempotentSameDecision => Ok(()),
            ConfirmationResponseResult::ConflictDifferentDecision => Err(AgentError::conflict(format!(
                "ACP permission already resolved with a different decision: {call_id}"
            ))),
            ConfirmationResponseResult::Expired => Err(AgentError::bad_request(format!(
                "Pending ACP permission expired: {call_id}"
            ))),
            ConfirmationResponseResult::UnknownConfirmation => Err(AgentError::bad_request(format!(
                "Pending ACP permission not found: {call_id}"
            ))),
            ConfirmationResponseResult::WrongSession => Err(AgentError::bad_request(format!(
                "Pending ACP permission belongs to a different session: {call_id}"
            ))),
        }
    }

    pub(crate) fn confirm_result(
        &self,
        call_id: &str,
        option_id: String,
        conversation_id: &str,
    ) -> ConfirmationResponseResult {
        self.expire_due_permissions();
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        self.wait_policy_race_hook();

        let (responder, forwarded_option_id, grant) = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let Some(pending) = permissions.get_mut(call_id) else {
                return ConfirmationResponseResult::UnknownConfirmation;
            };
            if pending.runtime.conversation_id() != conversation_id {
                return ConfirmationResponseResult::WrongSession;
            }
            match pending.lifecycle {
                ConfirmationLifecycle::Expired => return ConfirmationResponseResult::Expired,
                ConfirmationLifecycle::Allowed | ConfirmationLifecycle::Denied => {
                    return if pending.decided_option.as_deref() == Some(option_id.as_str()) {
                        ConfirmationResponseResult::IdempotentSameDecision
                    } else {
                        ConfirmationResponseResult::ConflictDifferentDecision
                    };
                }
                ConfirmationLifecycle::Cancelled | ConfirmationLifecycle::Superseded => {
                    return ConfirmationResponseResult::ConflictDifferentDecision;
                }
                ConfirmationLifecycle::Pending => {}
            }

            let (forwarded_option_id, grant) = if let Some(authority) = pending.command_eve.as_ref() {
                if let Some(policy) = authority.policy.as_ref()
                    && self.current_policy.lock().unwrap().as_ref() != Some(policy)
                {
                    transition_confirmation(
                        pending,
                        self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                        ConfirmationLifecycle::Superseded,
                        CONFIRMATION_ACTION_SUPERSEDED,
                    );
                    if let Some(responder) = pending.responder.take() {
                        let _ = responder.send(PermissionDecision::Cancelled);
                    }
                    pending
                        .runtime
                        .emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                            pending.confirmation.clone(),
                        )));
                    drop(permissions);
                    self.prune_terminal_history();
                    return ConfirmationResponseResult::ConflictDifferentDecision;
                }
                match authority.option_dispositions.get(&option_id) {
                    Some(OptionDisposition::AllowOnce)
                        if matches!(
                            authority.decision,
                            AuthorityDecision::RequireAuthority(_)
                                | AuthorityDecision::Block
                                | AuthorityDecision::Unsupported
                        ) =>
                    {
                        return ConfirmationResponseResult::ConflictDifferentDecision;
                    }
                    Some(OptionDisposition::AllowOnce | OptionDisposition::RejectOnce) => (option_id.clone(), None),
                    Some(OptionDisposition::ExactSession) => {
                        if !authority.grant_eligible {
                            return ConfirmationResponseResult::ConflictDifferentDecision;
                        }
                        let Some(allow_once) = authority.allow_once_option_id.clone() else {
                            return ConfirmationResponseResult::ConflictDifferentDecision;
                        };
                        let Some(policy) = authority.policy.as_ref() else {
                            return ConfirmationResponseResult::ConflictDifferentDecision;
                        };
                        (
                            allow_once,
                            Some(SessionGrant {
                                operation_digest: authority.operation_digest.clone(),
                                policy_revision: policy.policy_revision,
                                session_epoch: policy.session_epoch,
                                expires_at: Instant::now() + EXACT_SESSION_GRANT_TTL,
                                revoked: false,
                            }),
                        )
                    }
                    Some(OptionDisposition::UnsupportedPermanent) => {
                        return ConfirmationResponseResult::ConflictDifferentDecision;
                    }
                    None => return ConfirmationResponseResult::ConflictDifferentDecision,
                }
            } else {
                (option_id.clone(), None)
            };

            let responder = match pending.responder.take() {
                Some(responder) => responder,
                None => return ConfirmationResponseResult::Expired,
            };
            let lifecycle = if pending
                .command_eve
                .as_ref()
                .and_then(|authority| authority.option_dispositions.get(&option_id))
                == Some(&OptionDisposition::RejectOnce)
            {
                ConfirmationLifecycle::Denied
            } else {
                ConfirmationLifecycle::Allowed
            };
            pending.decided_option = Some(option_id.clone());
            transition_confirmation(
                pending,
                self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                lifecycle,
                if lifecycle == ConfirmationLifecycle::Denied {
                    CONFIRMATION_ACTION_DENIED
                } else {
                    CONFIRMATION_ACTION_ALLOWED
                },
            );
            debug!(
                conversation_id,
                call_id,
                confirmation_version = pending.confirmation_version,
                policy_revision = pending
                    .command_eve
                    .as_ref()
                    .and_then(|authority| authority.policy.as_ref().map(|policy| policy.policy_revision)),
                session_epoch = pending
                    .command_eve
                    .as_ref()
                    .and_then(|authority| authority.policy.as_ref().map(|policy| policy.session_epoch)),
                decision_latency_ms = now_epoch_ms().saturating_sub(pending.created_at_ms),
                expires_at_ms = pending.expires_at_ms,
                "ACP permission decision applied"
            );
            (responder, forwarded_option_id, grant)
        };

        if responder
            .send(PermissionDecision::Selected {
                option_id: forwarded_option_id,
            })
            .is_err()
        {
            self.mark_history_expired(call_id);
            return ConfirmationResponseResult::Expired;
        }

        if let Some(grant) = grant {
            self.session_grants
                .lock()
                .unwrap()
                .insert(grant.operation_digest.clone(), grant);
        }

        self.prune_terminal_history();

        ConfirmationResponseResult::Applied
    }

    /// Resolve the separate HG-3.5/HG-4 challenge from an authenticated
    /// server principal. The renderer supplies only the user's decision; the
    /// principal and authority level come from ConversationService.
    pub(crate) fn confirm_authority_as(
        &self,
        call_id: &str,
        conversation_id: &str,
        principal: &ConfirmationPrincipalContext,
    ) -> Result<ConfirmationResponseResult, AgentError> {
        self.expire_due_permissions();
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        self.wait_policy_race_hook();

        let (responder, option_id, receipt) = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let Some(pending) = permissions.get_mut(call_id) else {
                return Ok(ConfirmationResponseResult::UnknownConfirmation);
            };
            if pending.runtime.conversation_id() != conversation_id {
                return Ok(ConfirmationResponseResult::WrongSession);
            }
            match pending.lifecycle {
                ConfirmationLifecycle::Expired => return Ok(ConfirmationResponseResult::Expired),
                ConfirmationLifecycle::Allowed => {
                    return Ok(
                        if pending.authority_receipt.as_ref().is_some_and(|receipt| {
                            receipt.decision == AuthorityReceiptDecision::Allow
                                && receipt.principal == principal.principal_id()
                        }) {
                            ConfirmationResponseResult::IdempotentSameDecision
                        } else {
                            ConfirmationResponseResult::ConflictDifferentDecision
                        },
                    );
                }
                ConfirmationLifecycle::Denied
                | ConfirmationLifecycle::Cancelled
                | ConfirmationLifecycle::Superseded => {
                    return Ok(ConfirmationResponseResult::ConflictDifferentDecision);
                }
                ConfirmationLifecycle::Pending => {}
            }

            let Some(authority) = pending.command_eve.as_ref() else {
                return Err(AgentError::bad_request(
                    "Authority receipts are only valid for Command EVE requests",
                ));
            };
            let Some(required) = authority.classification.required_authority else {
                return Err(AgentError::bad_request(
                    "This operation has no HumanGate authority challenge",
                ));
            };
            if !matches!(required, RequiredAuthority::Proxy | RequiredAuthority::Founder)
                || !matches!(authority.decision, AuthorityDecision::RequireAuthority(_))
            {
                return Err(AgentError::bad_request(
                    "This operation does not require an HG-3.5/HG-4 receipt",
                ));
            }
            let Some(policy) = authority.policy.clone() else {
                return Err(AgentError::conflict(
                    "Authority challenge has no acknowledged policy snapshot",
                ));
            };
            if self.current_policy.lock().unwrap().as_ref() != Some(&policy) {
                transition_confirmation(
                    pending,
                    self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                    ConfirmationLifecycle::Superseded,
                    CONFIRMATION_ACTION_SUPERSEDED,
                );
                if let Some(responder) = pending.responder.take() {
                    let _ = responder.send(PermissionDecision::Cancelled);
                }
                pending
                    .runtime
                    .emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                        pending.confirmation.clone(),
                    )));
                drop(permissions);
                self.prune_terminal_history();
                return Ok(ConfirmationResponseResult::ConflictDifferentDecision);
            }
            if principal_authority_rank(principal.authority()) < required.rank() {
                return Err(AgentError::forbidden(format!(
                    "Principal '{}' does not satisfy the required authority level",
                    principal.principal_id()
                )));
            }
            let nonce = authority
                .authority_nonce
                .as_ref()
                .ok_or_else(|| AgentError::conflict("Authority challenge nonce is missing"))?;
            let option_id = authority
                .allow_once_option_id
                .clone()
                .ok_or_else(|| AgentError::conflict("Authority-approved operation has no one-shot runtime option"))?;
            let expires_at_ms = pending
                .expires_at_ms
                .ok_or_else(|| AgentError::conflict("Authority challenge has no server expiry"))?;
            if expires_at_ms <= now_epoch_ms() {
                return Ok(ConfirmationResponseResult::Expired);
            }
            if pending.responder.is_none() {
                return Err(AgentError::conflict(
                    "Authority challenge responder is no longer active",
                ));
            }

            let mut receipt = AuthorityReceipt {
                protocol_version: COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION,
                operation_digest: authority.operation_digest.clone(),
                required_level: required,
                principal: principal.principal_id().to_owned(),
                policy_revision: policy.policy_revision,
                session_epoch: policy.session_epoch,
                decision: AuthorityReceiptDecision::Allow,
                expires_at_ms,
                single_use_nonce: nonce.clone(),
                signature: String::new(),
            };
            // This proof is minted inside the authenticated service boundary;
            // it is never accepted from renderer JSON. The digest makes the
            // immutable receipt auditable without logging operation content.
            receipt.signature = format!(
                "local:{}",
                hex::encode(Sha256::digest(authority_receipt_payload(&receipt)))
            );

            // Consume the nonce only after every fallible binding/TTL/responder
            // check has passed. The pending map lock makes the following take
            // infallible, so a failed attempt cannot strand the challenge.
            {
                let mut used_nonces = self.used_authority_nonces.lock().unwrap();
                if !used_nonces.insert(nonce.clone()) {
                    return Ok(ConfirmationResponseResult::ConflictDifferentDecision);
                }
            }

            let responder = pending
                .responder
                .take()
                .expect("responder checked while holding pending permission lock");
            pending.decided_option = Some("command_eve_authority_allow".to_owned());
            pending.authority_receipt = Some(receipt.clone());
            transition_confirmation(
                pending,
                self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                ConfirmationLifecycle::Allowed,
                CONFIRMATION_ACTION_ALLOWED,
            );
            (responder, option_id, receipt)
        };

        if responder
            .send(PermissionDecision::Selected {
                option_id: option_id.clone(),
            })
            .is_err()
        {
            self.mark_history_expired(call_id);
            return Ok(ConfirmationResponseResult::Expired);
        }
        info!(
            conversation_id,
            call_id,
            principal = %receipt.principal,
            required_level = ?receipt.required_level,
            policy_revision = receipt.policy_revision,
            session_epoch = receipt.session_epoch,
            "Command EVE authority receipt verified; resumed exact operation once"
        );
        self.prune_terminal_history();
        Ok(ConfirmationResponseResult::Applied)
    }

    pub(crate) fn apply_policy_snapshot(&self, snapshot: PolicySnapshot) {
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        let changed = {
            let mut current = self.current_policy.lock().unwrap();
            if current.as_ref() == Some(&snapshot) {
                false
            } else {
                *current = Some(snapshot.clone());
                true
            }
        };
        if !changed {
            return;
        }

        self.session_grants.lock().unwrap().retain(|_, grant| {
            !grant.revoked
                && grant.expires_at > Instant::now()
                && grant.policy_revision == snapshot.policy_revision
                && grant.session_epoch == snapshot.session_epoch
        });

        let superseded = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            permissions
                .iter_mut()
                .filter_map(|(call_id, pending)| {
                    let policy = pending.command_eve.as_ref()?.policy.as_ref()?;
                    if pending.lifecycle != ConfirmationLifecycle::Pending || policy == &snapshot {
                        return None;
                    }
                    transition_confirmation(
                        pending,
                        self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                        ConfirmationLifecycle::Superseded,
                        CONFIRMATION_ACTION_SUPERSEDED,
                    );
                    Some((
                        call_id.clone(),
                        pending.responder.take(),
                        pending.confirmation.clone(),
                        pending.runtime.clone(),
                    ))
                })
                .collect::<Vec<_>>()
        };
        for (call_id, responder, confirmation, runtime) in superseded {
            if let Some(responder) = responder {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
            info!(
                conversation_id = %runtime.conversation_id(),
                call_id,
                policy_revision = snapshot.policy_revision,
                session_epoch = snapshot.session_epoch,
                "Pending Command EVE permission superseded by policy change"
            );
        }
        self.prune_terminal_history();
    }

    pub(crate) fn revoke_command_eve_policy(&self, reason: &'static str) {
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        self.revoke_command_eve_policy_locked(reason);
    }

    /// Atomically order a session SetPolicy transition against every
    /// side-effect-producing permission decision. The transition closure runs
    /// while the router linearization is held; authority is revoked even when
    /// validation fails, so no old policy can survive a rejected request.
    pub(crate) fn begin_command_eve_policy_change<T, E>(
        &self,
        transition: impl FnOnce() -> Result<T, E>,
        reason: &'static str,
    ) -> Result<T, E> {
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        let result = transition();
        self.revoke_command_eve_policy_locked(reason);
        result
    }

    fn revoke_command_eve_policy_locked(&self, reason: &'static str) {
        *self.current_policy.lock().unwrap() = None;
        self.session_grants.lock().unwrap().clear();
        let superseded = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            permissions
                .iter_mut()
                .filter_map(|(call_id, pending)| {
                    if pending.command_eve.is_none() || pending.lifecycle != ConfirmationLifecycle::Pending {
                        return None;
                    }
                    transition_confirmation(
                        pending,
                        self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                        ConfirmationLifecycle::Superseded,
                        CONFIRMATION_ACTION_SUPERSEDED,
                    );
                    Some((
                        call_id.clone(),
                        pending.responder.take(),
                        pending.confirmation.clone(),
                        pending.runtime.clone(),
                    ))
                })
                .collect::<Vec<_>>()
        };
        for (call_id, responder, confirmation, runtime) in superseded {
            if let Some(responder) = responder {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
            warn!(
                conversation_id = %runtime.conversation_id(),
                call_id,
                reason,
                "Command EVE permission superseded because authority was revoked"
            );
        }
        self.prune_terminal_history();
    }

    fn has_valid_session_grant(&self, authority: &CommandEveAuthority) -> bool {
        let Some(policy) = authority.policy.as_ref() else {
            return false;
        };
        let now = Instant::now();
        let mut grants = self.session_grants.lock().unwrap();
        grants.retain(|_, grant| !grant.revoked && grant.expires_at > now);
        grants.get(&authority.operation_digest).is_some_and(|grant| {
            authority.grant_eligible
                && grant.policy_revision == policy.policy_revision
                && grant.session_epoch == policy.session_epoch
        })
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
            transition_confirmation(
                pending,
                self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                ConfirmationLifecycle::Expired,
                CONFIRMATION_ACTION_EXPIRED,
            );
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
        self.prune_terminal_history();
    }

    fn mark_history_expired(&self, call_id: &str) {
        let history = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let Some(pending) = permissions.get_mut(call_id) else {
                return;
            };
            transition_confirmation(
                pending,
                self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                ConfirmationLifecycle::Expired,
                CONFIRMATION_ACTION_EXPIRED,
            );
            pending.responder = None;
            Some((pending.confirmation.clone(), pending.runtime.clone()))
        };
        if let Some((confirmation, runtime)) = history {
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
            warn!(
                conversation_id = %runtime.conversation_id(),
                call_id,
                "ACP permission responder was no longer active; recorded as expired"
            );
        }
        self.prune_terminal_history();
    }

    /// Cancel all pending permission requests. Called during `stop()` and `kill()`.
    pub fn cancel_all(&self) {
        let _policy_linearization = self.policy_linearization.lock().unwrap();
        let cancelled = {
            let mut pending_permissions = self.pending_permissions.lock().unwrap();
            pending_permissions
                .values_mut()
                .filter_map(|pending| {
                    if pending.lifecycle != ConfirmationLifecycle::Pending {
                        return None;
                    }
                    transition_confirmation(
                        pending,
                        self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                        ConfirmationLifecycle::Cancelled,
                        CONFIRMATION_ACTION_CANCELLED,
                    );
                    Some((
                        pending.responder.take(),
                        pending.confirmation.clone(),
                        pending.runtime.clone(),
                    ))
                })
                .collect::<Vec<_>>()
        };
        for (responder, confirmation, runtime) in cancelled {
            if let Some(responder) = responder {
                let _ = responder.send(PermissionDecision::Cancelled);
            }
            runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                confirmation,
            )));
        }
        self.session_grants.lock().unwrap().clear();
        *self.current_policy.lock().unwrap() = None;
        self.used_authority_nonces.lock().unwrap().clear();
        self.prune_terminal_history();
    }

    fn prune_terminal_history(&self) {
        let removed_nonces = {
            let mut permissions = self.pending_permissions.lock().unwrap();
            let terminal_count = permissions
                .values()
                .filter(|pending| pending.lifecycle != ConfirmationLifecycle::Pending)
                .count();
            if terminal_count <= MAX_TERMINAL_CONFIRMATION_HISTORY {
                return;
            }
            let mut candidates = permissions
                .iter()
                .filter_map(|(call_id, pending)| {
                    (pending.lifecycle != ConfirmationLifecycle::Pending).then_some((
                        call_id.clone(),
                        !matches!(
                            pending.lifecycle,
                            ConfirmationLifecycle::Allowed | ConfirmationLifecycle::Denied
                        ),
                        pending.confirmation_version,
                    ))
                })
                .collect::<Vec<_>>();
            // Allowed/Denied are invisible and prune first; within each class,
            // oldest versions prune first so recent replay/visible history wins.
            candidates.sort_by_key(|(_, visible, version)| (*visible, *version));
            candidates
                .into_iter()
                .take(terminal_count - MAX_TERMINAL_CONFIRMATION_HISTORY)
                .filter_map(|(call_id, _, _)| {
                    permissions
                        .remove(&call_id)
                        .and_then(|pending| pending.authority_receipt.map(|receipt| receipt.single_use_nonce))
                })
                .collect::<Vec<_>>()
        };
        if !removed_nonces.is_empty() {
            let mut nonces = self.used_authority_nonces.lock().unwrap();
            for nonce in removed_nonces {
                nonces.remove(&nonce);
            }
        }
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
                created_at_ms: now_epoch_ms(),
                expires_at_ms: None,
                confirmation_version: self.next_confirmation_version.fetch_add(1, Ordering::Relaxed),
                lifecycle: ConfirmationLifecycle::Pending,
                decided_option: None,
                authority_receipt: None,
                nonce: self.next_nonce.fetch_add(1, Ordering::Relaxed),
                runtime: AgentRuntime::new("conv-1", "/tmp/test-workspace", 8),
            },
        );
    }

    #[cfg(test)]
    fn insert_command_eve_pending_for_test(
        &self,
        call_id: String,
        responder: oneshot::Sender<PermissionDecision>,
        mut confirmation: Confirmation,
        command_eve: CommandEveAuthority,
        expires_at: Option<Instant>,
        runtime: AgentRuntime,
    ) {
        if let Some(policy) = command_eve.policy.clone() {
            self.apply_policy_snapshot(policy);
        }
        let created_at_ms = now_epoch_ms();
        let expires_at_ms = expires_at
            .map(|deadline| {
                created_at_ms.saturating_add(deadline.saturating_duration_since(Instant::now()).as_millis() as u64)
            })
            .unwrap_or(created_at_ms);
        let confirmation_version = self.next_confirmation_version.fetch_add(1, Ordering::Relaxed);
        confirmation.authority = build_authority_metadata(
            &command_eve,
            &call_id,
            confirmation_version,
            created_at_ms,
            expires_at_ms,
            ConfirmationLifecycle::Pending,
        );
        self.pending_permissions.lock().unwrap().insert(
            call_id,
            PendingPermission {
                responder: Some(responder),
                confirmation,
                command_eve: Some(command_eve),
                expires_at,
                created_at_ms,
                expires_at_ms: Some(expires_at_ms),
                confirmation_version,
                lifecycle: ConfirmationLifecycle::Pending,
                decided_option: None,
                authority_receipt: None,
                nonce: self.next_nonce.fetch_add(1, Ordering::Relaxed),
                runtime,
            },
        );
    }
}

fn principal_authority_rank(level: ConfirmationAuthorityLevel) -> u8 {
    match level {
        ConfirmationAuthorityLevel::User => 1,
        ConfirmationAuthorityLevel::Proxy => 2,
        ConfirmationAuthorityLevel::Founder => 3,
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_authority_metadata(
    authority: &CommandEveAuthority,
    operation_id: &str,
    confirmation_version: u64,
    created_at_ms: u64,
    expires_at_ms: u64,
    lifecycle: ConfirmationLifecycle,
) -> Option<ConfirmationAuthorityMetadata> {
    let policy = authority.policy.as_ref()?;
    Some(ConfirmationAuthorityMetadata {
        protocol_version: COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION,
        operation_id: operation_id.to_owned(),
        operation_digest: authority.operation_digest.clone(),
        confirmation_version,
        policy_revision: policy.policy_revision,
        session_epoch: policy.session_epoch,
        created_at_ms,
        expires_at_ms,
        lifecycle: lifecycle.as_str().to_owned(),
        classification: operation_class_name(authority.classification.class).to_owned(),
        required_authority: authority
            .classification
            .required_authority
            .map(required_authority_name)
            .map(str::to_owned),
        runtime_receipt_digest: policy.runtime_receipt.receipt_digest.clone(),
    })
}

fn operation_class_name(classification: OperationClass) -> &'static str {
    match classification {
        OperationClass::RoutineEdit => "routine_edit",
        OperationClass::RoutineTerminal => "routine_terminal",
        OperationClass::HardBlocked => "hard_blocked",
        OperationClass::Sensitive => "sensitive",
        OperationClass::Hg35 => "hg35",
        OperationClass::Hg4 => "hg4",
        OperationClass::Unknown => "unknown",
    }
}

fn required_authority_name(authority: RequiredAuthority) -> &'static str {
    match authority {
        RequiredAuthority::User => "user",
        RequiredAuthority::Proxy => "proxy",
        RequiredAuthority::Founder => "founder",
    }
}

fn transition_confirmation(
    pending: &mut PendingPermission,
    confirmation_version: u64,
    lifecycle: ConfirmationLifecycle,
    action: &str,
) {
    pending.lifecycle = lifecycle;
    pending.confirmation_version = confirmation_version;
    pending.confirmation.action = Some(action.to_owned());
    pending.confirmation.options.clear();
    if let Some(metadata) = pending.confirmation.authority.as_mut() {
        metadata.confirmation_version = confirmation_version;
        metadata.lifecycle = lifecycle.as_str().to_owned();
    }
}

fn emit_terminal_decision(
    runtime: &AgentRuntime,
    request: &RequestPermissionRequest,
    authority: &CommandEveAuthority,
    confirmation_version: u64,
    created_at_ms: u64,
    action: &str,
) {
    let mut event = permission_request_to_event_data(request);
    contain_command_eve_options(&mut event, false, authority);
    let lifecycle = match action {
        CONFIRMATION_ACTION_DENIED => ConfirmationLifecycle::Denied,
        CONFIRMATION_ACTION_SUPERSEDED => ConfirmationLifecycle::Superseded,
        CONFIRMATION_ACTION_EXPIRED => ConfirmationLifecycle::Expired,
        _ => ConfirmationLifecycle::Cancelled,
    };
    if let Some(metadata) = build_authority_metadata(
        authority,
        &request.tool_call.tool_call_id.to_string(),
        confirmation_version,
        created_at_ms,
        created_at_ms,
        lifecycle,
    ) {
        attach_confirmation_authority_metadata(&mut event, &metadata);
    }
    if let Some(mut confirmation) = event.as_confirmation() {
        confirmation.action = Some(action.to_owned());
        confirmation.options.clear();
        runtime.emit(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
            confirmation,
        )));
    }
}

fn authority_receipt_payload(receipt: &AuthorityReceipt) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol_version": receipt.protocol_version,
        "operation_digest": receipt.operation_digest,
        "required_level": receipt.required_level,
        "principal": receipt.principal,
        "policy_revision": receipt.policy_revision,
        "session_epoch": receipt.session_epoch,
        "decision": receipt.decision,
        "expires_at_ms": receipt.expires_at_ms,
        "single_use_nonce": receipt.single_use_nonce,
    }))
    .unwrap_or_default()
}

fn decide_command_eve(authority: &CommandEveAuthority, exact_grant: bool) -> AuthorityDecision {
    let (mode, capabilities, exact_grant) = authority.policy.as_ref().map_or_else(
        || {
            (
                PermissionMode::Default,
                CommandEveCapabilities {
                    trusted_classification: true,
                    ..CommandEveCapabilities::default()
                },
                false,
            )
        },
        |policy| (policy.mode, policy.capabilities, exact_grant),
    );
    decide(DecisionInput {
        mode,
        classification: authority.classification,
        explicit_deny: false,
        exact_grant,
        authority_receipt_verified: false,
        capabilities,
    })
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
    let policy = if let Some(manager) = manager.upgrade() {
        let session = manager.session.read().await;
        match session.command_eve_permission_snapshot(&request.session_id.to_string()) {
            Ok(policy) => Some(policy),
            Err(error) => {
                warn!(
                    conversation_id = %runtime.conversation_id(),
                    error = %error,
                    "Command EVE permission has no valid turn policy lease; forcing visible Ask"
                );
                None
            }
        }
    } else {
        None
    };

    build_command_eve_authority(backend, policy, runtime.workspace(), request)
}

fn build_command_eve_authority(
    backend: Option<&str>,
    policy: Option<PolicySnapshot>,
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
    let reject_once_option_id = request
        .options
        .iter()
        .find(|option| matches!(option.kind, SdkPermissionOptionKind::RejectOnce))
        .map(|option| option.option_id.to_string());
    let option_dispositions = request
        .options
        .iter()
        .map(|option| (option.option_id.to_string(), command_eve_option_disposition(option)))
        .collect();
    let classification = classify_request(request, workspace);
    let operation_digest = operation_digest(workspace, HERMES_BACKEND, policy.as_ref(), classification, request);
    let grant_eligible = matches!(
        classification.class,
        OperationClass::RoutineEdit | OperationClass::RoutineTerminal
    );

    Some(CommandEveAuthority {
        operation_digest,
        policy,
        classification,
        decision: AuthorityDecision::Ask,
        grant_eligible,
        authority_nonce: None,
        allow_once_option_id,
        reject_once_option_id,
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

fn contain_command_eve_options(
    event: &mut AcpPermissionEventData,
    exact_session_available: bool,
    authority: &CommandEveAuthority,
) {
    let AcpPermissionEventData::Request(request) = event else {
        return;
    };
    let authority_only = matches!(authority.decision, AuthorityDecision::RequireAuthority(_));
    request.options.retain_mut(|option| match option.kind {
        AcpPermissionOptionKind::AllowOnce => !authority_only,
        AcpPermissionOptionKind::RejectOnce => true,
        AcpPermissionOptionKind::AllowAlways
            if exact_session_available && is_session_scoped_option(&option.option_id, &option.name) =>
        {
            option.name = EXACT_SESSION_GRANT_LABEL.to_owned();
            true
        }
        AcpPermissionOptionKind::AllowAlways | AcpPermissionOptionKind::RejectAlways => false,
    });
    if authority_only {
        request.options.insert(
            0,
            crate::protocol::events::AcpPermissionOptionData {
                option_id: "command_eve_authority_allow".to_owned(),
                name: "Approve with required authority".to_owned(),
                kind: AcpPermissionOptionKind::AllowOnce,
                meta: None,
            },
        );
    }

    match authority.classification.class {
        OperationClass::Unknown => {
            request.tool_call.title = Some(format!(
                "[classification=unknown] {}",
                request.tool_call.title.as_deref().unwrap_or("Permission required")
            ));
        }
        OperationClass::Hg35 | OperationClass::Hg4 => {
            let gate = if authority.classification.class == OperationClass::Hg4 {
                "HG-4 Founder"
            } else {
                "HG-3.5 proxy-or-higher"
            };
            request.tool_call.title = Some(format!(
                "[{gate} decision required] {}",
                request.tool_call.title.as_deref().unwrap_or("Permission required")
            ));
            if let Some(nonce) = authority.authority_nonce.as_deref() {
                let meta = request.tool_call.meta.get_or_insert_with(Default::default);
                meta.insert(
                    "command_eve_authority_challenge".to_owned(),
                    json!({
                        "protocol_version": COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION,
                        "required_level": authority.classification.required_authority,
                        "operation_digest": authority.operation_digest,
                        "policy_revision": authority.policy.as_ref().map(|policy| policy.policy_revision),
                        "session_epoch": authority.policy.as_ref().map(|policy| policy.session_epoch),
                        "single_use_nonce": nonce,
                    }),
                );
            }
        }
        _ => {}
    }
}

fn permission_ttl(request: &RequestPermissionRequest) -> Duration {
    if matches!(request.tool_call.fields.kind.as_ref(), Some(SdkToolKind::Edit)) {
        HERMES_EDIT_PERMISSION_TTL
    } else {
        HERMES_COMMAND_PERMISSION_TTL
    }
}

fn operation_digest(
    workspace: &str,
    backend: &str,
    policy: Option<&PolicySnapshot>,
    classification: TrustedClassification,
    request: &RequestPermissionRequest,
) -> String {
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
        "version": COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION,
        "backend": backend,
        "session_id": request.session_id.to_string(),
        "workspace": canonical_workspace(workspace),
        "policy_revision": policy.map(|policy| policy.policy_revision),
        "session_epoch": policy.map(|policy| policy.session_epoch),
        "mode": policy.map(|policy| policy.mode),
        "runtime_receipt_digest": policy.map(|policy| policy.runtime_receipt.receipt_digest.as_str()),
        "classification": classification.class,
        "required_authority": classification.required_authority,
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
        let policy = policy_for_test(super::super::permission_authority::PermissionMode::Default);
        CommandEveAuthority {
            operation_digest: grant_key.unwrap_or("digest-unavailable").to_owned(),
            policy: Some(policy),
            classification: TrustedClassification::new(OperationClass::RoutineEdit),
            decision: AuthorityDecision::Ask,
            grant_eligible: grant_key.is_some(),
            authority_nonce: None,
            allow_once_option_id: Some("allow_once".to_owned()),
            reject_once_option_id: Some("deny".to_owned()),
            option_dispositions: HashMap::from([
                ("allow_once".to_owned(), OptionDisposition::AllowOnce),
                ("allow_session".to_owned(), OptionDisposition::ExactSession),
                ("allow_always".to_owned(), OptionDisposition::UnsupportedPermanent),
                ("deny".to_owned(), OptionDisposition::RejectOnce),
                ("deny_always".to_owned(), OptionDisposition::UnsupportedPermanent),
            ]),
        }
    }

    fn policy_for_test(mode: super::super::permission_authority::PermissionMode) -> PolicySnapshot {
        let mut state = super::super::permission_authority::CommandEvePolicyState::default();
        assert!(
            state.apply_runtime_hello(super::super::permission_authority::RuntimeCapabilityReceipt::test_receipt())
        );
        state.begin_session();
        state.request_mode(mode);
        state.acknowledge_runtime_mode(mode).unwrap();
        state.begin_turn().unwrap()
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
            authority: None,
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

        let authority = command_eve_authority_for_test(Some("digest-1"));
        contain_command_eve_options(&mut event, true, &authority);

        let AcpPermissionEventData::Request(event) = event else {
            panic!("permission translation must keep the Request variant");
        };
        let option_ids = event
            .options
            .iter()
            .map(|option| option.option_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(option_ids, vec!["allow_once", "allow_session", "deny"]);
        assert_eq!(event.options[1].name, EXACT_SESSION_GRANT_LABEL);
        assert_eq!(EXACT_SESSION_GRANT_TTL, Duration::from_secs(30 * 60));
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
        assert!(router.session_grants.lock().unwrap().contains_key("digest-1"));
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

        assert!(error.to_string().contains("different decision"));
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
        let default_policy = policy_for_test(super::super::permission_authority::PermissionMode::Default);
        let auto_policy = policy_for_test(super::super::permission_authority::PermissionMode::DontAsk);
        let classification = TrustedClassification::new(OperationClass::RoutineTerminal);

        let first_digest = operation_digest(
            "/tmp/workspace",
            "hermes",
            Some(&default_policy),
            classification,
            &first,
        );
        assert_eq!(
            first_digest,
            operation_digest(
                "/tmp/workspace",
                "hermes",
                Some(&default_policy),
                classification,
                &repeated,
            )
        );
        assert_ne!(
            first_digest,
            operation_digest(
                "/tmp/workspace",
                "hermes",
                Some(&default_policy),
                classification,
                &changed,
            )
        );
        assert_ne!(
            first_digest,
            operation_digest("/tmp/other", "hermes", Some(&default_policy), classification, &first,)
        );
        assert_ne!(
            first_digest,
            operation_digest("/tmp/workspace", "hermes", Some(&auto_policy), classification, &first,)
        );
        assert_ne!(
            first_digest,
            operation_digest(
                "/tmp/workspace",
                "hermes",
                Some(&default_policy),
                classification,
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
                Some(policy_for_test(
                    super::super::permission_authority::PermissionMode::Default,
                )),
                "/tmp/workspace",
                &request,
            )
            .is_none(),
            "shared ACP backends must retain their existing manual semantics"
        );

        let authority = build_command_eve_authority(
            Some("hermes"),
            Some(policy_for_test(
                super::super::permission_authority::PermissionMode::Default,
            )),
            "/tmp/workspace",
            &request,
        )
        .expect("Hermes is the authenticated Command EVE backend");
        assert!(authority.policy.is_some());
        assert_eq!(authority.classification.class, OperationClass::Unknown);

        let missing_policy = build_command_eve_authority(Some("hermes"), None, "/tmp/workspace", &request)
            .expect("missing policy asks visibly rather than auto-approving");
        assert!(missing_policy.policy.is_none());
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
    fn cancel_all_keeps_disabled_cancelled_history() {
        let (_tx, rx) = mpsc::channel(1);
        let router = PermissionRouter::new(rx);
        let (response_tx, _response_rx) = oneshot::channel();
        router.insert_pending_for_test("tool-1".to_owned(), response_tx, sample_confirmation("tool-1"));

        router.cancel_all();

        let confirmations = router.get_confirmations();
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].action.as_deref(), Some("cancelled"));
        assert!(confirmations[0].options.is_empty());
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

#[cfg(test)]
#[path = "permission_router_c7_tests.rs"]
mod c7_tests;
