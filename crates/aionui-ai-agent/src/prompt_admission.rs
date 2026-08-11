use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::AgentError;

pub const COMMAND_EVE_PROMPT_ADMISSION_VERSION: &str = "command-eve-prompt-admission/v1";
pub(crate) const COMMAND_EVE_PROMPT_ADMISSION_EXT_METHOD: &str = "command_eve/prompt_admission";

const PROMPT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);
const PROMPT_ADMISSION_FINALIZE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ACTIVE_ADMISSIONS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandEvePromptAdmissionRequest {
    pub version: String,
    pub request_id: String,
    pub turn_id: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEvePromptAdmissionResponse {
    pub version: String,
    pub request_id: String,
    pub status: CommandEvePromptAdmissionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandEvePromptAdmissionWireRequest {
    pub version: String,
    pub request_id: String,
    pub turn_id: String,
    pub receipt_sha256: String,
    pub session_id: String,
    pub phase: CommandEvePromptAdmissionPhase,
}

impl CommandEvePromptAdmissionWireRequest {
    pub(crate) fn request(&self) -> CommandEvePromptAdmissionRequest {
        CommandEvePromptAdmissionRequest {
            version: self.version.clone(),
            request_id: self.request_id.clone(),
            turn_id: self.turn_id.clone(),
            receipt_sha256: self.receipt_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommandEvePromptAdmissionStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CommandEvePromptAdmissionPhase {
    Accept,
    Commit,
    Finalize,
}

pub struct CommandEvePromptAdmissionTicket {
    turn_id: String,
    claim_rx: oneshot::Receiver<Result<CommandEvePromptAdmissionClaim, String>>,
}

pub struct CommandEvePromptAdmissionClaim {
    pub session_id: String,
    turn_id: String,
    decision_tx: Option<oneshot::Sender<CommandEvePromptAdmissionDecision>>,
    finalize_rx: oneshot::Receiver<Result<CommandEvePromptAdmissionFinalizeClaim, String>>,
}

pub struct CommandEvePromptAdmissionFinalizeTicket {
    turn_id: String,
    finalize_rx: oneshot::Receiver<Result<CommandEvePromptAdmissionFinalizeClaim, String>>,
}

pub struct CommandEvePromptAdmissionFinalizeClaim {
    turn_id: String,
    decision_tx: Option<oneshot::Sender<CommandEvePromptAdmissionDecision>>,
    delivery_rx: oneshot::Receiver<Result<(), String>>,
}

pub struct CommandEvePromptAdmissionDeliveryTicket {
    turn_id: String,
    delivery_rx: oneshot::Receiver<Result<(), String>>,
}

impl CommandEvePromptAdmissionClaim {
    pub fn accept(mut self) -> Result<CommandEvePromptAdmissionFinalizeTicket, AgentError> {
        self.send(CommandEvePromptAdmissionDecision::Accepted)?;
        Ok(CommandEvePromptAdmissionFinalizeTicket {
            turn_id: self.turn_id,
            finalize_rx: self.finalize_rx,
        })
    }

    pub fn reject(mut self, _code: &'static str) {
        let _ = self.send(CommandEvePromptAdmissionDecision::Rejected);
    }

    fn send(&mut self, decision: CommandEvePromptAdmissionDecision) -> Result<(), AgentError> {
        self.decision_tx
            .take()
            .ok_or_else(|| AgentError::conflict("ATTACHMENT_PROMPT_ADMISSION_ALREADY_DECIDED"))?
            .send(decision)
            .map_err(|_| AgentError::bad_gateway("ATTACHMENT_PROMPT_ADMISSION_TRANSPORT_CLOSED"))
    }
}

impl CommandEvePromptAdmissionFinalizeTicket {
    pub async fn wait(self) -> Result<CommandEvePromptAdmissionFinalizeClaim, AgentError> {
        let outcome = tokio::time::timeout(PROMPT_ADMISSION_FINALIZE_TIMEOUT, self.finalize_rx).await;
        match outcome {
            Ok(Ok(Ok(claim))) => Ok(claim),
            Ok(Ok(Err(code))) => Err(AgentError::bad_gateway(code)),
            Ok(Err(_)) => Err(AgentError::bad_gateway("ATTACHMENT_PROMPT_FINALIZE_CHANNEL_CLOSED")),
            Err(_) => {
                reject_command_eve_prompt_admission(&self.turn_id, "ATTACHMENT_PROMPT_FINALIZE_TIMEOUT");
                Err(AgentError::timeout("ATTACHMENT_PROMPT_FINALIZE_TIMEOUT"))
            }
        }
    }
}

impl CommandEvePromptAdmissionFinalizeClaim {
    pub fn accept(mut self) -> Result<CommandEvePromptAdmissionDeliveryTicket, AgentError> {
        self.send(CommandEvePromptAdmissionDecision::Accepted)?;
        Ok(CommandEvePromptAdmissionDeliveryTicket {
            turn_id: self.turn_id,
            delivery_rx: self.delivery_rx,
        })
    }

    pub fn reject(mut self, _code: &'static str) {
        let _ = self.send(CommandEvePromptAdmissionDecision::Rejected);
    }

    fn send(&mut self, decision: CommandEvePromptAdmissionDecision) -> Result<(), AgentError> {
        self.decision_tx
            .take()
            .ok_or_else(|| AgentError::conflict("ATTACHMENT_PROMPT_FINALIZE_ALREADY_DECIDED"))?
            .send(decision)
            .map_err(|_| AgentError::bad_gateway("ATTACHMENT_PROMPT_FINALIZE_TRANSPORT_CLOSED"))
    }
}

impl CommandEvePromptAdmissionDeliveryTicket {
    pub async fn wait(self) -> Result<(), AgentError> {
        let outcome = tokio::time::timeout(PROMPT_ADMISSION_FINALIZE_TIMEOUT, self.delivery_rx).await;
        match outcome {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(code))) => Err(AgentError::bad_gateway(code)),
            Ok(Err(_)) => Err(AgentError::bad_gateway(
                "ATTACHMENT_PROMPT_FINALIZE_DELIVERY_CHANNEL_CLOSED",
            )),
            Err(_) => {
                reject_command_eve_prompt_admission(&self.turn_id, "ATTACHMENT_PROMPT_FINALIZE_DELIVERY_TIMEOUT");
                Err(AgentError::timeout("ATTACHMENT_PROMPT_FINALIZE_DELIVERY_TIMEOUT"))
            }
        }
    }
}

impl CommandEvePromptAdmissionTicket {
    pub async fn wait(self) -> Result<CommandEvePromptAdmissionClaim, AgentError> {
        let turn_id = self.turn_id.clone();
        let outcome = tokio::time::timeout(PROMPT_ADMISSION_TIMEOUT, self.claim_rx).await;
        match outcome {
            Ok(Ok(Ok(claim))) => Ok(claim),
            Ok(Ok(Err(code))) => Err(AgentError::bad_gateway(code)),
            Ok(Err(_)) => Err(AgentError::bad_gateway("ATTACHMENT_PROMPT_ADMISSION_CHANNEL_CLOSED")),
            Err(_) => {
                reject_command_eve_prompt_admission(&turn_id, "ATTACHMENT_PROMPT_ADMISSION_TIMEOUT");
                Err(AgentError::timeout("ATTACHMENT_PROMPT_ADMISSION_TIMEOUT"))
            }
        }
    }
}

#[doc(hidden)]
pub enum CommandEvePromptAdmissionDecision {
    Accepted,
    Rejected,
}

#[doc(hidden)]
pub enum CommandEvePromptAdmissionClaimResult {
    AwaitingDecision(oneshot::Receiver<CommandEvePromptAdmissionDecision>),
    AlreadyAccepted,
}

#[doc(hidden)]
pub enum CommandEvePromptAdmissionFinalizeClaimResult {
    AwaitingDecision {
        decision_rx: oneshot::Receiver<CommandEvePromptAdmissionDecision>,
        delivery_tx: oneshot::Sender<Result<(), String>>,
    },
    AlreadyAccepted,
}

enum AdmissionEntry {
    Pending {
        request: CommandEvePromptAdmissionRequest,
        claim_tx: oneshot::Sender<Result<CommandEvePromptAdmissionClaim, String>>,
    },
    Admitted {
        request: CommandEvePromptAdmissionRequest,
        session_id: String,
        claim_tx: oneshot::Sender<Result<CommandEvePromptAdmissionClaim, String>>,
    },
    Claimed {
        request: CommandEvePromptAdmissionRequest,
        session_id: String,
        finalize_tx: oneshot::Sender<Result<CommandEvePromptAdmissionFinalizeClaim, String>>,
    },
    Committed {
        request: CommandEvePromptAdmissionRequest,
        session_id: String,
        finalize_tx: oneshot::Sender<Result<CommandEvePromptAdmissionFinalizeClaim, String>>,
    },
    Finalizing {
        request: CommandEvePromptAdmissionRequest,
        session_id: String,
    },
    Accepted {
        request: CommandEvePromptAdmissionRequest,
        session_id: String,
    },
}

#[derive(Default)]
struct AdmissionRegistry {
    request_by_turn: HashMap<String, String>,
    entries: HashMap<String, AdmissionEntry>,
}

fn registry() -> &'static Mutex<AdmissionRegistry> {
    static REGISTRY: OnceLock<Mutex<AdmissionRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(AdmissionRegistry::default()))
}

pub fn register_command_eve_prompt_admission(
    turn_id: &str,
    receipt_sha256: &str,
) -> Result<CommandEvePromptAdmissionTicket, AgentError> {
    validate_identifier(turn_id).map_err(AgentError::bad_request)?;
    validate_sha256(receipt_sha256).map_err(AgentError::bad_request)?;

    let request = CommandEvePromptAdmissionRequest {
        version: COMMAND_EVE_PROMPT_ADMISSION_VERSION.to_owned(),
        request_id: Uuid::new_v4().to_string(),
        turn_id: turn_id.to_owned(),
        receipt_sha256: receipt_sha256.to_owned(),
    };
    let (claim_tx, claim_rx) = oneshot::channel();
    let mut state = registry()
        .lock()
        .map_err(|_| AgentError::internal("ATTACHMENT_PROMPT_ADMISSION_STATE_UNAVAILABLE"))?;
    if state.request_by_turn.contains_key(turn_id) {
        return Err(AgentError::conflict("ATTACHMENT_PROMPT_ADMISSION_ALREADY_REGISTERED"));
    }
    if state.request_by_turn.len() >= MAX_ACTIVE_ADMISSIONS {
        return Err(AgentError::conflict("ATTACHMENT_PROMPT_ADMISSION_SATURATED"));
    }
    state
        .request_by_turn
        .insert(turn_id.to_owned(), request.request_id.clone());
    state.entries.insert(
        request.request_id.clone(),
        AdmissionEntry::Pending { request, claim_tx },
    );
    Ok(CommandEvePromptAdmissionTicket {
        turn_id: turn_id.to_owned(),
        claim_rx,
    })
}

#[doc(hidden)]
pub fn command_eve_prompt_admission_for_turn(turn_id: &str) -> Option<CommandEvePromptAdmissionRequest> {
    let state = registry().lock().ok()?;
    let request_id = state.request_by_turn.get(turn_id)?;
    match state.entries.get(request_id)? {
        AdmissionEntry::Pending { request, .. }
        | AdmissionEntry::Admitted { request, .. }
        | AdmissionEntry::Claimed { request, .. }
        | AdmissionEntry::Committed { request, .. }
        | AdmissionEntry::Finalizing { request, .. }
        | AdmissionEntry::Accepted { request, .. } => Some(request.clone()),
    }
}

#[doc(hidden)]
pub fn admit_command_eve_prompt_admission(
    request: &CommandEvePromptAdmissionRequest,
    session_id: &str,
) -> Result<(), &'static str> {
    validate_request(request, session_id)?;

    let mut state = registry().lock().map_err(|_| "state_unavailable")?;
    let Some(entry) = state.entries.remove(&request.request_id) else {
        return Err("unknown_request");
    };
    match entry {
        AdmissionEntry::Pending {
            request: expected,
            claim_tx,
        } => {
            if !request_matches(&state, &expected, request) {
                state.entries.insert(
                    expected.request_id.clone(),
                    AdmissionEntry::Pending {
                        request: expected,
                        claim_tx,
                    },
                );
                return Err("request_mismatch");
            }
            state.entries.insert(
                request.request_id.clone(),
                AdmissionEntry::Admitted {
                    request: request.clone(),
                    session_id: session_id.to_owned(),
                    claim_tx,
                },
            );
            Ok(())
        }
        AdmissionEntry::Admitted {
            request: expected,
            session_id: admitted_session,
            claim_tx,
        } => {
            let matches = expected == *request && admitted_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Admitted {
                    request: expected,
                    session_id: admitted_session,
                    claim_tx,
                },
            );
            matches.then_some(()).ok_or("request_mismatch")
        }
        AdmissionEntry::Claimed {
            request: expected,
            session_id: claimed_session,
            finalize_tx,
        } => {
            let matches = expected == *request && claimed_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Claimed {
                    request: expected,
                    session_id: claimed_session,
                    finalize_tx,
                },
            );
            matches.then_some(()).ok_or("request_mismatch")
        }
        AdmissionEntry::Committed {
            request: expected,
            session_id: committed_session,
            finalize_tx,
        } => {
            let matches = expected == *request && committed_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Committed {
                    request: expected,
                    session_id: committed_session,
                    finalize_tx,
                },
            );
            matches.then_some(()).ok_or("request_mismatch")
        }
        AdmissionEntry::Finalizing {
            request: expected,
            session_id: finalizing_session,
        } => {
            let matches = expected == *request && finalizing_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Finalizing {
                    request: expected,
                    session_id: finalizing_session,
                },
            );
            matches.then_some(()).ok_or("request_mismatch")
        }
        AdmissionEntry::Accepted {
            request: expected,
            session_id: accepted_session,
        } => {
            let matches = expected == *request && accepted_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Accepted {
                    request: expected,
                    session_id: accepted_session,
                },
            );
            matches.then_some(()).ok_or("request_mismatch")
        }
    }
}

#[doc(hidden)]
pub fn claim_command_eve_prompt_admission(
    request: &CommandEvePromptAdmissionRequest,
    session_id: &str,
) -> Result<CommandEvePromptAdmissionClaimResult, &'static str> {
    validate_request(request, session_id)?;

    let mut state = registry().lock().map_err(|_| "state_unavailable")?;
    let Some(entry) = state.entries.remove(&request.request_id) else {
        return Err("unknown_request");
    };
    match entry {
        AdmissionEntry::Admitted {
            request: expected,
            session_id: admitted_session,
            claim_tx,
        } => {
            if !request_matches(&state, &expected, request) || admitted_session != session_id {
                state.entries.insert(
                    expected.request_id.clone(),
                    AdmissionEntry::Admitted {
                        request: expected,
                        session_id: admitted_session,
                        claim_tx,
                    },
                );
                return Err("request_mismatch");
            }
            let (decision_tx, decision_rx) = oneshot::channel();
            let (finalize_tx, finalize_rx) = oneshot::channel();
            let claim = CommandEvePromptAdmissionClaim {
                session_id: session_id.to_owned(),
                turn_id: request.turn_id.clone(),
                decision_tx: Some(decision_tx),
                finalize_rx,
            };
            if claim_tx.send(Ok(claim)).is_err() {
                state.request_by_turn.remove(&request.turn_id);
                return Err("consumer_unavailable");
            }
            state.entries.insert(
                request.request_id.clone(),
                AdmissionEntry::Claimed {
                    request: request.clone(),
                    session_id: session_id.to_owned(),
                    finalize_tx,
                },
            );
            Ok(CommandEvePromptAdmissionClaimResult::AwaitingDecision(decision_rx))
        }
        AdmissionEntry::Pending {
            request: expected,
            claim_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Pending {
                    request: expected,
                    claim_tx,
                },
            );
            Err("request_not_admitted")
        }
        AdmissionEntry::Accepted {
            request: expected,
            session_id: accepted_session,
        } => {
            let matches = expected == *request && accepted_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Accepted {
                    request: expected,
                    session_id: accepted_session,
                },
            );
            if matches {
                Ok(CommandEvePromptAdmissionClaimResult::AlreadyAccepted)
            } else {
                Err("request_mismatch")
            }
        }
        AdmissionEntry::Claimed {
            request: expected,
            session_id: claimed_session,
            finalize_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Claimed {
                    request: expected,
                    session_id: claimed_session,
                    finalize_tx,
                },
            );
            Err("request_in_progress")
        }
        AdmissionEntry::Committed {
            request: expected,
            session_id: committed_session,
            finalize_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Committed {
                    request: expected,
                    session_id: committed_session,
                    finalize_tx,
                },
            );
            Err("request_in_progress")
        }
        AdmissionEntry::Finalizing {
            request: expected,
            session_id: finalizing_session,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Finalizing {
                    request: expected,
                    session_id: finalizing_session,
                },
            );
            Err("request_in_progress")
        }
    }
}

#[doc(hidden)]
pub fn complete_command_eve_prompt_admission_commit(request_id: &str, session_id: &str, accepted: bool) {
    let Ok(mut state) = registry().lock() else {
        return;
    };
    let Some(entry) = state.entries.remove(request_id) else {
        return;
    };
    match entry {
        AdmissionEntry::Claimed {
            request,
            session_id: claimed_session,
            finalize_tx,
        } if claimed_session == session_id && accepted => {
            state.entries.insert(
                request_id.to_owned(),
                AdmissionEntry::Committed {
                    request,
                    session_id: claimed_session,
                    finalize_tx,
                },
            );
        }
        AdmissionEntry::Claimed {
            request, finalize_tx, ..
        }
        | AdmissionEntry::Committed {
            request, finalize_tx, ..
        } => {
            let _ = finalize_tx.send(Err("ATTACHMENT_PROMPT_COMMIT_TRANSPORT_REJECTED".to_owned()));
            state.request_by_turn.remove(&request.turn_id);
        }
        AdmissionEntry::Pending { request, claim_tx } | AdmissionEntry::Admitted { request, claim_tx, .. } => {
            let _ = claim_tx.send(Err("ATTACHMENT_PROMPT_ADMISSION_REJECTED".to_owned()));
            state.request_by_turn.remove(&request.turn_id);
        }
        AdmissionEntry::Finalizing { request, .. } | AdmissionEntry::Accepted { request, .. } => {
            state.request_by_turn.remove(&request.turn_id);
        }
    }
}

#[doc(hidden)]
pub fn finalize_command_eve_prompt_admission(
    request: &CommandEvePromptAdmissionRequest,
    session_id: &str,
) -> Result<CommandEvePromptAdmissionFinalizeClaimResult, &'static str> {
    validate_request(request, session_id)?;

    let mut state = registry().lock().map_err(|_| "state_unavailable")?;
    let Some(entry) = state.entries.remove(&request.request_id) else {
        return Err("unknown_request");
    };
    match entry {
        AdmissionEntry::Committed {
            request: expected,
            session_id: committed_session,
            finalize_tx,
        } => {
            if !request_matches(&state, &expected, request) || committed_session != session_id {
                state.entries.insert(
                    expected.request_id.clone(),
                    AdmissionEntry::Committed {
                        request: expected,
                        session_id: committed_session,
                        finalize_tx,
                    },
                );
                return Err("request_mismatch");
            }
            let (decision_tx, decision_rx) = oneshot::channel();
            let (delivery_tx, delivery_rx) = oneshot::channel();
            let claim = CommandEvePromptAdmissionFinalizeClaim {
                decision_tx: Some(decision_tx),
                delivery_rx,
                turn_id: request.turn_id.clone(),
            };
            if finalize_tx.send(Ok(claim)).is_err() {
                state.request_by_turn.remove(&request.turn_id);
                return Err("consumer_unavailable");
            }
            state.entries.insert(
                request.request_id.clone(),
                AdmissionEntry::Finalizing {
                    request: request.clone(),
                    session_id: session_id.to_owned(),
                },
            );
            Ok(CommandEvePromptAdmissionFinalizeClaimResult::AwaitingDecision {
                decision_rx,
                delivery_tx,
            })
        }
        AdmissionEntry::Accepted {
            request: expected,
            session_id: accepted_session,
        } => {
            let matches = expected == *request && accepted_session == session_id;
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Accepted {
                    request: expected,
                    session_id: accepted_session,
                },
            );
            if matches {
                Ok(CommandEvePromptAdmissionFinalizeClaimResult::AlreadyAccepted)
            } else {
                Err("request_mismatch")
            }
        }
        AdmissionEntry::Finalizing {
            request: expected,
            session_id: finalizing_session,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Finalizing {
                    request: expected,
                    session_id: finalizing_session,
                },
            );
            Err("request_in_progress")
        }
        AdmissionEntry::Pending {
            request: expected,
            claim_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Pending {
                    request: expected,
                    claim_tx,
                },
            );
            Err("request_not_committed")
        }
        AdmissionEntry::Admitted {
            request: expected,
            session_id: admitted_session,
            claim_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Admitted {
                    request: expected,
                    session_id: admitted_session,
                    claim_tx,
                },
            );
            Err("request_not_committed")
        }
        AdmissionEntry::Claimed {
            request: expected,
            session_id: claimed_session,
            finalize_tx,
        } => {
            state.entries.insert(
                expected.request_id.clone(),
                AdmissionEntry::Claimed {
                    request: expected,
                    session_id: claimed_session,
                    finalize_tx,
                },
            );
            Err("request_not_committed")
        }
    }
}

#[doc(hidden)]
pub fn complete_command_eve_prompt_admission(request_id: &str, session_id: &str, accepted: bool) {
    let Ok(mut state) = registry().lock() else {
        return;
    };
    let Some(entry) = state.entries.remove(request_id) else {
        return;
    };
    match entry {
        AdmissionEntry::Finalizing {
            request,
            session_id: finalizing_session,
        } if finalizing_session == session_id && accepted => {
            state.entries.insert(
                request_id.to_owned(),
                AdmissionEntry::Accepted {
                    request,
                    session_id: finalizing_session,
                },
            );
        }
        AdmissionEntry::Pending { request, claim_tx } => {
            let _ = claim_tx.send(Err("ATTACHMENT_PROMPT_ADMISSION_REJECTED".to_owned()));
            state.request_by_turn.remove(&request.turn_id);
        }
        AdmissionEntry::Admitted { request, claim_tx, .. } => {
            let _ = claim_tx.send(Err("ATTACHMENT_PROMPT_ADMISSION_REJECTED".to_owned()));
            state.request_by_turn.remove(&request.turn_id);
        }
        AdmissionEntry::Claimed {
            request, finalize_tx, ..
        }
        | AdmissionEntry::Committed {
            request, finalize_tx, ..
        } => {
            let _ = finalize_tx.send(Err("ATTACHMENT_PROMPT_FINALIZE_REJECTED".to_owned()));
            state.request_by_turn.remove(&request.turn_id);
        }
        AdmissionEntry::Finalizing { request, .. } | AdmissionEntry::Accepted { request, .. } => {
            state.request_by_turn.remove(&request.turn_id);
        }
    }
}

pub fn reject_command_eve_prompt_admission(turn_id: &str, code: &'static str) {
    let Ok(mut state) = registry().lock() else {
        return;
    };
    let Some(request_id) = state.request_by_turn.get(turn_id).cloned() else {
        return;
    };
    let Some(entry) = state.entries.remove(&request_id) else {
        state.request_by_turn.remove(turn_id);
        return;
    };
    match entry {
        AdmissionEntry::Pending { claim_tx, .. } | AdmissionEntry::Admitted { claim_tx, .. } => {
            state.request_by_turn.remove(turn_id);
            let _ = claim_tx.send(Err(code.to_owned()));
        }
        AdmissionEntry::Claimed { finalize_tx, .. } | AdmissionEntry::Committed { finalize_tx, .. } => {
            state.request_by_turn.remove(turn_id);
            let _ = finalize_tx.send(Err(code.to_owned()));
        }
        other => {
            state.entries.insert(request_id, other);
        }
    }
}

pub fn forget_command_eve_prompt_admission(turn_id: &str) {
    let Ok(mut state) = registry().lock() else {
        return;
    };
    if let Some(request_id) = state.request_by_turn.remove(turn_id) {
        state.entries.remove(&request_id);
    }
}

fn validate_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("invalid_identifier");
    }
    Ok(())
}

fn validate_request(request: &CommandEvePromptAdmissionRequest, session_id: &str) -> Result<(), &'static str> {
    validate_identifier(session_id)?;
    if request.version != COMMAND_EVE_PROMPT_ADMISSION_VERSION {
        return Err("unsupported_version");
    }
    validate_identifier(&request.request_id)?;
    validate_identifier(&request.turn_id)?;
    validate_sha256(&request.receipt_sha256)
}

fn request_matches(
    state: &AdmissionRegistry,
    expected: &CommandEvePromptAdmissionRequest,
    request: &CommandEvePromptAdmissionRequest,
) -> bool {
    expected == request
        && state.request_by_turn.get(&request.turn_id).map(String::as_str) == Some(request.request_id.as_str())
}

fn validate_sha256(value: &str) -> Result<(), &'static str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("invalid_receipt_sha256");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_claim_is_exactly_once_and_replay_is_idempotent() {
        let turn_id = format!("turn-{}", Uuid::new_v4());
        let ticket = register_command_eve_prompt_admission(&turn_id, &"a".repeat(64)).unwrap();
        let request = command_eve_prompt_admission_for_turn(&turn_id).unwrap();
        admit_command_eve_prompt_admission(&request, "session-1").unwrap();
        let decision = match claim_command_eve_prompt_admission(&request, "session-1").unwrap() {
            CommandEvePromptAdmissionClaimResult::AwaitingDecision(decision) => decision,
            CommandEvePromptAdmissionClaimResult::AlreadyAccepted => panic!("first claim cannot be accepted"),
        };
        let claim = ticket.wait().await.unwrap();
        assert_eq!(claim.session_id, "session-1");
        let finalize_ticket = claim.accept().unwrap();
        assert!(matches!(
            decision.await.unwrap(),
            CommandEvePromptAdmissionDecision::Accepted
        ));
        complete_command_eve_prompt_admission_commit(&request.request_id, "session-1", true);
        let (finalize_decision, delivery_tx) =
            match finalize_command_eve_prompt_admission(&request, "session-1").unwrap() {
                CommandEvePromptAdmissionFinalizeClaimResult::AwaitingDecision {
                    decision_rx,
                    delivery_tx,
                } => (decision_rx, delivery_tx),
                CommandEvePromptAdmissionFinalizeClaimResult::AlreadyAccepted => {
                    panic!("first finalize cannot be accepted")
                }
            };
        let finalize_claim = finalize_ticket.wait().await.unwrap();
        let delivery_ticket = finalize_claim.accept().unwrap();
        assert!(matches!(
            finalize_decision.await.unwrap(),
            CommandEvePromptAdmissionDecision::Accepted
        ));
        complete_command_eve_prompt_admission(&request.request_id, "session-1", true);
        delivery_tx.send(Ok(())).unwrap();
        delivery_ticket.wait().await.unwrap();
        assert!(matches!(
            claim_command_eve_prompt_admission(&request, "session-1").unwrap(),
            CommandEvePromptAdmissionClaimResult::AlreadyAccepted
        ));
        forget_command_eve_prompt_admission(&turn_id);
    }

    #[tokio::test]
    async fn commit_is_rejected_until_acp_has_admitted_the_exact_prompt() {
        let turn_id = format!("turn-{}", Uuid::new_v4());
        let ticket = register_command_eve_prompt_admission(&turn_id, &"b".repeat(64)).unwrap();
        let request = command_eve_prompt_admission_for_turn(&turn_id).unwrap();

        let pre_admission_error = match claim_command_eve_prompt_admission(&request, "session-2") {
            Err(error) => error,
            Ok(_) => panic!("commit cannot precede ACP acceptance"),
        };
        assert_eq!(pre_admission_error, "request_not_admitted");
        admit_command_eve_prompt_admission(&request, "session-2").unwrap();
        let decision = match claim_command_eve_prompt_admission(&request, "session-2").unwrap() {
            CommandEvePromptAdmissionClaimResult::AwaitingDecision(decision) => decision,
            CommandEvePromptAdmissionClaimResult::AlreadyAccepted => panic!("first commit cannot be accepted"),
        };
        let claim = ticket.wait().await.unwrap();
        claim.reject("test_reject");
        assert!(matches!(
            decision.await.unwrap(),
            CommandEvePromptAdmissionDecision::Rejected
        ));
        forget_command_eve_prompt_admission(&turn_id);
    }

    #[tokio::test]
    async fn mismatch_does_not_consume_the_registered_turn() {
        let turn_id = format!("turn-{}", Uuid::new_v4());
        let ticket = register_command_eve_prompt_admission(&turn_id, &"b".repeat(64)).unwrap();
        let mut mismatched = command_eve_prompt_admission_for_turn(&turn_id).unwrap();
        mismatched.receipt_sha256 = "c".repeat(64);
        let mismatch_error = match admit_command_eve_prompt_admission(&mismatched, "session-1") {
            Err(error) => error,
            Ok(_) => panic!("mismatched receipt digest must be rejected"),
        };
        assert_eq!(mismatch_error, "request_mismatch");
        reject_command_eve_prompt_admission(&turn_id, "ATTACHMENT_PROMPT_ADMISSION_TEST_REJECTED");
        let ticket_error = match ticket.wait().await {
            Err(error) => error,
            Ok(_) => panic!("rejected admission must wake the waiting service"),
        };
        assert!(ticket_error.to_string().contains("TEST_REJECTED"));
    }

    #[test]
    fn wire_contract_requires_the_exact_accept_commit_or_finalize_phase() {
        let base = serde_json::json!({
            "version": COMMAND_EVE_PROMPT_ADMISSION_VERSION,
            "request_id": "request-1",
            "turn_id": "turn-1",
            "receipt_sha256": "d".repeat(64),
            "session_id": "session-1",
            "phase": "accept",
        });
        let accept: CommandEvePromptAdmissionWireRequest = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(accept.phase, CommandEvePromptAdmissionPhase::Accept);

        let mut commit = base.clone();
        commit["phase"] = serde_json::json!("commit");
        let commit: CommandEvePromptAdmissionWireRequest = serde_json::from_value(commit).unwrap();
        assert_eq!(commit.phase, CommandEvePromptAdmissionPhase::Commit);

        let mut finalize = base.clone();
        finalize["phase"] = serde_json::json!("finalize");
        let finalize: CommandEvePromptAdmissionWireRequest = serde_json::from_value(finalize).unwrap();
        assert_eq!(finalize.phase, CommandEvePromptAdmissionPhase::Finalize);

        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("phase");
        assert!(serde_json::from_value::<CommandEvePromptAdmissionWireRequest>(missing).is_err());
        let mut extra = base;
        extra["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CommandEvePromptAdmissionWireRequest>(extra).is_err());
    }
}
