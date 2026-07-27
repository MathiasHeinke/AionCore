use crate::manager::acp::AcpAgentManager;

use crate::manager::acp::agent::{PolicyChangeOrigin, is_stale_reconcile_plan};
use crate::manager::acp::error_mapping::is_acp_session_not_found;
use crate::manager::acp::mode_normalize::normalize_requested_mode;
use crate::manager::acp::permission_authority::command_eve_transport_mode;
use crate::manager::acp::session::PendingStartupConfigSeedResult;
use crate::protocol::error::AcpError;
use crate::shared_kernel::{ConfigKey, ConfigValue, ModeId, ModelId};
use agent_client_protocol::schema::{
    SessionId, SetSessionConfigOptionRequest, SetSessionModeRequest, SetSessionModelRequest,
};
use std::collections::VecDeque;
use tracing::{error, info, warn};

const MAX_RECONCILE_ACTIONS: usize = 8;

/// Actions the session driver must execute to align CLI state with user intent.
///
/// Produced by `AcpSession::plan_reconcile` — a pure function that compares
/// desired vs observed and returns a list of idempotent, order-independent ops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    SetMode { mode: ModeId },
    SetModel { model: ModelId },
    SetConfigOption { key: ConfigKey, value: ConfigValue },
}

impl AcpAgentManager {
    /// Execute reconcile actions produced by `AcpSession::plan_reconcile`.
    ///
    /// Compares the aggregate's desired state against what the CLI has
    /// reported as current, then issues the minimal set of SDK calls
    /// (set_mode, set_model, set_config_option) to bring the CLI into
    /// alignment.
    ///
    /// Failure handling:
    /// - `SessionNotFound`: returned as structured `AcpError::SessionNotFound` so callers
    ///   (e.g. `open_session_resume`) can drop the stale sid and rebuild
    ///   the session. ELECTRON-1HQ regressed because we silently swallowed
    ///   this case during warmup, leaving downstream `session/prompt` to
    ///   surface the same error to the user every turn.
    /// - Any other error: logged and skipped (best-effort), so a failed
    ///   `set_config_option` doesn't block a successful `set_mode`.
    pub(super) async fn reconcile_session(&self, session_id: &str) -> Result<(), AcpError> {
        use crate::manager::acp::ReconcileAction;

        let (startup_config_seed_results, invalid_mode, invalid_model, mut actions) = {
            let mut session = self.session.write().await;
            let startup_config_seed_results = session.resolve_pending_startup_config_seeds();
            let invalid_mode = if self.backend() == Some("hermes") {
                match session.migrate_command_eve_mode_config_intent() {
                    Ok(Some(_)) => self.permission_router.revoke_command_eve_policy(
                        "persisted Command EVE mode config migrated before Hermes transport acknowledgement",
                    ),
                    Ok(None) => {}
                    Err(error) => {
                        self.permission_router
                            .revoke_command_eve_policy("invalid persisted Command EVE mode config was removed");
                        warn!(
                            conversation_id = %self.params.conversation_id,
                            error = %error,
                            "reconcile_session: invalid Command EVE mode config remains fail-closed"
                        );
                    }
                }
                session.clear_invalid_command_eve_desired_mode()
            } else {
                session.clear_invalid_desired_mode()
            };
            let invalid_model = session.clear_invalid_desired_model();
            let actions = session.plan_reconcile();
            (startup_config_seed_results, invalid_mode, invalid_model, actions)
        };
        if self.backend() == Some("hermes")
            && !self.session.read().await.command_eve_policy_acknowledged()
            && !actions
                .iter()
                .any(|action| matches!(action, ReconcileAction::SetMode { .. }))
        {
            // P0 (C7 integrator review): the AionCore policy must NEVER be derived
            // from what the transport reports. `observed_mode()` holds Hermes' own
            // `current_mode_id`, which `apply_command_eve_transport_mode` writes
            // through unvalidated and — when it is not "default" — immediately
            // revokes as untrustworthy. Feeding it back in here promoted exactly
            // that revoked state to the authority, so a persisted `dont_ask`
            // (RoutineEdit + RoutineTerminal without asking) reinstalled itself on
            // every session start. Only our OWN desired policy may seed this, and
            // absent one we start fail-closed at "default" (Ask).
            let mode = {
                let session = self.session.read().await;
                session.desired_mode().unwrap_or("default").to_owned()
            };
            if self
                .session
                .read()
                .await
                .ensure_command_eve_mode_available(&mode)
                .is_ok()
            {
                actions.push(ReconcileAction::SetMode {
                    mode: ModeId::new(mode),
                });
            } else {
                warn!(
                    conversation_id = %self.params.conversation_id,
                    mode_id = %mode,
                    "reconcile_session: unavailable Command EVE mode remains fail-closed"
                );
            }
        }
        self.log_reconcile_session_plan_results(startup_config_seed_results, invalid_mode, invalid_model);
        let mut actions: VecDeque<_> = actions.into();
        let mut executed_actions = 0usize;
        while let Some(action) = actions.pop_front() {
            let executed_action = action.clone();
            executed_actions += 1;
            if executed_actions > MAX_RECONCILE_ACTIONS {
                warn!(
                    conversation_id = %self.params.conversation_id,
                    max_actions = MAX_RECONCILE_ACTIONS,
                    "reconcile_session: stopping after action limit"
                );
                break;
            }
            match action {
                ReconcileAction::SetMode { mode } => {
                    let normalized = normalize_requested_mode(&self.params.metadata, mode.as_str());
                    if normalized.is_empty() {
                        continue;
                    }
                    let transport_mode = if self.backend() == Some("hermes") {
                        command_eve_transport_mode(&normalized)
                    } else {
                        normalized.as_str()
                    };
                    // P1 (independent review, Grok): a reconcile must never overwrite a
                    // policy the operator asked for while this action was in flight.
                    //
                    // `set_config_option_confirmed` deliberately does NOT take `session_lock`
                    // (that lock belongs to the active prompt — see `steer_active_turn`), so a
                    // human mode change can land at any point during this loop. If it lands
                    // BETWEEN our prepare and our acknowledge, the stale-ack guard in
                    // `acknowledge_runtime_mode` already rejects us. If it lands BEFORE our
                    // prepare, `begin_mode_change` used to overwrite the human's request with
                    // the older, machine-planned one — and the acknowledge then matched.
                    //
                    // `PolicyChangeOrigin::Reconcile` closes that: the staleness check runs
                    // inside `prepare_command_eve_policy_change`, under the same write lock
                    // that mutates the policy, so no window remains between checking and
                    // acting. Deliberate asymmetry: the operator overrides the reconcile,
                    // never the other way round. Taking `session_lock` here would have closed
                    // it too, but at the price of blocking every mode change for the whole
                    // duration of a running agent turn.
                    if self.backend() == Some("hermes")
                        && let Err(error) = self
                            .prepare_command_eve_policy_change(
                                session_id,
                                &normalized,
                                "reconcile Command EVE mode change started before Hermes transport acknowledgement",
                                PolicyChangeOrigin::Reconcile,
                            )
                            .await
                    {
                        // P3 (independent review, Kimi): two very different causes land
                        // here and must not share a log level. An operator having chosen
                        // something else since this action was planned is ROUTINE — the
                        // asymmetry working as designed. Anything else is a contract
                        // violation or a failed operation and stays `error!`, per the
                        // project logging rule.
                        if is_stale_reconcile_plan(&error) {
                            info!(
                                conversation_id = %self.params.conversation_id,
                                mode_id = %normalized,
                                "reconcile_session: an operator policy change superseded this \
                                 planned mode change; stepping aside"
                            );
                        } else {
                            error!(
                                conversation_id = %self.params.conversation_id,
                                mode_id = %normalized,
                                error = %error,
                                "reconcile_session: Command EVE policy preparation failed"
                            );
                        }
                        continue;
                    }
                    if let Err(e) = self
                        .protocol
                        .set_mode(SetSessionModeRequest::new(
                            SessionId::new(session_id),
                            transport_mode.to_owned(),
                        ))
                        .await
                    {
                        if is_acp_session_not_found(&e) {
                            warn!(
                                conversation_id = %self.params.conversation_id,
                                mode_id = %normalized,
                                error = %e,
                                "reconcile_session: set_mode hit SessionNotFound; aborting reconcile"
                            );
                            return Err(e);
                        }
                        error!(
                            conversation_id = %self.params.conversation_id,
                            mode_id = %normalized,
                            error = %e,
                            "reconcile_session: set_mode failed"
                        );
                        continue;
                    }
                    if self.backend() == Some("hermes") {
                        let mut session = self.session.write().await;
                        if !session.apply_command_eve_transport_mode(ModeId::new(transport_mode)) {
                            self.permission_router
                                .revoke_command_eve_policy("reconcile transport was not default");
                            continue;
                        }
                        if session
                            .acknowledge_command_eve_policy(ModeId::new(normalized.clone()))
                            .is_none()
                        {
                            error!(
                                conversation_id = %self.params.conversation_id,
                                mode_id = %normalized,
                                "reconcile_session: Command EVE policy acknowledgement failed"
                            );
                            continue;
                        }
                        if let Some(snapshot) = session.command_eve_policy_snapshot() {
                            self.permission_router.apply_policy_snapshot(snapshot);
                        }
                        self.commit_session_changes(&mut session).await;
                    }
                }

                ReconcileAction::SetModel { model } => {
                    if let Err(e) = self
                        .protocol
                        .set_model(SetSessionModelRequest::new(
                            SessionId::new(session_id),
                            model.as_str().to_owned(),
                        ))
                        .await
                    {
                        if is_acp_session_not_found(&e) {
                            warn!(
                                conversation_id = %self.params.conversation_id,
                                model_id = %model,
                                error = %e,
                                "reconcile_session: set_model hit SessionNotFound; aborting reconcile"
                            );
                            return Err(e);
                        }
                        error!(
                            conversation_id = %self.params.conversation_id,
                            model_id = %model,
                            error = %e,
                            "reconcile_session: set_model failed"
                        );
                        continue;
                    }
                }

                ReconcileAction::SetConfigOption { key, value } => {
                    info!(
                        conversation_id = %self.params.conversation_id,
                        agent_backend = ?self.params.metadata.backend,
                        config_id = %key,
                        desired = %value,
                        "acp_reconcile_config_option_requested"
                    );
                    match self
                        .protocol
                        .set_config_option(SetSessionConfigOptionRequest::new(
                            SessionId::new(session_id),
                            key.as_str().to_owned(),
                            value.as_str().to_owned(),
                        ))
                        .await
                    {
                        Ok(response) => {
                            info!(
                                conversation_id = %self.params.conversation_id,
                                agent_backend = ?self.params.metadata.backend,
                                config_id = %key,
                                desired = %value,
                                "acp_reconcile_config_option_ack"
                            );
                            let (startup_config_seed_results, invalid_mode, invalid_model, followup_actions) = {
                                let mut session = self.session.write().await;
                                if self.backend() == Some("hermes") {
                                    session.apply_command_eve_advertised_config_options(response.config_options);
                                } else {
                                    session.apply_advertised_config_options(response.config_options);
                                }
                                let startup_config_seed_results = session.resolve_pending_startup_config_seeds();
                                // Mirror the backend split from the first reconcile pass
                                // (see the `clear_invalid_command_eve_desired_mode` branch
                                // above). The plain variant validates the desired mode against
                                // the Hermes transport catalogue — but a Command EVE policy
                                // mode deliberately is NOT in that catalogue, so running it
                                // here silently discarded a valid AionCore preference.
                                let invalid_mode = if self.backend() == Some("hermes") {
                                    session.clear_invalid_command_eve_desired_mode()
                                } else {
                                    session.clear_invalid_desired_mode()
                                };
                                let invalid_model = session.clear_invalid_desired_model();
                                let followup_actions = session.plan_reconcile();
                                self.commit_session_changes(&mut session).await;
                                (
                                    startup_config_seed_results,
                                    invalid_mode,
                                    invalid_model,
                                    followup_actions,
                                )
                            };
                            self.log_reconcile_session_plan_results(
                                startup_config_seed_results,
                                invalid_mode,
                                invalid_model,
                            );
                            let mut followup_actions = followup_actions;
                            followup_actions.retain(|candidate| candidate != &executed_action);
                            actions = followup_actions.into();
                        }
                        Err(err) => {
                            if is_acp_session_not_found(&err) {
                                warn!(
                                    conversation_id = %self.params.conversation_id,
                                    config_id = %key,
                                    desired = %value,
                                    error = %err,
                                    "reconcile_session: set_config_option hit SessionNotFound; aborting reconcile"
                                );
                                return Err(err);
                            }
                            info!(
                                conversation_id = %self.params.conversation_id,
                                config_id = %key,
                                desired = %value,
                                error = %err,
                                "reconcile_session: set_config_option failed; skipping"
                            );
                            continue;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn log_reconcile_session_plan_results(
        &self,
        startup_config_seed_results: Vec<PendingStartupConfigSeedResult>,
        invalid_mode: Option<ModeId>,
        invalid_model: Option<ModelId>,
    ) {
        if let Some(mode) = invalid_mode {
            warn!(
                conversation_id = %self.params.conversation_id,
                mode_id = %mode,
                "reconcile_session: dropped unavailable desired mode"
            );
        }
        if let Some(model) = invalid_model {
            warn!(
                conversation_id = %self.params.conversation_id,
                model_id = %model,
                "reconcile_session: dropped unavailable desired model"
            );
        }
        for result in startup_config_seed_results {
            match result {
                PendingStartupConfigSeedResult::Applied { .. } => {}
                PendingStartupConfigSeedResult::OptionNotAdvertised { category } => {
                    warn!(
                        conversation_id = %self.params.conversation_id,
                        agent_backend = ?self.params.metadata.backend,
                        category = ?category,
                        reason = "option_not_advertised",
                        "reconcile_session: startup config seed not applied"
                    );
                }
                PendingStartupConfigSeedResult::ValueNotSelectable { category } => {
                    warn!(
                        conversation_id = %self.params.conversation_id,
                        agent_backend = ?self.params.metadata.backend,
                        category = ?category,
                        reason = "value_not_selectable",
                        "reconcile_session: startup config seed not applied"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::acp::AcpSession;
    use std::collections::HashMap;

    #[test]
    fn reconcile_action_equality() {
        let a = ReconcileAction::SetMode {
            mode: ModeId::new("plan"),
        };
        let b = ReconcileAction::SetMode {
            mode: ModeId::new("plan"),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn reconcile_set_config_option_ack_must_not_be_modeled_as_observed_event() {
        let mut session = AcpSession::new(
            None,
            None,
            HashMap::from([(ConfigKey::new("reasoning_effort"), ConfigValue::new("high"))]),
        );

        session.apply_observed_config(ConfigKey::new("reasoning_effort"), ConfigValue::new("medium"));
        session.drain_events();

        let actions = session.plan_reconcile();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ReconcileAction::SetConfigOption { .. }));

        let events = session.drain_events();
        assert!(events.is_empty());
    }
}
