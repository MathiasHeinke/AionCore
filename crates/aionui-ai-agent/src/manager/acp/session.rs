use std::collections::HashMap;

use agent_client_protocol::schema::{
    AgentCapabilities, AuthMethod, AvailableCommand, SessionConfigKind, SessionConfigOption,
    SessionConfigOptionCategory, SessionConfigSelectOptions, SessionModeState, SessionModelState, UsageUpdate,
};

use super::agent_event_tracker::AcpSessionEvent;
use super::agent_reconcile::ReconcileAction;
use super::config_option_catalog::{
    derive_models_from_config_options, derive_modes_from_config_options, merge_config_options,
};
use super::config_options::ConfigSnapshot;
use super::permission_authority::{
    CommandEvePolicyState, PermissionMode, PolicyGateError, PolicySnapshot, RuntimeCapabilityReceipt,
};
use crate::protocol::error::CloseReason;
use crate::shared_kernel::{ConfigKey, ConfigValue, ModeId, ModelId, PersistedSessionState, SessionId};

/// What the user wants the session to be (intent).
#[derive(Debug, Clone, Default)]
struct Desired {
    mode_id: Option<ModeId>,
    model_id: Option<ModelId>,
    config_selections: HashMap<ConfigKey, ConfigValue>,
    pending_startup_config: Vec<PendingStartupConfigSeed>,
}

/// What the CLI last reported (ground truth from the backend).
#[derive(Debug, Clone, Default)]
struct Observed {
    mode_id: Option<ModeId>,
    model_id: Option<ModelId>,
    config_current: HashMap<ConfigKey, ConfigValue>,
}

/// What the CLI advertises as available options.
#[derive(Debug, Clone, Default)]
struct Advertised {
    modes: Option<SessionModeState>,
    models: Option<SessionModelState>,
    config_options: Option<Vec<SessionConfigOption>>,
    context_usage: Option<UsageUpdate>,
    agent_capabilities: Option<AgentCapabilities>,
    auth_methods: Option<Vec<AuthMethod>>,
    available_commands: Option<Vec<AvailableCommand>>,
}

/// Aggregate root for a single ACP session's lifecycle and state.
///
/// Encapsulates the three-layer state model (desired / observed / advertised)
/// and protects invariants:
/// - `session_id` is assigned at most once per lifecycle
/// - `desired.mode_id` must be in `advertised.modes` (when modes are known)
/// - `plan_reconcile` is a pure function: no side effects, fully testable
///
/// All mutations happen through aggregate methods which may emit domain
/// events (collected in `pending_events` and drained by the driver).
#[derive(Debug, Clone)]
pub struct AcpSession {
    session_id: Option<SessionId>,
    opened: bool,
    desired: Desired,
    observed: Observed,
    advertised: Advertised,
    /// Command-EVE policy lives in the existing session aggregate. Hermes'
    /// observed mode is transport state; this is the revisioned AionCore
    /// authority acknowledged for the current session epoch.
    command_eve_policy: CommandEvePolicyState,
    /// True only after a mode arrived from a live ACP response/notification.
    /// Persisted preload data is preference input and must never acknowledge a
    /// policy by itself.
    runtime_mode_attested: bool,
    config_set_in_flight: bool,
    pending_events: Vec<AcpSessionEvent>,
    /// Whether `open_session_new` has just completed and the next prompt
    /// should receive preset_context / skill-index injection.
    ///
    /// Lifecycle:
    /// - writer: `AcpAgentManager::open_session_new` after a successful
    ///   `session/new` handshake.
    /// - reader: `SessionNewPreludeHook` via `take_pending_session_new_prelude`.
    /// - invalidation: any `take_*` call drains it to `false`.
    ///
    /// Starts `false` so resume paths, warmup-only flows, and aborted
    /// session/new attempts all correctly observe "no prelude pending".
    pending_session_new_prelude: bool,
    /// Why the session most recently terminated, if at all.
    ///
    /// Lifecycle (see also `CloseReason` doc comment):
    /// - writer: `record_close_reason`, called by the manager from each
    ///   close path (`send_message` Err, `cancel`, `kill`, post-init exit
    ///   detection).
    /// - reader: `last_close_reason` (non-destructive) for diagnostics and
    ///   `take_close_reason` (drain) by the toast-builder right before the
    ///   `Error` event broadcast.
    /// - invalidation: cleared on `clear_session_id` so a rebuilt session
    ///   does not inherit the previous turn's close reason.
    last_close_reason: Option<CloseReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigSetGuardToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingStartupConfigSeed {
    category: SessionConfigOptionCategory,
    value: ConfigValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingStartupConfigSeedResult {
    Applied {
        category: SessionConfigOptionCategory,
        option_id: ConfigKey,
    },
    OptionNotAdvertised {
        category: SessionConfigOptionCategory,
    },
    ValueNotSelectable {
        category: SessionConfigOptionCategory,
    },
}

impl AcpSession {
    pub(crate) fn apply_command_eve_runtime_hello(&mut self, receipt: RuntimeCapabilityReceipt) -> bool {
        self.command_eve_policy.apply_runtime_hello(receipt)
    }

    pub fn new(
        initial_mode: Option<ModeId>,
        initial_model: Option<ModelId>,
        config_selections: HashMap<ConfigKey, ConfigValue>,
    ) -> Self {
        Self {
            session_id: None,
            opened: false,
            pending_session_new_prelude: false,
            desired: Desired {
                mode_id: initial_mode,
                model_id: initial_model,
                config_selections,
                pending_startup_config: Vec::new(),
            },
            observed: Observed::default(),
            advertised: Advertised::default(),
            command_eve_policy: CommandEvePolicyState::default(),
            runtime_mode_attested: false,
            config_set_in_flight: false,
            pending_events: Vec::new(),
            last_close_reason: None,
        }
    }
}

impl AcpSession {
    pub fn try_begin_config_set(&mut self) -> Option<ConfigSetGuardToken> {
        if self.config_set_in_flight {
            return None;
        }
        self.config_set_in_flight = true;
        Some(ConfigSetGuardToken)
    }

    pub fn end_config_set(&mut self, _token: ConfigSetGuardToken) {
        self.config_set_in_flight = false;
    }
}

// ─── Session Id and Session Opened ───────────────────────────────────────────────────────
impl AcpSession {
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_ref().map(SessionId::as_str)
    }

    pub fn session_id_vo(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    /// Assign (or restore) a session ID. Idempotent: re-assigning the same
    /// ID is a no-op. Assigning a *different* ID after one is already set
    /// is an invariant violation (the aggregate must be recreated).
    pub fn set_session_id(&mut self, sid: SessionId) {
        if let Some(existing) = &self.session_id {
            debug_assert_eq!(existing, &sid, "session_id reassignment attempted");
            return;
        }
        self.session_id = Some(sid.clone());
        self.command_eve_policy.begin_session();
        if self.runtime_mode_attested
            && let Some(mode) = self
                .observed
                .mode_id
                .as_ref()
                .and_then(|mode| PermissionMode::parse(mode.as_str()))
        {
            self.command_eve_policy.acknowledge_runtime_mode(mode);
        }
        if let Some(desired) = self
            .desired
            .mode_id
            .as_ref()
            .and_then(|mode| PermissionMode::parse(mode.as_str()))
            && self.command_eve_policy.acknowledged().map(|snapshot| snapshot.mode) != Some(desired)
        {
            self.command_eve_policy.request_mode(desired);
        }
        self.pending_events
            .push(AcpSessionEvent::SessionAssigned { session_id: sid });
    }

    /// Drop a stale session id so the aggregate can be re-seeded with a
    /// freshly-issued one. Used when the CLI rejects the persisted sid
    /// with `SessionNotFound` (ELECTRON-1HQ): the resume helpers fall
    /// back to `open_session_new`, which calls `set_session_id` again.
    /// Also clears the `opened` flag so the next `ensure_session_opened`
    /// goes down the "no sid" branch instead of the "sid+opened" no-op.
    pub fn clear_session_id(&mut self) {
        self.session_id = None;
        self.opened = false;
        // A rebuilt session must not inherit the prior turn's close reason —
        // otherwise the next user-facing error would surface stale context.
        self.last_close_reason = None;
        self.runtime_mode_attested = false;
        self.command_eve_policy.revoke();
    }

    /// Record the reason the most recent turn closed. Overwrites any
    /// previous reason — only the latest one is meaningful for the next
    /// user-facing toast. Pass `None` to clear (rare; mostly used by tests
    /// and `clear_session_id`).
    pub fn record_close_reason(&mut self, reason: Option<CloseReason>) {
        self.last_close_reason = reason;
    }

    /// Read the last close reason without consuming it. Used for
    /// diagnostics and for tests.
    pub fn last_close_reason(&self) -> Option<&CloseReason> {
        self.last_close_reason.as_ref()
    }

    /// Drain the last close reason. Called by the close-path handler in
    /// `AcpAgentManager` right before broadcasting the `Error` event so
    /// the same reason is not re-rendered on a follow-up request.
    pub fn take_close_reason(&mut self) -> Option<CloseReason> {
        self.last_close_reason.take()
    }

    pub fn is_opened(&self) -> bool {
        self.opened
    }

    /// Mark the session as opened with the CLI (first turn handshake complete).
    pub fn mark_opened(&mut self) {
        if !self.opened {
            self.opened = true;
            self.pending_events.push(AcpSessionEvent::SessionOpened);
        }
    }

    /// Set the flag signalling that the next prompt carries the first
    /// post-`session/new` payload. Idempotent.
    pub fn mark_pending_session_new_prelude(&mut self) {
        self.pending_session_new_prelude = true;
    }

    /// Consume the prelude flag. Returns `true` exactly once after
    /// `mark_pending_session_new_prelude`; subsequent calls return `false`.
    pub fn take_pending_session_new_prelude(&mut self) -> bool {
        std::mem::replace(&mut self.pending_session_new_prelude, false)
    }
}

// ─── Getters Setters desired ───────────────────────────────────────────────────────
impl AcpSession {
    pub fn desired_mode(&self) -> Option<&str> {
        self.desired.mode_id.as_ref().map(ModeId::as_str)
    }

    pub fn desired_mode_id(&self) -> Option<&ModeId> {
        self.desired.mode_id.as_ref()
    }

    pub fn desired_model(&self) -> Option<&str> {
        self.desired.model_id.as_ref().map(ModelId::as_str)
    }

    pub fn desired_model_id(&self) -> Option<&ModelId> {
        self.desired.model_id.as_ref()
    }

    pub fn desired_config_selections(&self) -> &HashMap<ConfigKey, ConfigValue> {
        &self.desired.config_selections
    }

    /// Whether the requested model can be selected in the current session.
    ///
    /// Before the ACP backend advertises models, keep the historical permissive
    /// behavior so initial seeds can still be reconciled once the session opens.
    pub fn can_select_model(&self, model_id: &str) -> bool {
        !model_id.is_empty() && self.is_model_valid(model_id)
    }

    /// Whether the requested mode can be selected in the current session.
    ///
    /// Before the ACP backend advertises modes, keep the historical permissive
    /// behavior so initial seeds can still be reconciled once the session opens.
    pub fn can_select_mode(&self, mode_id: &str) -> bool {
        !mode_id.is_empty() && self.is_mode_valid(mode_id)
    }

    /// Set the user's desired mode. Emits `DesiredModeChanged` if the
    /// value actually changed. When advertised modes are known, the mode
    /// must be in the list (otherwise the call is a no-op).
    pub fn set_desired_mode(&mut self, mode: ModeId) -> bool {
        if mode.as_str().is_empty() {
            return false;
        }
        if !self.is_mode_valid(mode.as_str()) {
            return false;
        }
        if self.desired.mode_id.as_ref() == Some(&mode) {
            return false;
        }
        self.desired.mode_id = Some(mode.clone());
        if let Some(permission_mode) = PermissionMode::parse(mode.as_str()) {
            self.command_eve_policy.request_mode(permission_mode);
        }
        self.pending_events.push(AcpSessionEvent::DesiredModeChanged { mode });
        true
    }

    /// Start a Command EVE SetPolicy transition before the Hermes transport
    /// request is awaited. Unlike generic ACP mode selection, the policy is
    /// validated against AionCore's four-mode contract rather than Hermes'
    /// deliberately pinned transport catalog.
    pub(crate) fn request_command_eve_policy(&mut self, mode: ModeId) -> Result<(), PolicyGateError> {
        let Some(permission_mode) = PermissionMode::parse(mode.as_str()) else {
            self.command_eve_policy.revoke();
            return Err(PolicyGateError::UnsupportedPermissionMode);
        };
        if !self.command_eve_policy.mode_available(permission_mode) {
            self.command_eve_policy.revoke();
            return Err(PolicyGateError::GuardedAutoUnavailable);
        }
        let changed = self.desired.mode_id.as_ref() != Some(&mode);
        self.desired.mode_id = Some(mode.clone());
        self.command_eve_policy.begin_mode_change(permission_mode);
        if changed {
            self.pending_events.push(AcpSessionEvent::DesiredModeChanged { mode });
        }
        Ok(())
    }

    /// Set the user's desired model. Emits `DesiredModelChanged` if the
    /// value actually changed. When advertised models are known, the model
    /// must be in the list (otherwise the call is a no-op).
    pub fn set_desired_model(&mut self, model: ModelId) -> bool {
        if model.as_str().is_empty() {
            return false;
        }
        if !self.is_model_valid(model.as_str()) {
            return false;
        }
        if self.desired.model_id.as_ref() == Some(&model) {
            return false;
        }
        self.desired.model_id = Some(model.clone());
        self.pending_events.push(AcpSessionEvent::DesiredModelChanged { model });
        true
    }

    /// Drop a desired model that is not advertised by the active ACP session.
    ///
    /// Initial model seeds can be loaded before `session/new` reports the
    /// provider's available models. Once advertised models are known, reconcile
    /// must not issue `session/set_model` for a stale seed.
    pub fn clear_invalid_desired_model(&mut self) -> Option<ModelId> {
        let model = self.desired.model_id.clone()?;
        if self.is_model_valid(model.as_str()) {
            return None;
        }
        self.desired.model_id = None;
        Some(model)
    }

    /// Drop a desired mode that is not advertised by the active ACP session.
    ///
    /// Initial mode seeds can be loaded before `session/new` reports the
    /// provider's available modes. Once advertised modes are known, reconcile
    /// must not issue `session/set_mode` for a stale seed.
    pub fn clear_invalid_desired_mode(&mut self) -> Option<ModeId> {
        let mode = self.desired.mode_id.clone()?;
        if self.is_mode_valid(mode.as_str()) {
            return None;
        }
        self.desired.mode_id = None;
        Some(mode)
    }

    /// Command EVE policy modes are AionCore-owned and intentionally absent
    /// from Hermes' transport catalog. Validate them against the policy
    /// protocol instead of the generic advertised-mode list.
    pub(crate) fn clear_invalid_command_eve_desired_mode(&mut self) -> Option<ModeId> {
        let mode = self.desired.mode_id.clone()?;
        let valid = PermissionMode::parse(mode.as_str())
            .is_some_and(|permission_mode| self.command_eve_policy.mode_available(permission_mode));
        if valid {
            return None;
        }
        self.desired.mode_id = None;
        Some(mode)
    }

    /// Set a user's desired config selection.
    pub fn set_desired_config(&mut self, key: ConfigKey, value: ConfigValue) {
        let changed = self.desired.config_selections.get(&key) != Some(&value);
        self.desired.config_selections.insert(key, value);
        if changed {
            let selections = self.desired.config_selections.clone();
            self.pending_events
                .push(AcpSessionEvent::DesiredConfigChanged { selections });
        }
    }

    pub(crate) fn seed_pending_startup_config(&mut self, category: SessionConfigOptionCategory, value: ConfigValue) {
        if value.as_str().is_empty() {
            return;
        }
        if self
            .desired
            .pending_startup_config
            .iter()
            .any(|seed| seed.category == category && seed.value == value)
        {
            return;
        }
        self.desired
            .pending_startup_config
            .push(PendingStartupConfigSeed { category, value });
    }

    pub(crate) fn resolve_pending_startup_config_seeds(&mut self) -> Vec<PendingStartupConfigSeedResult> {
        let seeds = std::mem::take(&mut self.desired.pending_startup_config);
        if seeds.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(seeds.len());
        for seed in seeds {
            let Some(options) = self.advertised.config_options.as_ref() else {
                self.handle_unresolved_startup_config_seed(&seed, false);
                results.push(PendingStartupConfigSeedResult::OptionNotAdvertised {
                    category: seed.category,
                });
                continue;
            };

            let Some(option) = select_option_for_startup_seed(options, &seed.category) else {
                self.handle_unresolved_startup_config_seed(&seed, false);
                results.push(PendingStartupConfigSeedResult::OptionNotAdvertised {
                    category: seed.category,
                });
                continue;
            };

            if !select_option_contains_value(&option.kind, seed.value.as_str()) {
                self.handle_unresolved_startup_config_seed(&seed, true);
                results.push(PendingStartupConfigSeedResult::ValueNotSelectable {
                    category: seed.category,
                });
                continue;
            }

            let option_id = ConfigKey::new(option.id.to_string());
            self.clear_legacy_desired_for_config_category(&seed.category);
            self.set_desired_config(option_id.clone(), seed.value);
            results.push(PendingStartupConfigSeedResult::Applied {
                category: seed.category,
                option_id,
            });
        }
        results
    }

    /// Convert any real ACP `category=Mode` config selection into the
    /// AionCore-owned Command EVE policy lane. The raw config selection is
    /// removed so reconcile can never emit `session/set_config_option` for it.
    pub(crate) fn migrate_command_eve_mode_config_intent(&mut self) -> Result<Option<ModeId>, PolicyGateError> {
        let mode_keys = self
            .advertised
            .config_options
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|option| is_mode_config_option(option))
            .map(|option| ConfigKey::new(option.id.to_string()))
            .collect::<Vec<_>>();
        let mut selected = None;
        let mut changed = false;
        for key in mode_keys {
            if let Some(value) = self.desired.config_selections.remove(&key) {
                selected = Some(ModeId::new(value.as_str()));
                changed = true;
            }
        }
        if changed {
            self.pending_events.push(AcpSessionEvent::DesiredConfigChanged {
                selections: self.desired.config_selections.clone(),
            });
        }
        let Some(mode) = selected else {
            return Ok(None);
        };
        self.request_command_eve_policy(mode.clone())?;
        Ok(Some(mode))
    }

    fn clear_legacy_desired_for_config_category(&mut self, category: &SessionConfigOptionCategory) {
        match category {
            SessionConfigOptionCategory::Mode => {
                self.desired.mode_id = None;
            }
            SessionConfigOptionCategory::Model => {
                self.desired.model_id = None;
            }
            _ => {}
        }
    }

    fn handle_unresolved_startup_config_seed(&mut self, seed: &PendingStartupConfigSeed, option_was_advertised: bool) {
        match seed.category {
            SessionConfigOptionCategory::Mode | SessionConfigOptionCategory::Model if !option_was_advertised => {
                // Keep legacy desired mode/model so old ACP implementations still use set_mode/set_model.
            }
            SessionConfigOptionCategory::Mode | SessionConfigOptionCategory::Model => {
                self.clear_legacy_desired_for_config_category(&seed.category);
            }
            SessionConfigOptionCategory::ThoughtLevel if !option_was_advertised => {
                self.seed_pending_startup_config(seed.category.clone(), seed.value.clone());
            }
            _ => {}
        }
    }
}

// ─── Getters observed ───────────────────────────────────────────────────────
impl AcpSession {
    pub fn observed_mode(&self) -> Option<&str> {
        self.observed.mode_id.as_ref().map(ModeId::as_str)
    }

    pub fn observed_mode_id(&self) -> Option<&ModeId> {
        self.observed.mode_id.as_ref()
    }

    pub fn observed_model(&self) -> Option<&str> {
        self.observed.model_id.as_ref().map(ModelId::as_str)
    }

    pub fn observed_model_id(&self) -> Option<&ModelId> {
        self.observed.model_id.as_ref()
    }
}

// ─── Getters advertised ───────────────────────────────────────────────────────
impl AcpSession {
    pub fn modes(&self) -> Option<&SessionModeState> {
        self.advertised.modes.as_ref()
    }

    pub fn model_info(&self) -> Option<&SessionModelState> {
        self.advertised.models.as_ref()
    }

    pub fn config_options(&self) -> Option<&[SessionConfigOption]> {
        self.advertised.config_options.as_deref()
    }

    pub(crate) fn config_snapshot(&self) -> ConfigSnapshot {
        let mut snapshot = if let Some(options) = self.advertised.config_options.clone() {
            ConfigSnapshot::from_real_options(options)
        } else {
            ConfigSnapshot::from_legacy_catalogs(self.advertised.modes.as_ref(), self.advertised.models.as_ref())
        };
        if let Some(policy) = self.command_eve_policy.acknowledged() {
            for mode in snapshot
                .options
                .iter_mut()
                .filter(|option| option.id == "mode" || option.category.as_deref() == Some("mode"))
            {
                mode.current_value = Some(policy.mode.as_str().to_owned());
            }
        }
        snapshot
    }

    pub fn context_usage(&self) -> Option<&UsageUpdate> {
        self.advertised.context_usage.as_ref()
    }

    pub fn agent_capabilities(&self) -> Option<&AgentCapabilities> {
        self.advertised.agent_capabilities.as_ref()
    }

    pub fn auth_methods(&self) -> Option<&[AuthMethod]> {
        self.advertised.auth_methods.as_deref()
    }

    pub fn available_commands(&self) -> Option<&[AvailableCommand]> {
        self.advertised.available_commands.as_deref()
    }

    pub fn current_mode_id(&self) -> Option<String> {
        self.advertised.modes.as_ref().map(|m| m.current_mode_id.to_string())
    }

    pub fn current_model_id(&self) -> Option<String> {
        self.advertised.models.as_ref().map(|m| m.current_model_id.to_string())
    }
}

// ─── Observations (from CLI responses/notifications) ───────────────
impl AcpSession {
    /// Record the CLI's current mode. Updates both `observed.mode_id` and
    /// the `advertised.modes.current_mode_id` (available_modes preserved);
    /// emits `ObservedModeSynced` when the value actually changed.
    pub fn apply_observed_mode(&mut self, mode: ModeId) {
        let changed = self.observed.mode_id.as_ref() != Some(&mode);
        self.observed.mode_id = Some(mode.clone());
        self.runtime_mode_attested = true;
        if let Some(permission_mode) = PermissionMode::parse(mode.as_str()) {
            self.command_eve_policy.acknowledge_runtime_mode(permission_mode);
        }
        let available = self
            .advertised
            .modes
            .as_ref()
            .map(|m| m.available_modes.clone())
            .unwrap_or_default();
        self.advertised.modes = Some(SessionModeState::new(mode.as_str().to_owned(), available));
        if changed {
            self.pending_events.push(AcpSessionEvent::ObservedModeSynced { mode });
        }
    }

    /// Record Hermes' real transport mode without treating it as a Command
    /// EVE policy acknowledgement. Hermes remains pinned to `default`; the
    /// selected AionCore policy is a separate server-local state machine.
    pub fn apply_command_eve_transport_mode(&mut self, mode: ModeId) -> bool {
        let safe = mode.as_str() == "default";
        if !safe {
            self.command_eve_policy.revoke();
        }
        self.observed.mode_id = Some(mode.clone());
        let available = self
            .advertised
            .modes
            .as_ref()
            .map(|m| m.available_modes.clone())
            .unwrap_or_default();
        self.advertised.modes = Some(SessionModeState::new(mode.as_str().to_owned(), available));
        safe
    }

    /// Record the CLI's current model. Updates both `observed.model_id` and
    /// the `advertised.models.current_model_id` (available_models preserved);
    /// emits `ObservedModelSynced` when the value actually changed.
    pub fn apply_observed_model(&mut self, model: ModelId) {
        let changed = self.observed.model_id.as_ref() != Some(&model);
        self.observed.model_id = Some(model.clone());
        let available = self
            .advertised
            .models
            .as_ref()
            .map(|m| m.available_models.clone())
            .unwrap_or_default();
        self.advertised.models = Some(SessionModelState::new(model.as_str().to_owned(), available));
        if changed {
            self.pending_events.push(AcpSessionEvent::ObservedModelSynced { model });
        }
    }

    /// Confirm a user command after the ACP backend accepted it.
    ///
    /// Unlike `apply_observed_mode`, this also aligns the pending intent so
    /// a later startup/recovery reconcile does not pull the session back to
    /// the previous desired mode.
    pub fn confirm_mode(&mut self, mode: ModeId) {
        self.desired.mode_id = Some(mode.clone());
        self.apply_observed_mode(mode);
    }

    /// Acknowledge the AionCore-owned Command EVE policy only after the
    /// synchronous Hermes `session/set_mode(default)` transport call succeeds.
    /// This deliberately leaves observed/advertised transport state unchanged.
    pub fn acknowledge_command_eve_policy(&mut self, mode: ModeId) -> Option<PolicySnapshot> {
        let permission_mode = PermissionMode::parse(mode.as_str())?;
        if !self.command_eve_policy.mode_available(permission_mode) {
            return None;
        }
        if self.desired.mode_id.as_ref() != Some(&mode) {
            self.desired.mode_id = Some(mode.clone());
            self.pending_events.push(AcpSessionEvent::DesiredModeChanged { mode });
        }
        // P1 (C7 integrator review): do NOT force `pending` to the acknowledged mode
        // here. `acknowledge_runtime_mode` guards against a stale acknowledgement with
        // `if pending.mode != mode { return None }` — rewriting `pending` first made
        // that guard unreachable, so a slow reconcile acknowledgement returning
        // `dont_ask` could replace a NARROWER policy the user had meanwhile chosen.
        // Without the rewrite the guard rejects the stale ack (both callers already
        // treat `None` as a failure), and an acknowledgement with no pending request
        // still succeeds through the `or_else`/`take_revision` path below.
        self.command_eve_policy.acknowledge_runtime_mode(permission_mode)
    }

    /// Confirm a user command after the ACP backend accepted it.
    ///
    /// Unlike `apply_observed_model`, this also aligns the pending intent so
    /// a later startup/recovery reconcile does not pull the session back to
    /// the previous desired model.
    pub fn confirm_model(&mut self, model: ModelId) {
        self.desired.model_id = Some(model.clone());
        self.apply_observed_model(model);
    }

    /// Record the CLI's current value for a single config option. Mirrors
    /// `apply_observed_mode/model`: diff-driven, emits `ObservedConfigSynced`
    /// with the full selection map when the value actually changed. Used by
    /// the reconcile loop after a successful `set_config_option` so
    /// `plan_reconcile` treats the drift as resolved.
    pub fn apply_observed_config(&mut self, key: ConfigKey, value: ConfigValue) {
        let changed = self.observed.config_current.get(&key) != Some(&value);
        self.observed.config_current.insert(key, value);
        if changed {
            let selections = self.observed.config_current.clone();
            self.pending_events
                .push(AcpSessionEvent::ObservedConfigSynced { selections });
        }
    }

    pub fn apply_advertised_modes(&mut self, modes: SessionModeState) {
        let new_id = ModeId::new(modes.current_mode_id.to_string());
        let changed = self.observed.mode_id.as_ref() != Some(&new_id);
        self.observed.mode_id = Some(new_id.clone());
        self.runtime_mode_attested = true;
        if let Some(permission_mode) = PermissionMode::parse(new_id.as_str()) {
            self.command_eve_policy.acknowledge_runtime_mode(permission_mode);
        }
        self.advertised.modes = Some(modes);
        if changed {
            self.pending_events
                .push(AcpSessionEvent::ObservedModeSynced { mode: new_id });
        }
    }

    /// Store Hermes' advertised transport catalog/current mode without using
    /// it as PolicyApplied and without emitting a persisted policy preference.
    pub fn apply_command_eve_transport_modes(&mut self, modes: SessionModeState) -> bool {
        let new_id = ModeId::new(modes.current_mode_id.to_string());
        let safe = new_id.as_str() == "default";
        if !safe {
            self.command_eve_policy.revoke();
        }
        self.observed.mode_id = Some(new_id);
        self.advertised.modes = Some(modes);
        safe
    }

    pub fn apply_advertised_models(&mut self, models: SessionModelState) {
        let new_id = ModelId::new(models.current_model_id.to_string());
        let changed = self.observed.model_id.as_ref() != Some(&new_id);
        self.observed.model_id = Some(new_id.clone());
        self.advertised.models = Some(models);
        if changed {
            self.pending_events
                .push(AcpSessionEvent::ObservedModelSynced { model: new_id });
        }
    }

    fn preserve_desired_model_in_catalog(&self, models: SessionModelState) -> SessionModelState {
        let Some(desired_model) = self.desired.model_id.as_ref() else {
            return models;
        };
        let desired_model_id = desired_model.as_str();
        if models.current_model_id.to_string() == desired_model_id {
            return models;
        }
        if models
            .available_models
            .iter()
            .any(|model| model.model_id.to_string() == desired_model_id)
        {
            return SessionModelState::new(desired_model_id.to_owned(), models.available_models.clone());
        }
        models
    }

    pub fn apply_advertised_config_options(&mut self, options: Vec<SessionConfigOption>) {
        self.apply_advertised_config_options_inner(options, true);
    }

    /// Store Hermes config options without allowing a real `category=Mode`
    /// option to mutate transport state or acknowledge an AionCore policy.
    pub(crate) fn apply_command_eve_advertised_config_options(&mut self, options: Vec<SessionConfigOption>) {
        self.apply_advertised_config_options_inner(options, false);
    }

    fn apply_advertised_config_options_inner(&mut self, options: Vec<SessionConfigOption>, derive_mode: bool) {
        let options = merge_config_options(self.advertised.config_options.as_deref(), options);

        if derive_mode && let Some(modes) = derive_modes_from_config_options(&options) {
            self.apply_advertised_modes(modes);
        }

        if let Some(models) = derive_models_from_config_options(&options) {
            self.apply_advertised_models(self.preserve_desired_model_in_catalog(models));
        }

        let mut changed = false;
        for opt in &options {
            if !derive_mode && is_mode_config_option(opt) {
                let key = ConfigKey::new(opt.id.to_string());
                changed |= self.observed.config_current.remove(&key).is_some();
                continue;
            }
            if let Some(current) = extract_config_current_value(&opt.kind) {
                let key = ConfigKey::new(opt.id.to_string());
                let value = ConfigValue::new(current);
                if self.observed.config_current.insert(key, value.clone()).as_ref() != Some(&value) {
                    changed = true;
                }
            }
        }
        self.advertised.config_options = Some(options);
        if changed {
            let selections = self.observed.config_current.clone();
            self.pending_events
                .push(AcpSessionEvent::ObservedConfigSynced { selections });
        }
    }

    pub fn apply_advertised_capabilities(&mut self, caps: AgentCapabilities) {
        self.advertised.agent_capabilities = Some(caps);
    }

    pub fn apply_advertised_auth_methods(&mut self, methods: Vec<AuthMethod>) {
        self.advertised.auth_methods = Some(methods);
    }

    pub fn apply_advertised_commands(&mut self, commands: Vec<AvailableCommand>) {
        self.advertised.available_commands = Some(commands);
    }

    /// Record the CLI's latest context usage. Diff-driven: emits
    /// `ObservedContextUsageChanged` only when the usage payload differs
    /// from what we last cached, so the persistence consumer can debounce
    /// a stream of token updates into one DB write per turn.
    pub fn apply_context_usage(&mut self, usage: UsageUpdate) {
        let changed = self.advertised.context_usage.as_ref() != Some(&usage);
        self.advertised.context_usage = Some(usage.clone());
        if changed {
            let usage_json = serde_json::to_string(&usage).unwrap_or_default();
            self.pending_events
                .push(AcpSessionEvent::ObservedContextUsageChanged { usage_json });
        }
    }
}

impl AcpSession {
    /// Seed the aggregate with persisted user choices from DB.
    /// Called on resume paths before the CLI session/load response arrives.
    pub fn preload_persisted(&mut self, state: &PersistedSessionState) {
        if let Some(mode) = &state.current_mode_id {
            self.advertised.modes = Some(SessionModeState::new(mode.as_str().to_owned(), Vec::new()));
            self.observed.mode_id = Some(mode.clone());
            self.runtime_mode_attested = false;
        }
        if let Some(model) = &state.current_model_id {
            self.advertised.models = Some(SessionModelState::new(model.as_str().to_owned(), Vec::new()));
            self.observed.model_id = Some(model.clone());
        }
        if !state.config_selections.is_empty() {
            self.observed.config_current = state.config_selections.clone();
        }
        if let Some(usage) = &state.context_usage {
            self.advertised.context_usage = Some(usage.clone());
        }
    }
}

// ─── Command EVE permission policy handshake ───────────────────────
impl AcpSession {
    /// Bind a user turn to the exact runtime-acknowledged policy revision.
    pub(crate) fn begin_command_eve_turn(&mut self) -> Result<PolicySnapshot, PolicyGateError> {
        if self.observed_mode() != Some("default") {
            self.command_eve_policy.revoke();
            return Err(PolicyGateError::UnsafeTransportMode);
        }
        self.command_eve_policy.begin_turn()
    }

    /// Policy snapshot that owns a permission created by the active turn.
    pub(crate) fn command_eve_permission_snapshot(
        &self,
        request_session_id: &str,
    ) -> Result<PolicySnapshot, PolicyGateError> {
        if self.session_id() != Some(request_session_id) {
            return Err(PolicyGateError::StaleTurnPolicy);
        }
        if self.observed_mode() != Some("default") {
            return Err(PolicyGateError::UnsafeTransportMode);
        }
        self.command_eve_policy.permission_snapshot()
    }

    pub(crate) fn command_eve_policy_snapshot(&self) -> Option<PolicySnapshot> {
        self.command_eve_policy.routable_snapshot().cloned()
    }

    pub(crate) fn command_eve_policy_acknowledged(&self) -> bool {
        self.command_eve_policy.routable_snapshot().is_some()
    }

    pub(crate) fn ensure_command_eve_mode_available(&self, mode: &str) -> Result<(), PolicyGateError> {
        if PermissionMode::parse(mode) == Some(PermissionMode::Guarded)
            && !self.command_eve_policy.mode_available(PermissionMode::Guarded)
        {
            return Err(PolicyGateError::GuardedAutoUnavailable);
        }
        Ok(())
    }
}

// ─── Reconcile ─────────────────────────────────────────────────────
impl AcpSession {
    /// Produce a list of actions needed to align CLI state with user intent.
    /// Pure function — no side effects. The driver executes the actions.
    pub fn plan_reconcile(&self) -> Vec<ReconcileAction> {
        let mut actions = Vec::new();

        if let Some(desired_mode) = &self.desired.mode_id
            && !self.command_eve_policy.routable_snapshot().is_some_and(|policy| {
                policy.mode.as_str() == desired_mode.as_str() && self.observed_mode() == Some("default")
            })
            && self.observed.mode_id.as_ref() != Some(desired_mode)
            && PermissionMode::parse(desired_mode.as_str())
                .is_none_or(|mode| self.command_eve_policy.mode_available(mode))
        {
            actions.push(ReconcileAction::SetMode {
                mode: desired_mode.clone(),
            });
        }

        if let Some(desired_model) = &self.desired.model_id
            && self.observed.model_id.as_ref() != Some(desired_model)
        {
            actions.push(ReconcileAction::SetModel {
                model: desired_model.clone(),
            });
        }

        for (key, desired_value) in &self.desired.config_selections {
            if self.observed.config_current.get(key) != Some(desired_value) {
                actions.push(ReconcileAction::SetConfigOption {
                    key: key.clone(),
                    value: desired_value.clone(),
                });
            }
        }

        actions
    }

    // ─── Event drain ───────────────────────────────────────────────────

    /// Consume and return all pending domain events.
    pub fn drain_events(&mut self) -> Vec<AcpSessionEvent> {
        std::mem::take(&mut self.pending_events)
    }

    // ─── Private helpers ───────────────────────────────────────────────

    fn is_mode_valid(&self, mode_id: &str) -> bool {
        match &self.advertised.modes {
            None => true,
            Some(modes) if modes.available_modes.is_empty() => true,
            Some(modes) => modes.available_modes.iter().any(|m| m.id.0.as_ref() == mode_id),
        }
    }

    fn is_model_valid(&self, model_id: &str) -> bool {
        match &self.advertised.models {
            None => true,
            Some(models) if models.available_models.is_empty() => true,
            Some(models) => models
                .available_models
                .iter()
                .any(|m| m.model_id.0.as_ref() == model_id),
        }
    }
}

fn is_mode_config_option(option: &SessionConfigOption) -> bool {
    option.id.to_string() == "mode" || option.category == Some(SessionConfigOptionCategory::Mode)
}

fn extract_config_current_value(kind: &SessionConfigKind) -> Option<String> {
    match kind {
        SessionConfigKind::Select(sel) => Some(sel.current_value.to_string()),
        _ => None,
    }
}

fn select_option_for_startup_seed<'a>(
    options: &'a [SessionConfigOption],
    category: &SessionConfigOptionCategory,
) -> Option<&'a SessionConfigOption> {
    options
        .iter()
        .find(|option| option.category.as_ref() == Some(category))
        .or_else(|| {
            let aliases = config_option_aliases_for_category(category);
            options.iter().find(|option| {
                let option_id = option.id.to_string();
                aliases.iter().any(|alias| *alias == option_id)
            })
        })
}

fn config_option_aliases_for_category(category: &SessionConfigOptionCategory) -> &'static [&'static str] {
    match category {
        SessionConfigOptionCategory::Mode => &["mode", "modes"],
        SessionConfigOptionCategory::Model => &["model", "models"],
        SessionConfigOptionCategory::ThoughtLevel => &[
            "thought_level",
            "reasoning_effort",
            "effort",
            "thinking_budget",
            "thinking",
        ],
        _ => &[],
    }
}

fn select_option_contains_value(kind: &SessionConfigKind, value: &str) -> bool {
    match kind {
        SessionConfigKind::Select(select) => match &select.options {
            SessionConfigSelectOptions::Ungrouped(options) => {
                options.iter().any(|option| option.value.to_string() == value)
            }
            SessionConfigSelectOptions::Grouped(groups) => groups
                .iter()
                .flat_map(|group| group.options.iter())
                .any(|option| option.value.to_string() == value),
            _ => false,
        },
        _ => false,
    }
}

// Tests live in `session_tests.rs` (linked via `#[path]`) so this file
// stays under the 1000-line per-file budget. Inside that file `super::*`
// resolves to this module's private items.
#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
