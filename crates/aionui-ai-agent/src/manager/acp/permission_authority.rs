use agent_client_protocol::schema::{RequestPermissionRequest, ToolKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

pub const COMMAND_EVE_POLICY_PROTOCOL_VERSION: u32 = 1;
pub const COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    Default,
    AcceptEdits,
    DontAsk,
    Guarded,
}

impl PermissionMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "default" | "ask" | "fragen" => Some(Self::Default),
            "accept_edits" | "accept-edits" | "auto_edits" | "auto-edits" => Some(Self::AcceptEdits),
            "dont_ask" | "dont-ask" | "auto" => Some(Self::DontAsk),
            "guarded" | "guarded_auto" | "guarded-auto" | "dont_ask_hg4" => Some(Self::Guarded),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AcceptEdits => "accept_edits",
            Self::DontAsk => "dont_ask",
            Self::Guarded => "guarded",
        }
    }
}

/// Hermes must stay in its ask-before-execution mode. Its wider modes approve
/// edits before the request reaches AionCore and would bypass this authority.
pub fn command_eve_transport_mode(_requested: &str) -> &'static str {
    "default"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    RoutineEdit,
    RoutineTerminal,
    HardBlocked,
    Sensitive,
    Hg35,
    Hg4,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAuthority {
    User,
    Proxy,
    Founder,
}

impl RequiredAuthority {
    pub fn rank(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Proxy => 2,
            Self::Founder => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEveCapabilities {
    pub trusted_classification: bool,
    pub policy_handshake: bool,
    pub guarded_auto: bool,
    pub versioned_grant_store: bool,
    pub revocation: bool,
}

impl CommandEveCapabilities {
    pub fn guarded_auto_proven(self) -> bool {
        self.trusted_classification
            && self.policy_handshake
            && self.guarded_auto
            && self.versioned_grant_store
            && self.revocation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilityReceipt {
    pub protocol_version: u32,
    pub runtime_name: String,
    pub runtime_version: String,
    pub source_commit: Option<String>,
    pub executable_sha256: String,
    pub backend_identity: String,
    pub instance_nonce: String,
    pub capabilities: CommandEveCapabilities,
    pub receipt_digest: String,
}

impl RuntimeCapabilityReceipt {
    pub fn for_current_process(backend_identity: &str) -> io::Result<Self> {
        static EXECUTABLE_SHA256: OnceLock<Result<String, String>> = OnceLock::new();
        let executable_sha256 = EXECUTABLE_SHA256
            .get_or_init(|| hash_current_executable().map_err(|error| error.to_string()))
            .clone()
            .map_err(io::Error::other)?;
        let mut receipt = Self {
            protocol_version: COMMAND_EVE_POLICY_PROTOCOL_VERSION,
            runtime_name: "aioncore".to_owned(),
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: option_env!("AIONCORE_SOURCE_COMMIT").map(str::to_owned),
            executable_sha256,
            backend_identity: backend_identity.to_owned(),
            instance_nonce: uuid::Uuid::new_v4().to_string(),
            capabilities: CommandEveCapabilities {
                trusted_classification: true,
                policy_handshake: true,
                guarded_auto: false,
                versioned_grant_store: false,
                revocation: true,
            },
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest();
        Ok(receipt)
    }

    pub fn is_valid_for(&self, backend_identity: &str) -> bool {
        self.protocol_version == COMMAND_EVE_POLICY_PROTOCOL_VERSION
            && self.runtime_name == "aioncore"
            && self.runtime_version == env!("CARGO_PKG_VERSION")
            && self.backend_identity == backend_identity
            && self.executable_sha256.len() == 64
            && self.executable_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            && !self.instance_nonce.is_empty()
            && self.capabilities.trusted_classification
            && self.capabilities.policy_handshake
            && self.capabilities.revocation
            && self.receipt_digest == self.expected_digest()
    }

    fn expected_digest(&self) -> String {
        let payload = serde_json::json!({
            "protocol_version": self.protocol_version,
            "runtime_name": self.runtime_name,
            "runtime_version": self.runtime_version,
            "source_commit": self.source_commit,
            "executable_sha256": self.executable_sha256,
            "backend_identity": self.backend_identity,
            "instance_nonce": self.instance_nonce,
            "capabilities": self.capabilities,
        });
        format!("{:x}", Sha256::digest(serde_json::to_vec(&payload).unwrap_or_default()))
    }

    #[cfg(test)]
    pub fn test_receipt() -> Self {
        let mut receipt = Self {
            protocol_version: COMMAND_EVE_POLICY_PROTOCOL_VERSION,
            runtime_name: "aioncore".to_owned(),
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: Some("test-source".to_owned()),
            executable_sha256: "a".repeat(64),
            backend_identity: "hermes".to_owned(),
            instance_nonce: "test-instance".to_owned(),
            capabilities: CommandEveCapabilities {
                trusted_classification: true,
                policy_handshake: true,
                guarded_auto: false,
                versioned_grant_store: false,
                revocation: true,
            },
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest();
        receipt
    }

    #[cfg(test)]
    pub fn test_guarded_receipt() -> Self {
        let mut receipt = Self::test_receipt();
        receipt.capabilities.guarded_auto = true;
        receipt.capabilities.versioned_grant_store = true;
        receipt.receipt_digest = receipt.expected_digest();
        receipt
    }
}

fn hash_current_executable() -> io::Result<String> {
    let executable = std::env::current_exe()?;
    let mut file = File::open(executable)?;
    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub protocol_version: u32,
    pub policy_revision: u64,
    pub session_epoch: u64,
    pub mode: PermissionMode,
    pub capabilities: CommandEveCapabilities,
    pub runtime_receipt: RuntimeCapabilityReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPolicy {
    policy_revision: u64,
    mode: PermissionMode,
}

/// Policy authority state owned by the existing `AcpSession` aggregate.
/// Desired mode is intentionally distinct from an acknowledged snapshot.
#[derive(Debug, Clone)]
pub struct CommandEvePolicyState {
    session_epoch: u64,
    next_revision: u64,
    pending: Option<PendingPolicy>,
    acknowledged: Option<PolicySnapshot>,
    active_turn: Option<PolicySnapshot>,
    capabilities: CommandEveCapabilities,
    runtime_receipt: Option<RuntimeCapabilityReceipt>,
}

impl Default for CommandEvePolicyState {
    fn default() -> Self {
        Self {
            session_epoch: 0,
            next_revision: 1,
            pending: None,
            acknowledged: None,
            active_turn: None,
            capabilities: CommandEveCapabilities::default(),
            runtime_receipt: None,
        }
    }
}

impl CommandEvePolicyState {
    pub fn mode_available(&self, mode: PermissionMode) -> bool {
        mode != PermissionMode::Guarded || self.capabilities.guarded_auto_proven()
    }

    pub fn apply_runtime_hello(&mut self, receipt: RuntimeCapabilityReceipt) -> bool {
        if !receipt.is_valid_for("hermes") {
            self.capabilities = CommandEveCapabilities::default();
            self.runtime_receipt = None;
            self.revoke();
            return false;
        }
        self.capabilities = receipt.capabilities;
        self.runtime_receipt = Some(receipt);
        true
    }

    pub fn begin_session(&mut self) {
        self.session_epoch = self.session_epoch.saturating_add(1).max(1);
        self.pending = None;
        self.acknowledged = None;
        self.active_turn = None;
    }

    pub fn request_mode(&mut self, mode: PermissionMode) -> u64 {
        if self.pending.as_ref().is_some_and(|pending| pending.mode == mode) {
            return self
                .pending
                .as_ref()
                .map(|pending| pending.policy_revision)
                .unwrap_or(0);
        }
        if self.acknowledged.as_ref().is_some_and(|snapshot| snapshot.mode == mode) {
            self.pending = None;
            return self
                .acknowledged
                .as_ref()
                .map(|snapshot| snapshot.policy_revision)
                .unwrap_or(0);
        }
        let revision = self.take_revision();
        self.pending = Some(PendingPolicy {
            policy_revision: revision,
            mode,
        });
        // A preference change invalidates the prior turn lease immediately.
        // This prevents a previously wider policy being used while SetPolicy
        // is still pending.
        self.active_turn = None;
        revision
    }

    /// Start a real transport-backed SetPolicy transition even when the
    /// requested value equals the last acknowledgement. While the transport
    /// call is outstanding, no prior turn lease or routable snapshot survives.
    /// The mode of an outstanding, not-yet-acknowledged policy request, if any.
    ///
    /// Exists so a MACHINE-initiated caller (reconcile) can see that a human already
    /// asked for something else and step aside. `begin_mode_change` itself stays
    /// unconditional: an explicit operator choice must always win over a reconcile.
    pub fn pending_mode(&self) -> Option<PermissionMode> {
        self.pending.as_ref().map(|pending| pending.mode)
    }

    pub fn begin_mode_change(&mut self, mode: PermissionMode) -> u64 {
        if self.pending.as_ref().is_some_and(|pending| pending.mode == mode) {
            return self
                .pending
                .as_ref()
                .map(|pending| pending.policy_revision)
                .unwrap_or(0);
        }
        let revision = self.take_revision();
        self.pending = Some(PendingPolicy {
            policy_revision: revision,
            mode,
        });
        self.active_turn = None;
        revision
    }

    pub fn acknowledge_runtime_mode(&mut self, mode: PermissionMode) -> Option<PolicySnapshot> {
        if !self.mode_available(mode) {
            return None;
        }
        let runtime_receipt = self.runtime_receipt.clone()?;
        if self.session_epoch == 0 {
            return None;
        }
        if self.pending.as_ref().is_some_and(|pending| pending.mode != mode) {
            return None;
        }
        let revision = self
            .pending
            .take()
            .map(|pending| pending.policy_revision)
            .or_else(|| {
                self.acknowledged
                    .as_ref()
                    .filter(|snapshot| snapshot.mode == mode)
                    .map(|snapshot| snapshot.policy_revision)
            })
            .unwrap_or_else(|| self.take_revision());
        let snapshot = PolicySnapshot {
            protocol_version: COMMAND_EVE_POLICY_PROTOCOL_VERSION,
            policy_revision: revision,
            session_epoch: self.session_epoch,
            mode,
            capabilities: self.capabilities,
            runtime_receipt,
        };
        self.acknowledged = Some(snapshot.clone());
        Some(snapshot)
    }

    pub fn begin_turn(&mut self) -> Result<PolicySnapshot, PolicyGateError> {
        if self.pending.is_some() {
            return Err(PolicyGateError::PolicyPending);
        }
        let snapshot = self.acknowledged.clone().ok_or(PolicyGateError::UnacknowledgedPolicy)?;
        if snapshot.mode == PermissionMode::Guarded && !snapshot.capabilities.guarded_auto_proven() {
            return Err(PolicyGateError::GuardedAutoUnavailable);
        }
        self.active_turn = Some(snapshot.clone());
        Ok(snapshot)
    }

    pub fn permission_snapshot(&self) -> Result<PolicySnapshot, PolicyGateError> {
        if self.pending.is_some() {
            return Err(PolicyGateError::PolicyPending);
        }
        let current = self
            .acknowledged
            .as_ref()
            .ok_or(PolicyGateError::UnacknowledgedPolicy)?;
        let turn = self.active_turn.as_ref().ok_or(PolicyGateError::MissingTurnLease)?;
        if current.policy_revision != turn.policy_revision || current.session_epoch != turn.session_epoch {
            return Err(PolicyGateError::StaleTurnPolicy);
        }
        Ok(turn.clone())
    }

    pub fn acknowledged(&self) -> Option<&PolicySnapshot> {
        self.acknowledged.as_ref()
    }

    /// A previously acknowledged snapshot is not routable while a newer
    /// SetPolicy request is pending. This prevents transport notifications
    /// from re-publishing the old policy during an asynchronous mode change.
    pub fn routable_snapshot(&self) -> Option<&PolicySnapshot> {
        self.pending.is_none().then_some(self.acknowledged.as_ref()).flatten()
    }

    pub fn revoke(&mut self) {
        self.pending = None;
        self.acknowledged = None;
        self.active_turn = None;
    }

    fn take_revision(&mut self) -> u64 {
        let revision = self.next_revision;
        self.next_revision = self.next_revision.saturating_add(1).max(revision + 1);
        revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyGateError {
    UnsupportedPermissionMode,
    PolicyPending,
    UnacknowledgedPolicy,
    GuardedAutoUnavailable,
    MissingTurnLease,
    StaleTurnPolicy,
    UnsafeTransportMode,
}

impl std::fmt::Display for PolicyGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnsupportedPermissionMode => "Command EVE permission mode is unsupported",
            Self::PolicyPending => "Command EVE permission policy is pending runtime acknowledgement",
            Self::UnacknowledgedPolicy => "Command EVE permission policy is not acknowledged by the runtime",
            Self::GuardedAutoUnavailable => "Guarded Auto is unavailable without the complete runtime capability proof",
            Self::MissingTurnLease => "Command EVE turn has no acknowledged policy lease",
            Self::StaleTurnPolicy => "Command EVE turn policy is stale",
            Self::UnsafeTransportMode => "Command EVE Hermes transport is not pinned to default",
        };
        f.write_str(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedClassification {
    pub class: OperationClass,
    pub required_authority: Option<RequiredAuthority>,
}

impl TrustedClassification {
    pub fn new(class: OperationClass) -> Self {
        let required_authority = match class {
            OperationClass::Sensitive => Some(RequiredAuthority::User),
            OperationClass::Hg35 => Some(RequiredAuthority::Proxy),
            OperationClass::Hg4 => Some(RequiredAuthority::Founder),
            _ => None,
        };
        Self {
            class,
            required_authority,
        }
    }

    /// An EXECUTE operation the trusted classifier could not place.
    ///
    /// Deliberately not the same as a bare `Unknown`: an unclassifiable command must
    /// never end up BELOW the gate of a classified one. It stays `Unknown`, so it can
    /// never be auto-allowed and stays `Unsupported` under Guarded, and it carries
    /// owner authority so `decide` surfaces it as `AskWithOwner(User)`.
    ///
    /// HONEST SCOPE — `AskWithOwner` is METADATA, not an enforced gate. An independent
    /// review found the earlier wording here overstated it: `confirm_result` refuses an
    /// `AllowOnce` confirmation only for `RequireAuthority`, `Block` and `Unsupported`
    /// (`permission_router.rs`), and it takes no principal at all, so any conversation
    /// participant can still confirm this card. Enforcing the owner needs the principal
    /// plumbed into `confirm_result` — a design change, tracked separately. What IS
    /// guaranteed today: the class stays `Unknown`, so no auto-allow and no grant.
    pub fn unclassified_execute() -> Self {
        Self {
            class: OperationClass::Unknown,
            required_authority: Some(RequiredAuthority::User),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
    Ask,
    AskWithOwner(RequiredAuthority),
    RequireAuthority(RequiredAuthority),
    Block,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
pub struct DecisionInput {
    pub mode: PermissionMode,
    pub classification: TrustedClassification,
    pub explicit_deny: bool,
    pub exact_grant: bool,
    pub authority_receipt_verified: bool,
    pub capabilities: CommandEveCapabilities,
}

/// Binding precedence: hard policy -> trusted classification -> HumanGate ->
/// explicit deny -> exact grant -> acknowledged mode -> visible Ask.
pub fn decide(input: DecisionInput) -> PermissionDecision {
    use OperationClass as Class;

    if input.classification.class == Class::HardBlocked {
        return PermissionDecision::Block;
    }
    if input.classification.class == Class::Unknown || !input.capabilities.trusted_classification {
        return if input.mode == PermissionMode::Guarded {
            PermissionDecision::Unsupported
        } else if let Some(required) = input.classification.required_authority {
            // An unplaceable EXECUTE (see `TrustedClassification::unclassified_execute`)
            // is surfaced with its required authority attached. NOTE: today that is a
            // metadata distinction only — `confirm_result` does not treat `AskWithOwner`
            // differently from `Ask`, so this does not yet narrow WHO may confirm.
            // Edits and a disabled trusted classifier take the plain `Ask` path below.
            PermissionDecision::AskWithOwner(required)
        } else {
            PermissionDecision::Ask
        };
    }
    if let Some(required) = input.classification.required_authority {
        if matches!(required, RequiredAuthority::Proxy | RequiredAuthority::Founder) {
            if input.authority_receipt_verified {
                return if input.explicit_deny {
                    PermissionDecision::Block
                } else {
                    PermissionDecision::Allow
                };
            }
            return PermissionDecision::RequireAuthority(required);
        }
        if input.explicit_deny {
            return PermissionDecision::Block;
        }
        return PermissionDecision::AskWithOwner(required);
    }
    if input.explicit_deny {
        return PermissionDecision::Block;
    }
    if input.exact_grant {
        return PermissionDecision::Allow;
    }

    match (input.mode, input.classification.class) {
        (PermissionMode::Default, Class::RoutineEdit | Class::RoutineTerminal) => PermissionDecision::Ask,
        (PermissionMode::AcceptEdits, Class::RoutineEdit) => PermissionDecision::Allow,
        (PermissionMode::AcceptEdits, Class::RoutineTerminal) => PermissionDecision::Ask,
        (PermissionMode::DontAsk, Class::RoutineEdit | Class::RoutineTerminal) => PermissionDecision::Allow,
        (PermissionMode::Guarded, Class::RoutineEdit | Class::RoutineTerminal)
            if input.capabilities.guarded_auto_proven() =>
        {
            PermissionDecision::Allow
        }
        (PermissionMode::Guarded, _) => PermissionDecision::Unsupported,
        _ => PermissionDecision::Ask,
    }
}

pub fn classify_request(request: &RequestPermissionRequest, workspace: &str) -> TrustedClassification {
    match request.tool_call.fields.kind.as_ref() {
        Some(ToolKind::Edit) => classify_edit(request.tool_call.fields.raw_input.as_ref(), workspace),
        Some(ToolKind::Execute) => classify_command(request.tool_call.fields.raw_input.as_ref(), workspace),
        Some(ToolKind::Other) | None => classify_other(request),
        Some(ToolKind::Read)
        | Some(ToolKind::Delete)
        | Some(ToolKind::Move)
        | Some(ToolKind::Search)
        | Some(ToolKind::Think)
        | Some(ToolKind::Fetch)
        | Some(ToolKind::SwitchMode)
        | Some(_) => TrustedClassification::new(OperationClass::Unknown),
    }
}

fn classify_edit(raw: Option<&Value>, workspace: &str) -> TrustedClassification {
    let Some(raw) = raw else {
        return TrustedClassification::new(OperationClass::Unknown);
    };
    let tool = raw.get("tool").and_then(Value::as_str).unwrap_or_default();
    if tool != "write_file" {
        return TrustedClassification::new(OperationClass::Unknown);
    }
    let Some(path) = raw
        .get("arguments")
        .and_then(|arguments| arguments.get("path"))
        .and_then(Value::as_str)
    else {
        return TrustedClassification::new(OperationClass::Unknown);
    };
    let Some(path) = normalize_bound_path(path, workspace) else {
        return TrustedClassification::new(OperationClass::HardBlocked);
    };
    if is_sensitive_path(&path) || !path_is_within(&path, Path::new(workspace)) {
        return TrustedClassification::new(OperationClass::HardBlocked);
    }
    TrustedClassification::new(OperationClass::RoutineEdit)
}

fn classify_command(raw: Option<&Value>, workspace: &str) -> TrustedClassification {
    let Some(command) = raw.and_then(|raw| raw.get("command")).and_then(Value::as_str) else {
        return TrustedClassification::unclassified_execute();
    };
    let command = command.trim();
    // Collapse internal whitespace before matching. The escalation lists below are
    // substring probes, so `notarytool  submit` (two spaces) silently missed the HG-4
    // list and fell through to a plain visible Ask. Runs of any whitespace — including
    // tabs and newlines — now normalise to a single space.
    let normalized = command
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return TrustedClassification::unclassified_execute();
    }
    if contains_any(
        &normalized,
        &[
            "rm -rf /",
            "rm -fr /",
            "mkfs",
            "diskutil erase",
            ":(){ :|:& };:",
            "chmod -r 777 /",
        ],
    ) {
        return TrustedClassification::new(OperationClass::HardBlocked);
    }
    if contains_any(
        &normalized,
        &[
            "notarytool submit",
            "eve-update-proxy",
            "r2 object put",
            "production rollback",
            "founder-gate",
        ],
    ) {
        return TrustedClassification::new(OperationClass::Hg4);
    }
    if contains_any(
        &normalized,
        &[
            "git push",
            "gh pr merge",
            "npm publish",
            "cargo publish",
            "wrangler deploy",
            "vercel deploy",
            "release upload",
        ],
    ) {
        return TrustedClassification::new(OperationClass::Hg35);
    }
    if contains_any(
        &normalized,
        &[
            "curl ",
            "wget ",
            "ssh ",
            "scp ",
            "sudo ",
            "security find-",
            ".env",
            "keychain",
            "docker run",
            "npm install",
            "pnpm add",
            "pip install",
        ],
    ) {
        return TrustedClassification::new(OperationClass::Sensitive);
    }
    if let Some(classification) = classify_bounded_workspace_mutation(command, workspace) {
        return TrustedClassification::new(classification);
    }
    if is_routine_command(command) {
        TrustedClassification::new(OperationClass::RoutineTerminal)
    } else {
        // An execute we could not place. The escalation lists above are substring
        // probes and therefore evadable by ordinary, entirely legitimate spelling:
        // `git -C /repo push origin main` does not contain "git push", so it used to
        // land here and — as a bare `Unknown` — became a plain Ask that any
        // conversation participant could click, i.e. a LOWER gate than the classified
        // `git push` it is equivalent to. Unclassifiable execute now carries owner
        // authority instead.
        TrustedClassification::unclassified_execute()
    }
}

fn classify_other(request: &RequestPermissionRequest) -> TrustedClassification {
    let _ = request;
    // Tool titles and raw_input are authored by the backend/model and can be
    // spoofed. Until ACP carries a structured authenticated MCP-server
    // identity, Other never becomes routine.
    TrustedClassification::new(OperationClass::Unknown)
}

fn is_routine_command(command: &str) -> bool {
    if has_shell_syntax(command) {
        return false;
    }
    let mut words = command.split_whitespace();
    let executable = words.next().unwrap_or_default();
    match executable.rsplit('/').next().unwrap_or(executable) {
        "pwd" => words.next().is_none(),
        "ls" => words.all(|word| {
            word.starts_with('-')
                && !word.starts_with("--")
                && word[1..]
                    .chars()
                    .all(|flag| matches!(flag, 'a' | 'A' | 'l' | 'h' | 'n' | 'd' | '1'))
        }),
        _ => false,
    }
}

/// One deliberately small terminal mutation is eligible for Auto: create one
/// directory below the current workspace. The exact `--` form prevents path
/// tokens from being parsed as options; anything needing shell parsing stays
/// visible Ask. This is product semantics, not a test-only adapter.
fn classify_bounded_workspace_mutation(command: &str, workspace: &str) -> Option<OperationClass> {
    let mut words = command.split_whitespace();
    if words.next()? != "mkdir" {
        return None;
    }
    if has_shell_syntax(command) {
        return Some(OperationClass::Unknown);
    }
    if words.next() != Some("--") {
        return Some(OperationClass::Unknown);
    }
    let Some(path_value) = words.next() else {
        return Some(OperationClass::Unknown);
    };
    if words.next().is_some() {
        return Some(OperationClass::Unknown);
    }

    let raw_path = Path::new(path_value);
    if raw_path.is_absolute()
        || raw_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Some(OperationClass::HardBlocked);
    }
    let Some(bound_path) = normalize_bound_path(path_value, workspace) else {
        return Some(OperationClass::HardBlocked);
    };
    if is_sensitive_path(&bound_path) || !path_is_within(&bound_path, Path::new(workspace)) {
        return Some(OperationClass::HardBlocked);
    }
    Some(OperationClass::RoutineTerminal)
}

fn has_shell_syntax(command: &str) -> bool {
    command.chars().any(|character| {
        matches!(
            character,
            '&' | '|'
                | ';'
                | '`'
                | '$'
                | '>'
                | '<'
                | '\n'
                | '\r'
                | '\''
                | '"'
                | '\\'
                | '*'
                | '?'
                | '['
                | ']'
                | '{'
                | '}'
                | '('
                | ')'
                | '~'
                | '#'
                | '!'
        )
    })
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn normalize_bound_path(value: &str, workspace: &str) -> Option<PathBuf> {
    let raw = Path::new(value);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        Path::new(workspace).join(raw)
    };
    lexical_normalize(&joined)
}

fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let Some(path) = resolve_through_existing_ancestor(path) else {
        return false;
    };
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    path.starts_with(root)
}

fn resolve_through_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut probe = path.to_path_buf();
    let mut missing = Vec::new();
    while !probe.exists() {
        missing.push(probe.file_name()?.to_owned());
        if !probe.pop() {
            return None;
        }
    }
    let mut resolved = std::fs::canonicalize(probe).ok()?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Some(resolved)
}

fn is_sensitive_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(value.as_str(), ".git" | ".ssh" | ".gnupg" | ".aws")
            || value == ".env"
            || value.starts_with(".env.")
            || value.starts_with("id_rsa")
            || value.starts_with("id_ed25519")
    })
}

#[cfg(test)]
#[path = "permission_authority_tests.rs"]
mod tests;
