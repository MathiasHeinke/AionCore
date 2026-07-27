use super::*;
use crate::agent_task::ConfirmationPrincipalContext;
use crate::manager::acp::AcpSession;
use crate::manager::acp::agent::prepare_command_eve_policy_change_state;
use crate::manager::acp::permission_authority::{PermissionMode, RuntimeCapabilityReceipt};
use crate::shared_kernel::{ModeId, SessionId};
use agent_client_protocol::schema::{
    PermissionOption, PermissionOptionKind, RequestPermissionRequest, SessionMode, SessionModeState, ToolCallUpdate,
    ToolCallUpdateFields, ToolKind,
};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};

fn policy(mode: PermissionMode) -> PolicySnapshot {
    let mut session = AcpSession::new(Some(ModeId::new(mode.as_str())), None, Default::default());
    assert!(session.apply_command_eve_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    assert!(session.apply_command_eve_transport_modes(SessionModeState::new(
        "default",
        vec![SessionMode::new("default", "Ask")],
    )));
    session.set_session_id(SessionId::new("session-1"));
    assert!(
        session
            .acknowledge_command_eve_policy(ModeId::new(mode.as_str()))
            .is_some()
    );
    session.begin_command_eve_turn().unwrap()
}

fn authority(class: OperationClass, mode: PermissionMode, digest: &str) -> CommandEveAuthority {
    let policy = policy(mode);
    let classification = TrustedClassification::new(class);
    let decision = decide(DecisionInput {
        mode,
        classification,
        explicit_deny: false,
        exact_grant: false,
        authority_receipt_verified: false,
        capabilities: policy.capabilities,
    });
    CommandEveAuthority {
        operation_digest: digest.to_owned(),
        policy: Some(policy),
        classification,
        decision,
        grant_eligible: matches!(class, OperationClass::RoutineEdit | OperationClass::RoutineTerminal),
        authority_nonce: matches!(class, OperationClass::Hg35 | OperationClass::Hg4).then(|| format!("nonce-{digest}")),
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

fn confirmation(call_id: &str) -> Confirmation {
    Confirmation {
        id: call_id.to_owned(),
        call_id: call_id.to_owned(),
        title: Some("Bound operation".to_owned()),
        action: None,
        description: "Bound operation".to_owned(),
        command_type: Some("execute".to_owned()),
        options: vec![aionui_common::ConfirmationOption {
            label: "Allow".to_owned(),
            value: json!("allow_once"),
            params: None,
        }],
        authority: None,
    }
}

fn insert(
    router: &PermissionRouter,
    call_id: &str,
    authority: CommandEveAuthority,
) -> oneshot::Receiver<PermissionDecision> {
    let (response_tx, response_rx) = oneshot::channel();
    router.insert_command_eve_pending_for_test(
        call_id.to_owned(),
        response_tx,
        confirmation(call_id),
        authority,
        Some(Instant::now() + Duration::from_secs(60)),
        AgentRuntime::new("conv-1", "/tmp/workspace", 8),
    );
    response_rx
}

fn side_effect_if_allowed(
    response: Result<PermissionDecision, tokio::sync::oneshot::error::TryRecvError>,
    counter: &AtomicUsize,
) {
    if matches!(response, Ok(PermissionDecision::Selected { ref option_id }) if option_id == "allow_once") {
        counter.fetch_add(1, AtomicOrdering::SeqCst);
    }
}

fn superseding_policy(authority: &CommandEveAuthority) -> PolicySnapshot {
    let mut snapshot = authority.policy.clone().expect("bound policy");
    snapshot.policy_revision += 1;
    snapshot.session_epoch += 1;
    snapshot
}

fn start_policy_change(
    router: Arc<PermissionRouter>,
    snapshot: PolicySnapshot,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let started = Arc::new(AtomicBool::new(false));
    let thread_started = Arc::clone(&started);
    let handle = std::thread::spawn(move || {
        thread_started.store(true, AtomicOrdering::SeqCst);
        router.apply_policy_snapshot(snapshot);
    });
    while !started.load(AtomicOrdering::SeqCst) {
        std::thread::yield_now();
    }
    (started, handle)
}

#[test]
fn unknown_call_returns_unknown_confirmation() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    assert_eq!(
        router.confirm_result("missing", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::UnknownConfirmation
    );
}

#[test]
fn wrong_conversation_is_denied_without_forwarding() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "cross-conversation",
        authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-cross"),
    );
    assert_eq!(
        router.confirm_result("cross-conversation", "allow_once".to_owned(), "conv-other"),
        ConfirmationResponseResult::WrongSession
    );
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[test]
fn same_decision_is_idempotent_and_forwards_once() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "idem",
        authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-idem"),
    );
    let side_effects = AtomicUsize::new(0);
    assert_eq!(
        router.confirm_result("idem", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::Applied
    );
    side_effect_if_allowed(response_rx.try_recv(), &side_effects);
    assert_eq!(
        router.confirm_result("idem", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::IdempotentSameDecision
    );
    assert_eq!(side_effects.load(AtomicOrdering::SeqCst), 1);
}

#[test]
fn different_decision_conflicts_after_first_apply() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "race",
        authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-race"),
    );
    assert_eq!(
        router.confirm_result("race", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::Applied
    );
    assert!(response_rx.try_recv().is_ok());
    assert_eq!(
        router.confirm_result("race", "deny".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );
}

#[test]
fn restart_epoch_supersedes_pending_and_late_response_is_denied() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let old_authority = authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-restart");
    let mut response_rx = insert(&router, "restart", old_authority.clone());
    let mut restarted = old_authority.policy.unwrap();
    restarted.session_epoch += 1;
    restarted.policy_revision += 1;
    router.apply_policy_snapshot(restarted);
    assert!(matches!(response_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
    assert_eq!(
        router.confirm_result("restart", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );
    let cards = router.get_confirmations();
    assert_eq!(cards[0].action.as_deref(), Some("superseded"));
}

#[test]
fn tampered_classification_and_mode_fields_cannot_elevate_unknown_operation() {
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "tampered",
            ToolCallUpdateFields::new().kind(ToolKind::Execute).raw_input(json!({
                "command": "python3 -c 'print(1)'",
                "classification": "routine_terminal",
                "mode": "dont_ask"
            })),
        ),
        vec![PermissionOption::new(
            "allow_once",
            "Allow",
            PermissionOptionKind::AllowOnce,
        )],
    );
    let built = build_command_eve_authority(
        Some("hermes"),
        Some(policy(PermissionMode::Default)),
        "/tmp/workspace",
        &request,
    )
    .unwrap();
    assert_eq!(built.classification.class, OperationClass::Unknown);
    let snapshot = built.policy.as_ref().unwrap();
    let decision = decide(DecisionInput {
        mode: snapshot.mode,
        classification: built.classification,
        explicit_deny: false,
        exact_grant: false,
        authority_receipt_verified: false,
        capabilities: snapshot.capabilities,
    });

    // The invariant this test is named for: the model-authored `classification` and
    // `mode` fields inside raw_input must never make the decision MORE permissive.
    // Stated directly instead of implied by an equality assertion.
    assert_ne!(decision, AuthorityDecision::Allow);

    // An unplaceable execute is now gated on the conversation OWNER rather than on a
    // card any participant can confirm — strictly narrower than the previous plain
    // `Ask`, so the anti-elevation invariant above is strengthened, not weakened.
    // (`python3 -c '…'` carries shell quoting and matches none of the escalation
    // lists, so it is exactly the unclassifiable-execute case.)
    assert_eq!(decision, AuthorityDecision::AskWithOwner(RequiredAuthority::User));
}

#[test]
fn hard_block_manual_allow_is_denied_with_zero_side_effects() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "hard-block",
        authority(OperationClass::HardBlocked, PermissionMode::DontAsk, "digest-hard"),
    );
    let side_effects = AtomicUsize::new(0);
    assert_eq!(
        router.confirm_result("hard-block", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );
    side_effect_if_allowed(response_rx.try_recv(), &side_effects);
    assert_eq!(side_effects.load(AtomicOrdering::SeqCst), 0);
}

#[test]
fn hg4_normal_allow_is_denied_but_authenticated_founder_resumes_exactly_once() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "hg4",
        authority(OperationClass::Hg4, PermissionMode::DontAsk, "digest-hg4"),
    );
    assert_eq!(
        router.confirm_result("hg4", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );

    let remote_user = ConfirmationPrincipalContext::for_authenticated_user("remote-user");
    assert!(router.confirm_authority_as("hg4", "conv-1", &remote_user).is_err());
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    let remote_default_user = ConfirmationPrincipalContext::for_authenticated_user("system_default_user");
    assert!(
        router
            .confirm_authority_as("hg4", "conv-1", &remote_default_user)
            .is_err()
    );
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    let founder = ConfirmationPrincipalContext::for_local_capability("system_default_user");
    assert_eq!(
        router.confirm_authority_as("hg4", "conv-1", &founder).unwrap(),
        ConfirmationResponseResult::Applied
    );
    let side_effects = AtomicUsize::new(0);
    side_effect_if_allowed(response_rx.try_recv(), &side_effects);
    assert_eq!(
        router.confirm_authority_as("hg4", "conv-1", &founder).unwrap(),
        ConfirmationResponseResult::IdempotentSameDecision
    );
    assert_eq!(side_effects.load(AtomicOrdering::SeqCst), 1);

    let pending = router.pending_permissions.lock().unwrap();
    let receipt = pending["hg4"].authority_receipt.as_ref().unwrap();
    assert_eq!(receipt.operation_digest, "digest-hg4");
    assert_eq!(receipt.required_level, RequiredAuthority::Founder);
    assert_eq!(receipt.principal, "system_default_user");
    assert_eq!(router.used_authority_nonces.lock().unwrap().len(), 1);
}

#[test]
fn missing_responder_does_not_consume_human_gate_nonce() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let _response_rx = insert(
        &router,
        "missing-responder",
        authority(OperationClass::Hg4, PermissionMode::DontAsk, "digest-no-responder"),
    );
    router
        .pending_permissions
        .lock()
        .unwrap()
        .get_mut("missing-responder")
        .unwrap()
        .responder = None;

    let founder = ConfirmationPrincipalContext::for_local_capability("system_default_user");
    assert!(
        router
            .confirm_authority_as("missing-responder", "conv-1", &founder)
            .is_err()
    );
    assert!(router.used_authority_nonces.lock().unwrap().is_empty());
}

#[test]
fn high_gate_challenge_metadata_preserves_original_operation() {
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "hg4-meta",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Execute)
                .title("Notarize release")
                .raw_input(json!({"command":"xcrun notarytool submit app.zip"})),
        ),
        vec![
            PermissionOption::new("allow_once", "Allow", PermissionOptionKind::AllowOnce),
            PermissionOption::new("deny", "Deny", PermissionOptionKind::RejectOnce),
        ],
    );
    let mut built = build_command_eve_authority(
        Some("hermes"),
        Some(policy(PermissionMode::Default)),
        "/tmp/workspace",
        &request,
    )
    .unwrap();
    built.decision = AuthorityDecision::RequireAuthority(RequiredAuthority::Founder);
    built.authority_nonce = Some("nonce-meta".to_owned());
    let mut event = permission_request_to_event_data(&request);
    contain_command_eve_options(&mut event, false, &built);
    let AcpPermissionEventData::Request(event) = event else {
        panic!("request event expected");
    };
    assert_eq!(
        event.tool_call.raw_input,
        Some(json!({"command":"xcrun notarytool submit app.zip"}))
    );
    assert_eq!(
        event
            .tool_call
            .meta
            .as_ref()
            .and_then(|meta| meta.get("command_eve_authority_challenge"))
            .and_then(|challenge| challenge.get("single_use_nonce"))
            .and_then(serde_json::Value::as_str),
        Some("nonce-meta")
    );
}

#[test]
fn spoofed_team_mcp_identity_remains_unknown() {
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "spoofed-team",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Other)
                .title("mcp__aionui-team__team_members")
                .raw_input(json!({"server_name":"aionui-team"})),
        ),
        vec![],
    );
    assert_eq!(
        classify_request(&request, "/tmp/workspace").class,
        OperationClass::Unknown
    );
}

#[test]
fn c7_s1_mode_matrix_edit_terminal_has_expected_side_effect_counts() {
    let cases = [
        (PermissionMode::Default, OperationClass::RoutineEdit, 0),
        (PermissionMode::Default, OperationClass::RoutineTerminal, 0),
        (PermissionMode::AcceptEdits, OperationClass::RoutineEdit, 1),
        (PermissionMode::AcceptEdits, OperationClass::RoutineTerminal, 0),
        (PermissionMode::DontAsk, OperationClass::RoutineEdit, 1),
        (PermissionMode::DontAsk, OperationClass::RoutineTerminal, 1),
    ];
    for (index, (mode, class, expected)) in cases.into_iter().enumerate() {
        let authority = authority(class, mode, &format!("s1-{index}"));
        let (tx, mut rx) = oneshot::channel();
        match authority.decision {
            AuthorityDecision::Allow => {
                assert!(
                    tx.send(PermissionDecision::Selected {
                        option_id: authority.allow_once_option_id.unwrap(),
                    })
                    .is_ok()
                );
            }
            _ => drop(tx),
        }
        let counter = AtomicUsize::new(0);
        side_effect_if_allowed(rx.try_recv(), &counter);
        assert_eq!(counter.load(AtomicOrdering::SeqCst), expected, "{mode:?}/{class:?}");
    }
}

#[test]
fn c7_s2_guarded_is_unavailable_without_full_receipt_and_enabled_with_it() {
    let mut unavailable = AcpSession::new(Some(ModeId::new("guarded")), None, Default::default());
    assert!(unavailable.apply_command_eve_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    unavailable.apply_command_eve_transport_modes(SessionModeState::new(
        "default",
        vec![
            SessionMode::new("default", "Ask"),
            SessionMode::new("guarded", "Guarded Auto"),
        ],
    ));
    unavailable.set_session_id(SessionId::new("session-guarded-off"));
    assert_eq!(
        unavailable.ensure_command_eve_mode_available("guarded"),
        Err(super::super::permission_authority::PolicyGateError::GuardedAutoUnavailable)
    );
    assert!(
        unavailable
            .acknowledge_command_eve_policy(ModeId::new("guarded"))
            .is_none()
    );
    assert!(!unavailable.command_eve_policy_acknowledged());
    assert_eq!(
        unavailable.config_snapshot().option_current("mode").as_deref(),
        Some("default")
    );
    assert!(unavailable.plan_reconcile().is_empty());
    assert!(unavailable.begin_command_eve_turn().is_err());

    let mut enabled = AcpSession::new(Some(ModeId::new("guarded")), None, Default::default());
    assert!(enabled.apply_command_eve_runtime_hello(RuntimeCapabilityReceipt::test_guarded_receipt()));
    enabled.apply_command_eve_transport_modes(SessionModeState::new(
        "default",
        vec![
            SessionMode::new("default", "Ask"),
            SessionMode::new("guarded", "Guarded Auto"),
        ],
    ));
    enabled.set_session_id(SessionId::new("session-guarded-on"));
    assert!(enabled.acknowledge_command_eve_policy(ModeId::new("guarded")).is_some());
    let snapshot = enabled.begin_command_eve_turn().unwrap();
    assert!(snapshot.capabilities.guarded_auto_proven());
    assert_eq!(
        enabled.config_snapshot().option_current("mode").as_deref(),
        Some("guarded")
    );
}

#[test]
fn c7_s3_recovery_returns_one_pending_card_without_execution() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut response_rx = insert(
        &router,
        "s3",
        authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-s3"),
    );
    assert_eq!(router.get_confirmations().len(), 1);
    assert_eq!(router.get_confirmations().len(), 1);
    let counter = AtomicUsize::new(0);
    side_effect_if_allowed(response_rx.try_recv(), &counter);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 0);
}

#[test]
fn c7_pending_recovery_exposes_complete_safe_authority_metadata() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let digest = "d".repeat(64);
    let bound = authority(OperationClass::RoutineEdit, PermissionMode::Default, &digest);
    let expected_policy = bound.policy.clone().unwrap();
    let _response_rx = insert(&router, "metadata-recovery", bound);

    let cards = router.get_confirmations();
    assert_eq!(cards.len(), 1);
    let metadata = cards[0].authority.as_ref().expect("Command EVE metadata");
    assert_eq!(metadata.protocol_version, COMMAND_EVE_AUTHORITY_PROTOCOL_VERSION);
    assert_eq!(metadata.operation_id, "metadata-recovery");
    assert_eq!(metadata.operation_digest, digest);
    assert!(metadata.confirmation_version > 0);
    assert_eq!(metadata.policy_revision, expected_policy.policy_revision);
    assert_eq!(metadata.session_epoch, expected_policy.session_epoch);
    assert!(metadata.created_at_ms <= metadata.expires_at_ms);
    assert_eq!(metadata.lifecycle, "pending");
    assert_eq!(metadata.classification, "routine_edit");
    assert_eq!(metadata.required_authority, None);
    assert_eq!(
        metadata.runtime_receipt_digest,
        expected_policy.runtime_receipt.receipt_digest
    );

    let wire = serde_json::to_value(&cards[0]).unwrap();
    let recovered: Confirmation = serde_json::from_value(wire).unwrap();
    assert_eq!(recovered.authority.as_ref(), Some(metadata));
}

#[test]
fn c7_s4_expiry_and_late_response_produce_zero_side_effects() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let (response_tx, mut response_rx) = oneshot::channel();
    router.insert_command_eve_pending_for_test(
        "s4".to_owned(),
        response_tx,
        confirmation("s4"),
        authority(OperationClass::RoutineTerminal, PermissionMode::Default, "digest-s4"),
        Some(Instant::now() - Duration::from_millis(1)),
        AgentRuntime::new("conv-1", "/tmp/workspace", 8),
    );
    assert_eq!(router.get_confirmations()[0].action.as_deref(), Some("expired"));
    assert_eq!(
        router.confirm_result("s4", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::Expired
    );
    let counter = AtomicUsize::new(0);
    side_effect_if_allowed(response_rx.try_recv(), &counter);
    assert_eq!(counter.load(AtomicOrdering::SeqCst), 0);
}

#[test]
fn c7_s5_exact_grant_matches_only_digest_revision_and_epoch() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let grant_authority = authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-s5");
    let mut response_rx = insert(&router, "s5", grant_authority.clone());
    assert_eq!(
        router.confirm_result("s5", "allow_session".to_owned(), "conv-1"),
        ConfirmationResponseResult::Applied
    );
    assert!(matches!(
        response_rx.try_recv(),
        Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
    ));
    assert!(router.has_valid_session_grant(&grant_authority));

    let changed = authority(
        OperationClass::RoutineEdit,
        PermissionMode::Default,
        "digest-s5-changed",
    );
    assert!(!router.has_valid_session_grant(&changed));
    let mut changed_policy = grant_authority.clone();
    changed_policy.policy.as_mut().unwrap().policy_revision += 1;
    assert!(!router.has_valid_session_grant(&changed_policy));
}

#[test]
fn c7_s6_runtime_restart_cancels_pending_and_revokes_session_grants() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let grant_authority = authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-s6-grant");
    let mut granted_rx = insert(&router, "s6-grant", grant_authority);
    assert_eq!(
        router.confirm_result("s6-grant", "allow_session".to_owned(), "conv-1"),
        ConfirmationResponseResult::Applied
    );
    assert!(granted_rx.try_recv().is_ok());
    let mut pending_rx = insert(
        &router,
        "s6-pending",
        authority(
            OperationClass::RoutineTerminal,
            PermissionMode::Default,
            "digest-s6-pending",
        ),
    );
    router.cancel_all();
    assert!(router.session_grants.lock().unwrap().is_empty());
    assert!(matches!(pending_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
    assert_eq!(
        router.confirm_result("s6-pending", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );
}

#[test]
fn c7_s7_policy_and_multiwindow_race_applies_at_most_once() {
    same_decision_is_idempotent_and_forwards_once();
    different_decision_conflicts_after_first_apply();
    restart_epoch_supersedes_pending_and_late_response_is_denied();
}

#[test]
fn policy_change_is_linearized_with_manual_session_grant_side_effect() {
    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let old_authority = authority(
        OperationClass::RoutineEdit,
        PermissionMode::Default,
        "manual-race-digest",
    );
    let new_policy = superseding_policy(&old_authority);
    let mut response_rx = insert(&router, "manual-policy-race", old_authority);
    let hook = router.install_policy_race_hook();
    let decision_router = Arc::clone(&router);
    let decision = std::thread::spawn(move || {
        decision_router.confirm_result("manual-policy-race", "allow_session".to_owned(), "conv-1")
    });

    hook.entered.wait();
    let (_started, policy_change) = start_policy_change(Arc::clone(&router), new_policy.clone());
    hook.release.wait();

    assert_eq!(decision.join().unwrap(), ConfirmationResponseResult::Applied);
    policy_change.join().unwrap();
    assert!(matches!(
        response_rx.try_recv(),
        Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
    ));
    assert_eq!(router.current_policy.lock().unwrap().as_ref(), Some(&new_policy));
    assert!(
        router.session_grants.lock().unwrap().is_empty(),
        "a grant bound to the superseded policy must not survive"
    );
}

#[test]
fn restart_cancel_is_linearized_with_manual_session_grant_side_effect() {
    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let mut response_rx = insert(
        &router,
        "manual-restart-race",
        authority(
            OperationClass::RoutineEdit,
            PermissionMode::Default,
            "manual-restart-digest",
        ),
    );
    let hook = router.install_policy_race_hook();
    let decision_router = Arc::clone(&router);
    let decision = std::thread::spawn(move || {
        decision_router.confirm_result("manual-restart-race", "allow_session".to_owned(), "conv-1")
    });

    hook.entered.wait();
    let restart_started = Arc::new(AtomicBool::new(false));
    let restart_thread_started = Arc::clone(&restart_started);
    let restart_router = Arc::clone(&router);
    let restart = std::thread::spawn(move || {
        restart_thread_started.store(true, AtomicOrdering::SeqCst);
        restart_router.cancel_all();
    });
    while !restart_started.load(AtomicOrdering::SeqCst) {
        std::thread::yield_now();
    }
    hook.release.wait();

    assert_eq!(decision.join().unwrap(), ConfirmationResponseResult::Applied);
    restart.join().unwrap();
    assert!(matches!(
        response_rx.try_recv(),
        Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
    ));
    assert!(router.current_policy.lock().unwrap().is_none());
    assert!(router.session_grants.lock().unwrap().is_empty());
}

#[test]
fn policy_change_is_linearized_with_founder_allow_side_effect() {
    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let old_authority = authority(OperationClass::Hg4, PermissionMode::DontAsk, "founder-race-digest");
    let new_policy = superseding_policy(&old_authority);
    let mut response_rx = insert(&router, "founder-policy-race", old_authority);
    let founder = ConfirmationPrincipalContext::for_local_capability("system_default_user");
    let hook = router.install_policy_race_hook();
    let decision_router = Arc::clone(&router);
    let decision =
        std::thread::spawn(move || decision_router.confirm_authority_as("founder-policy-race", "conv-1", &founder));

    hook.entered.wait();
    let (_started, policy_change) = start_policy_change(Arc::clone(&router), new_policy.clone());
    hook.release.wait();

    assert_eq!(decision.join().unwrap().unwrap(), ConfirmationResponseResult::Applied);
    policy_change.join().unwrap();
    assert!(matches!(
        response_rx.try_recv(),
        Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
    ));
    assert_eq!(router.current_policy.lock().unwrap().as_ref(), Some(&new_policy));
    assert!(router.session_grants.lock().unwrap().is_empty());
}

#[test]
fn policy_change_is_linearized_with_auto_allow_and_stale_auto_has_zero_side_effects() {
    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let old_authority = authority(OperationClass::RoutineEdit, PermissionMode::DontAsk, "auto-race-digest");
    assert_eq!(old_authority.decision, AuthorityDecision::Allow);
    let old_policy = old_authority.policy.clone().unwrap();
    let new_policy = superseding_policy(&old_authority);
    router.apply_policy_snapshot(old_policy.clone());
    router.session_grants.lock().unwrap().insert(
        old_authority.operation_digest.clone(),
        SessionGrant {
            operation_digest: old_authority.operation_digest.clone(),
            policy_revision: old_policy.policy_revision,
            session_epoch: old_policy.session_epoch,
            expires_at: Instant::now() + Duration::from_secs(60),
            revoked: false,
        },
    );
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "auto-policy-race",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Edit)
                .raw_input(json!({"tool":"write_file","arguments":{"path":"safe.txt"}})),
        ),
        vec![PermissionOption::new(
            "allow_once",
            "Allow",
            PermissionOptionKind::AllowOnce,
        )],
    );
    let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
    let hook = router.install_policy_race_hook();
    let decision_router = Arc::clone(&router);
    let decision_runtime = runtime.clone();
    let decision_request = request.clone();
    let decision_authority = old_authority.clone();
    let (response_tx, mut response_rx) = oneshot::channel();
    let decision = std::thread::spawn(move || {
        let mut responder = Some(response_tx);
        let handled = decision_router.resolve_command_eve_auto_allow(
            &decision_runtime,
            &decision_request,
            &decision_authority,
            true,
            &mut responder,
        );
        (handled, responder.is_none())
    });

    hook.entered.wait();
    let (_started, policy_change) = start_policy_change(Arc::clone(&router), new_policy.clone());
    hook.release.wait();

    assert_eq!(decision.join().unwrap(), (true, true));
    policy_change.join().unwrap();
    assert!(matches!(
        response_rx.try_recv(),
        Ok(PermissionDecision::Selected { option_id }) if option_id == "allow_once"
    ));
    assert_eq!(router.current_policy.lock().unwrap().as_ref(), Some(&new_policy));
    assert!(router.session_grants.lock().unwrap().is_empty());

    let stale_side_effects = AtomicUsize::new(0);
    let mut stale_events = runtime.subscribe();
    let (stale_tx, mut stale_rx) = oneshot::channel();
    let mut stale_responder = Some(stale_tx);
    assert!(router.resolve_command_eve_auto_allow(&runtime, &request, &old_authority, true, &mut stale_responder,));
    assert!(stale_responder.is_none());
    side_effect_if_allowed(stale_rx.try_recv(), &stale_side_effects);
    assert_eq!(stale_side_effects.load(AtomicOrdering::SeqCst), 0);
    assert!(matches!(
        stale_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(matches!(
        stale_events.try_recv(),
        Ok(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(card)))
            if card.action.as_deref() == Some("superseded")
    ));
}

#[test]
fn exact_grant_expiring_between_decision_and_send_routes_to_visible_ask() {
    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let bound = authority(
        OperationClass::RoutineEdit,
        PermissionMode::Default,
        "expiring-grant-digest",
    );
    let policy = bound.policy.clone().unwrap();
    router.apply_policy_snapshot(policy.clone());
    router.session_grants.lock().unwrap().insert(
        bound.operation_digest.clone(),
        SessionGrant {
            operation_digest: bound.operation_digest.clone(),
            policy_revision: policy.policy_revision,
            session_epoch: policy.session_epoch,
            expires_at: Instant::now() + Duration::from_secs(60),
            revoked: false,
        },
    );
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "expiring-grant",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Edit)
                .raw_input(json!({"tool":"write_file","arguments":{"path":"safe.txt"}})),
        ),
        vec![PermissionOption::new(
            "allow_once",
            "Allow",
            PermissionOptionKind::AllowOnce,
        )],
    );
    let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
    let hook = router.install_policy_race_hook();
    let decision_router = Arc::clone(&router);
    let decision_runtime = runtime.clone();
    let decision_request = request.clone();
    let decision_authority = bound.clone();
    let (response_tx, mut response_rx) = oneshot::channel();
    let decision = std::thread::spawn(move || {
        let mut responder = Some(response_tx);
        let handled = decision_router.resolve_command_eve_auto_allow(
            &decision_runtime,
            &decision_request,
            &decision_authority,
            true,
            &mut responder,
        );
        (handled, responder)
    });

    hook.entered.wait();
    router
        .session_grants
        .lock()
        .unwrap()
        .get_mut("expiring-grant-digest")
        .unwrap()
        .expires_at = Instant::now() - Duration::from_millis(1);
    hook.release.wait();

    let (handled, responder) = decision.join().unwrap();
    assert!(!handled, "expired exact grant must not dispatch an automatic allow");
    let side_effects = AtomicUsize::new(0);
    side_effect_if_allowed(response_rx.try_recv(), &side_effects);
    assert_eq!(side_effects.load(AtomicOrdering::SeqCst), 0);
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let mut visible = bound;
    visible.decision = AuthorityDecision::Ask;
    router.insert_command_eve_pending_for_test(
        "expiring-grant".to_owned(),
        responder.expect("visible Ask retains responder"),
        confirmation("expiring-grant"),
        visible,
        Some(Instant::now() + Duration::from_secs(60)),
        runtime,
    );
    assert_eq!(router.get_confirmations().len(), 1);
    assert!(router.session_grants.lock().unwrap().is_empty());
}

#[test]
fn mode_change_revokes_old_authority_before_delayed_transport_response() {
    let mut session = AcpSession::new(Some(ModeId::new("dont_ask")), None, Default::default());
    assert!(session.apply_command_eve_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    assert!(session.apply_command_eve_transport_modes(SessionModeState::new(
        "default",
        vec![SessionMode::new("default", "Ask")],
    )));
    session.set_session_id(SessionId::new("delayed-policy-session"));
    let old_policy = session.acknowledge_command_eve_policy(ModeId::new("dont_ask")).unwrap();
    assert!(session.begin_command_eve_turn().is_ok());

    let (_tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    router.apply_policy_snapshot(old_policy.clone());
    router.session_grants.lock().unwrap().insert(
        "delayed-exact-grant".to_owned(),
        SessionGrant {
            operation_digest: "delayed-exact-grant".to_owned(),
            policy_revision: old_policy.policy_revision,
            session_epoch: old_policy.session_epoch,
            expires_at: Instant::now() + Duration::from_secs(60),
            revoked: false,
        },
    );
    let mut manual_authority = authority(OperationClass::RoutineEdit, PermissionMode::DontAsk, "delayed-manual");
    manual_authority.policy = Some(old_policy.clone());
    manual_authority.decision = AuthorityDecision::Ask;
    let mut manual_rx = insert(&router, "delayed-manual", manual_authority);

    let session = Arc::new(std::sync::Mutex::new(session));
    let transport_entered = Arc::new(Barrier::new(2));
    let transport_release = Arc::new(Barrier::new(2));
    let change_session = Arc::clone(&session);
    let change_router = Arc::clone(&router);
    let change_entered = Arc::clone(&transport_entered);
    let change_release = Arc::clone(&transport_release);
    let change = std::thread::spawn(move || {
        {
            let mut session = change_session.lock().unwrap();
            prepare_command_eve_policy_change_state(
                &mut session,
                &change_router,
                "delayed-policy-session",
                "default",
                "test delayed Hermes transport",
            )
            .unwrap();
        }
        change_entered.wait();
        change_release.wait();
        let snapshot = {
            let mut session = change_session.lock().unwrap();
            assert!(session.apply_command_eve_transport_mode(ModeId::new("default")));
            session.acknowledge_command_eve_policy(ModeId::new("default")).unwrap()
        };
        change_router.apply_policy_snapshot(snapshot);
    });

    transport_entered.wait();
    assert!(router.current_policy.lock().unwrap().is_none());
    assert!(router.session_grants.lock().unwrap().is_empty());
    assert!(matches!(manual_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
    assert_eq!(
        session.lock().unwrap().begin_command_eve_turn(),
        Err(super::super::permission_authority::PolicyGateError::PolicyPending)
    );

    let auto_request = RequestPermissionRequest::new(
        "delayed-policy-session",
        ToolCallUpdate::new(
            "old-auto-during-transport",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Edit)
                .raw_input(json!({"tool":"write_file","arguments":{"path":"safe.txt"}})),
        ),
        vec![PermissionOption::new(
            "allow_once",
            "Allow",
            PermissionOptionKind::AllowOnce,
        )],
    );
    let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
    let mut auto_authority = authority(
        OperationClass::RoutineEdit,
        PermissionMode::DontAsk,
        "old-auto-during-transport",
    );
    auto_authority.policy = Some(old_policy);
    auto_authority.decision = AuthorityDecision::Allow;
    let (auto_tx, mut auto_rx) = oneshot::channel();
    let mut auto_responder = Some(auto_tx);
    assert!(router.resolve_command_eve_auto_allow(
        &runtime,
        &auto_request,
        &auto_authority,
        false,
        &mut auto_responder,
    ));
    assert!(matches!(auto_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
    assert_eq!(
        router.confirm_result("delayed-manual", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );

    transport_release.wait();
    change.join().unwrap();
    assert_eq!(
        router.current_policy.lock().unwrap().as_ref().map(|policy| policy.mode),
        Some(PermissionMode::Default)
    );
}

#[test]
fn c7_s8_human_gates_unknown_and_hard_block_never_bypass_authority() {
    hard_block_manual_allow_is_denied_with_zero_side_effects();
    hg4_normal_allow_is_denied_but_authenticated_founder_resumes_exactly_once();

    let unknown = authority(OperationClass::Unknown, PermissionMode::DontAsk, "digest-s8-unknown");
    assert_eq!(unknown.decision, AuthorityDecision::Ask);
    let hg35 = authority(OperationClass::Hg35, PermissionMode::DontAsk, "digest-s8-hg35");
    assert_eq!(
        hg35.decision,
        AuthorityDecision::RequireAuthority(RequiredAuthority::Proxy)
    );
}

fn execute_request(call_id: &'static str, command: &'static str) -> RequestPermissionRequest {
    RequestPermissionRequest::new(
        "session-unbound",
        ToolCallUpdate::new(
            call_id,
            ToolCallUpdateFields::new()
                .kind(ToolKind::Execute)
                .title("Execute")
                .raw_input(json!({"command":command})),
        ),
        vec![
            PermissionOption::new("allow_once", "Allow", PermissionOptionKind::AllowOnce),
            PermissionOption::new("deny", "Deny", PermissionOptionKind::RejectOnce),
        ],
    )
}

#[tokio::test]
async fn missing_policy_hard_block_stays_blocked_in_start_path() {
    let (tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
    let mut events = runtime.subscribe();
    router.start(runtime, Weak::new(), Some("hermes".to_owned()));
    let (response_tx, response_rx) = oneshot::channel();
    tx.send(PermissionRequest {
        request: execute_request("missing-policy-hard", "rm -rf /"),
        response_tx,
    })
    .await
    .unwrap();

    assert!(matches!(
        response_rx.await.unwrap(),
        PermissionDecision::Selected { option_id } if option_id == "deny"
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(card))
            if card.action.as_deref() == Some("denied")
    ));
}

#[tokio::test]
async fn missing_policy_hg4_never_exposes_or_accepts_normal_allow() {
    let (tx, rx) = mpsc::channel(1);
    let router = Arc::new(PermissionRouter::new(rx));
    let runtime = AgentRuntime::new("conv-1", "/tmp/workspace", 8);
    let mut events = runtime.subscribe();
    router.start(runtime, Weak::new(), Some("hermes".to_owned()));
    let (response_tx, mut response_rx) = oneshot::channel();
    tx.send(PermissionRequest {
        request: execute_request("missing-policy-hg4", "xcrun notarytool submit app.zip"),
        response_tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap(),
        AgentStreamEvent::AcpPermission(AcpPermissionEventData::Request(_))
    ));
    let cards = router.get_confirmations();
    assert_eq!(cards.len(), 1);
    assert!(
        cards[0]
            .options
            .iter()
            .all(|option| option.value != json!("allow_once"))
    );
    assert_eq!(
        router.confirm_result("missing-policy-hg4", "allow_once".to_owned(), "conv-1"),
        ConfirmationResponseResult::ConflictDifferentDecision
    );
    let founder = ConfirmationPrincipalContext::for_local_capability("system_default_user");
    assert!(
        router
            .confirm_authority_as("missing-policy-hg4", "conv-1", &founder)
            .is_err()
    );
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
}

#[test]
fn no_allow_once_hides_exact_session_option() {
    let workspace = tempfile::tempdir().unwrap();
    let request = RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new(
            "no-one-shot",
            ToolCallUpdateFields::new()
                .kind(ToolKind::Edit)
                .raw_input(json!({"tool":"write_file","arguments":{"path":"safe.txt"}})),
        ),
        vec![PermissionOption::new(
            "allow_session",
            "Allow session",
            PermissionOptionKind::AllowAlways,
        )],
    );
    let mut built = build_command_eve_authority(
        Some("hermes"),
        Some(policy(PermissionMode::Default)),
        workspace.path().to_str().unwrap(),
        &request,
    )
    .unwrap();
    built.allow_once_option_id = None;
    let mut event = permission_request_to_event_data(&request);
    contain_command_eve_options(
        &mut event,
        built.grant_eligible && built.policy.is_some() && built.allow_once_option_id.is_some(),
        &built,
    );
    let AcpPermissionEventData::Request(event) = event else {
        panic!("request event expected");
    };
    assert!(event.options.is_empty());
}

#[test]
fn unsafe_hermes_transport_revokes_policy_turn_and_router_projection() {
    let mut session = AcpSession::new(Some(ModeId::new("dont_ask")), None, Default::default());
    assert!(session.apply_command_eve_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    assert!(session.apply_command_eve_transport_modes(SessionModeState::new(
        "default",
        vec![SessionMode::new("default", "Ask"), SessionMode::new("dont_ask", "Auto")],
    )));
    session.set_session_id(SessionId::new("session-drift"));
    let policy = session.acknowledge_command_eve_policy(ModeId::new("dont_ask")).unwrap();
    assert!(session.begin_command_eve_turn().is_ok());

    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    router.apply_policy_snapshot(policy.clone());
    router.session_grants.lock().unwrap().insert(
        "old-grant".to_owned(),
        SessionGrant {
            operation_digest: "old-grant".to_owned(),
            policy_revision: 1,
            session_epoch: 1,
            expires_at: Instant::now() + Duration::from_secs(60),
            revoked: false,
        },
    );
    let mut command_eve = authority(
        OperationClass::RoutineEdit,
        PermissionMode::Default,
        "unsafe-transport-command-eve",
    );
    command_eve.policy = Some(policy);
    let mut command_eve_rx = insert(&router, "unsafe-transport-command-eve", command_eve);
    let (shared_tx, mut shared_rx) = oneshot::channel();
    router.insert_pending_for_test(
        "unsafe-transport-shared".to_owned(),
        shared_tx,
        confirmation("unsafe-transport-shared"),
    );
    assert!(!session.apply_command_eve_transport_mode(ModeId::new("dont_ask")));
    router.revoke_command_eve_policy("test unsafe transport");
    assert!(router.current_policy.lock().unwrap().is_none());
    assert!(router.session_grants.lock().unwrap().is_empty());
    assert!(matches!(command_eve_rx.try_recv(), Ok(PermissionDecision::Cancelled)));
    assert!(matches!(
        shared_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    let pending = router.pending_permissions.lock().unwrap();
    assert_eq!(
        pending["unsafe-transport-command-eve"].lifecycle,
        ConfirmationLifecycle::Superseded
    );
    assert_eq!(
        pending["unsafe-transport-shared"].lifecycle,
        ConfirmationLifecycle::Pending
    );
    drop(pending);
    assert_eq!(
        session.begin_command_eve_turn(),
        Err(super::super::permission_authority::PolicyGateError::UnsafeTransportMode)
    );
}

#[test]
fn terminal_history_and_authority_nonces_are_bounded_without_pruning_pending() {
    let (_tx, rx) = mpsc::channel(1);
    let router = PermissionRouter::new(rx);
    let mut pending_receivers = Vec::new();
    for index in 0..5 {
        let call_id = format!("still-pending-{index}");
        let (response_tx, response_rx) = oneshot::channel();
        router.insert_pending_for_test(call_id, response_tx, confirmation("shared-pending"));
        pending_receivers.push(response_rx);
    }

    let (expired_tx, mut expired_rx) = oneshot::channel();
    router.insert_command_eve_pending_for_test(
        "recent-visible-expired".to_owned(),
        expired_tx,
        confirmation("recent-visible-expired"),
        authority(OperationClass::RoutineEdit, PermissionMode::Default, "digest-expired"),
        Some(Instant::now() - Duration::from_millis(1)),
        AgentRuntime::new("conv-1", "/tmp/workspace", 8),
    );
    router.get_confirmations();
    assert!(matches!(expired_rx.try_recv(), Ok(PermissionDecision::Cancelled)));

    let founder = ConfirmationPrincipalContext::for_local_capability("system_default_user");
    let total = MAX_TERMINAL_CONFIRMATION_HISTORY + 16;
    for index in 0..total {
        let call_id = format!("bounded-founder-{index}");
        let mut response_rx = insert(
            &router,
            &call_id,
            authority(OperationClass::Hg4, PermissionMode::DontAsk, &format!("digest-{index}")),
        );
        assert_eq!(
            router.confirm_authority_as(&call_id, "conv-1", &founder).unwrap(),
            ConfirmationResponseResult::Applied
        );
        assert!(response_rx.try_recv().is_ok());
    }

    let permissions = router.pending_permissions.lock().unwrap();
    let terminal_count = permissions
        .values()
        .filter(|pending| pending.lifecycle != ConfirmationLifecycle::Pending)
        .count();
    assert!(terminal_count <= MAX_TERMINAL_CONFIRMATION_HISTORY);
    for index in 0..5 {
        assert_eq!(
            permissions[&format!("still-pending-{index}")].lifecycle,
            ConfirmationLifecycle::Pending
        );
    }
    assert_eq!(
        permissions["recent-visible-expired"].lifecycle,
        ConfirmationLifecycle::Expired
    );
    drop(permissions);
    assert!(router.used_authority_nonces.lock().unwrap().len() <= MAX_TERMINAL_CONFIRMATION_HISTORY);
    assert_eq!(
        router
            .confirm_authority_as(&format!("bounded-founder-{}", total - 1), "conv-1", &founder)
            .unwrap(),
        ConfirmationResponseResult::IdempotentSameDecision
    );
    drop(pending_receivers);
}
