use super::*;
use agent_client_protocol::schema::{RequestPermissionRequest, ToolCallUpdate, ToolCallUpdateFields};
use serde_json::json;

fn input(mode: PermissionMode, class: OperationClass) -> DecisionInput {
    DecisionInput {
        mode,
        classification: TrustedClassification::new(class),
        explicit_deny: false,
        exact_grant: false,
        authority_receipt_verified: false,
        capabilities: RuntimeCapabilityReceipt::test_receipt().capabilities,
    }
}

#[test]
fn full_four_mode_matrix_is_table_driven() {
    use OperationClass::*;
    use PermissionDecision::*;
    use PermissionMode::*;

    let cases = [
        (Default, RoutineEdit, Ask),
        (Default, RoutineTerminal, Ask),
        (AcceptEdits, RoutineEdit, Allow),
        (AcceptEdits, RoutineTerminal, Ask),
        (DontAsk, RoutineEdit, Allow),
        (DontAsk, RoutineTerminal, Allow),
        (Guarded, RoutineEdit, Unsupported),
        (Guarded, RoutineTerminal, Unsupported),
    ];
    for (mode, class, expected) in cases {
        assert_eq!(decide(input(mode, class)), expected, "{mode:?}/{class:?}");
    }

    for mode in [Default, AcceptEdits, DontAsk, Guarded] {
        assert_eq!(decide(input(mode, HardBlocked)), Block);
        assert_eq!(decide(input(mode, Sensitive)), AskWithOwner(RequiredAuthority::User));
        assert_eq!(decide(input(mode, Hg35)), RequireAuthority(RequiredAuthority::Proxy));
        assert_eq!(decide(input(mode, Hg4)), RequireAuthority(RequiredAuthority::Founder));
        assert_eq!(
            decide(input(mode, Unknown)),
            if mode == Guarded { Unsupported } else { Ask }
        );
    }
}

#[test]
fn grant_never_lowers_human_authority() {
    for class in [OperationClass::Hg35, OperationClass::Hg4] {
        let mut case = input(PermissionMode::DontAsk, class);
        case.exact_grant = true;
        assert!(matches!(
            decide(case),
            PermissionDecision::RequireAuthority(RequiredAuthority::Proxy | RequiredAuthority::Founder)
        ));
    }
}

#[test]
fn guarded_requires_the_complete_capability_set() {
    let mut case = input(PermissionMode::Guarded, OperationClass::RoutineEdit);
    case.capabilities = CommandEveCapabilities {
        trusted_classification: true,
        policy_handshake: true,
        guarded_auto: true,
        versioned_grant_store: true,
        revocation: true,
    };
    assert_eq!(decide(case), PermissionDecision::Allow);
}

#[test]
fn policy_state_requires_set_policy_applied_before_run_turn() {
    let mut state = CommandEvePolicyState::default();
    assert!(state.apply_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    state.begin_session();
    state.request_mode(PermissionMode::DontAsk);
    assert_eq!(state.begin_turn(), Err(PolicyGateError::PolicyPending));

    let applied = state
        .acknowledge_runtime_mode(PermissionMode::DontAsk)
        .expect("matching runtime acknowledgement");
    assert_eq!(state.begin_turn(), Ok(applied.clone()));
    assert_eq!(state.permission_snapshot(), Ok(applied));
}

#[test]
fn policy_change_invalidates_the_old_turn_lease() {
    let mut state = CommandEvePolicyState::default();
    assert!(state.apply_runtime_hello(RuntimeCapabilityReceipt::test_receipt()));
    state.begin_session();
    state.request_mode(PermissionMode::DontAsk);
    state.acknowledge_runtime_mode(PermissionMode::DontAsk);
    state.begin_turn().unwrap();
    state.request_mode(PermissionMode::Default);
    assert_eq!(state.permission_snapshot(), Err(PolicyGateError::PolicyPending));
}

fn request(kind: ToolKind, raw: Value) -> RequestPermissionRequest {
    RequestPermissionRequest::new(
        "session-1",
        ToolCallUpdate::new("call-1", ToolCallUpdateFields::new().kind(kind).raw_input(raw)),
        vec![],
    )
}

#[test]
fn classifier_trusts_only_structurally_bound_workspace_edits() {
    let workspace = tempfile::tempdir().unwrap();
    let inside = workspace.path().join("src/lib.rs");
    let routine = request(
        ToolKind::Edit,
        json!({"tool":"write_file","arguments":{"path":inside,"content":"ok"}}),
    );
    assert_eq!(
        classify_request(&routine, workspace.path().to_str().unwrap()).class,
        OperationClass::RoutineEdit
    );

    let escape = request(
        ToolKind::Edit,
        json!({"tool":"write_file","arguments":{"path":"../escape.txt","content":"no"}}),
    );
    assert_eq!(
        classify_request(&escape, workspace.path().to_str().unwrap()).class,
        OperationClass::HardBlocked
    );
}

#[test]
fn classifier_never_trusts_spoofed_single_path_for_multi_file_patch() {
    let workspace = tempfile::tempdir().unwrap();
    let request = request(
        ToolKind::Edit,
        json!({
            "tool":"patch",
            "arguments":{
                "path": workspace.path().join("safe.txt"),
                "patch":"*** Update File: safe.txt\n*** Update File: ../outside.txt"
            }
        }),
    );
    assert_eq!(
        classify_request(&request, workspace.path().to_str().unwrap()).class,
        OperationClass::Unknown
    );
}

#[test]
fn classifier_blocks_all_dot_env_component_variants_case_insensitively() {
    let workspace = tempfile::tempdir().unwrap();
    for path in [
        ".env",
        ".env.local",
        ".env.development",
        ".ENV.TEST",
        "config/.env.staging",
    ] {
        let request = request(
            ToolKind::Edit,
            json!({"tool":"write_file","arguments":{"path":path,"content":"secret"}}),
        );
        assert_eq!(
            classify_request(&request, workspace.path().to_str().unwrap()).class,
            OperationClass::HardBlocked,
            "{path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn classifier_rejects_nonexistent_target_below_symlink_escape() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), workspace.path().join("escape-link")).unwrap();
    let request = request(
        ToolKind::Edit,
        json!({
            "tool":"write_file",
            "arguments":{"path":"escape-link/new.txt","content":"no"}
        }),
    );
    assert_eq!(
        classify_request(&request, workspace.path().to_str().unwrap()).class,
        OperationClass::HardBlocked
    );
}

#[test]
fn runtime_receipt_tampering_revokes_policy_capability() {
    let mut receipt = RuntimeCapabilityReceipt::test_receipt();
    receipt.executable_sha256 = "b".repeat(64);
    let mut state = CommandEvePolicyState::default();
    assert!(!state.apply_runtime_hello(receipt));
    state.begin_session();
    assert_eq!(
        state.acknowledge_runtime_mode(PermissionMode::Default),
        None,
        "an unverified RuntimeHello can never manufacture PolicyApplied"
    );
}

#[test]
fn classifier_maps_known_terminal_authority_and_unknown_fail_closed() {
    let cases = [
        ("pwd", OperationClass::RoutineTerminal),
        ("cargo test -p aionui-ai-agent", OperationClass::Unknown),
        ("git push origin release", OperationClass::Hg35),
        ("xcrun notarytool submit app.zip", OperationClass::Hg4),
        ("python3 -c 'print(1)'", OperationClass::Unknown),
        ("rm -rf /", OperationClass::HardBlocked),
    ];
    for (command, expected) in cases {
        let classified = classify_request(&request(ToolKind::Execute, json!({"command": command})), "/tmp");
        assert_eq!(classified.class, expected, "{command}");
    }
}

#[test]
fn classifier_allows_only_exact_workspace_bound_mkdir_mutation() {
    let workspace = tempfile::tempdir().unwrap();
    let workspace_text = workspace.path().to_str().unwrap();
    let cases = [
        ("mkdir -- generated", OperationClass::RoutineTerminal),
        ("mkdir -- nested/generated", OperationClass::RoutineTerminal),
        ("mkdir generated", OperationClass::Unknown),
        ("mkdir -- one two", OperationClass::Unknown),
        ("mkdir -- 'quoted'", OperationClass::Unknown),
        ("mkdir -- generated; pwd", OperationClass::Unknown),
        ("mkdir -- ../escape", OperationClass::HardBlocked),
        ("mkdir -- /tmp/escape", OperationClass::HardBlocked),
        ("mkdir -- .git/generated", OperationClass::HardBlocked),
        ("ls /tmp", OperationClass::Unknown),
    ];
    for (command, expected) in cases {
        assert_eq!(
            classify_request(&request(ToolKind::Execute, json!({"command":command})), workspace_text).class,
            expected,
            "{command}"
        );
    }
}

#[cfg(unix)]
#[test]
fn classifier_rejects_mkdir_below_symlink_escape() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), workspace.path().join("escape-link")).unwrap();
    assert_eq!(
        classify_request(
            &request(ToolKind::Execute, json!({"command":"mkdir -- escape-link/generated"})),
            workspace.path().to_str().unwrap(),
        )
        .class,
        OperationClass::HardBlocked
    );
}
