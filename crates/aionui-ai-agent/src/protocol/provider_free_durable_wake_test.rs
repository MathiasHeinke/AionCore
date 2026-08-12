//! Provider-free cross-language proof for the Command EVE durable-wake seam.
//!
//! This executes the pinned Hermes ACP server, its real durable delegation
//! queue and completion pump, the Rust ACP SDK transport, and AionCore's real
//! session-bound extension router. The Hermes model-facing call is replaced by
//! a deterministic local fixture. Follow-up agent execution is intentionally
//! not faked here; the gate script runs the real ConversationService and
//! persistent receipt tests separately.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use agent_client_protocol::schema::{ContentBlock, LoadSessionRequest, NewSessionRequest, PromptRequest};
use aionui_api_types::COMMAND_EVE_ASYNC_COMPLETION_VERSION;
use aionui_runtime::{Builder, kill_process_tree};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, mpsc};

use super::acp::{AcpProtocol, PermissionRequest};
use crate::protocol::events::AgentStreamEvent;
use crate::{AcpSessionBinding, CommandEveAsyncCompletionResult, CommandEveAsyncCompletionRoute};

const TRIGGER: &str = "TRIGGER_PROVIDER_FREE_DURABLE_WAKE";

fn required_path(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required by the provider-free gate"));
    let path = PathBuf::from(value);
    assert!(path.exists(), "{name} does not exist: {}", path.display());
    path
}

async fn wait_for_trace(path: &Path, expected: usize) -> Vec<Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                let records = text
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| serde_json::from_str::<Value>(line).expect("valid Hermes trace line"))
                    .collect::<Vec<_>>();
                if records.len() >= expected {
                    return records;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Hermes wire trace timeout")
}

fn fixture_command(
    python: &Path,
    fixture: &Path,
    hermes_source: &Path,
    home: &Path,
    hermes_home: &Path,
    trace_path: &Path,
) -> Builder {
    let mut command = Builder::new(python);
    command
        .arg("-u")
        .arg(fixture)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("PYTHONPATH", hermes_source)
        .env("PYTHONUNBUFFERED", "1")
        .env("HERMES_HOME", hermes_home)
        .env("HERMES_ACP_SKIP_CONFIGURED_MCP", "1")
        .env("HERMES_AUXILIARY_FREE_ONLY", "true")
        .env("COMMAND_EVE_HERMES_SOURCE", hermes_source)
        .env("COMMAND_EVE_HARNESS_TRACE_FILE", trace_path)
        .current_dir(hermes_source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

async fn stderr_output(stderr: tokio::process::ChildStderr) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        let mut stderr = stderr;
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output).await;
        output
    })
}

async fn stop_fixture(mut child: tokio::process::Child, stderr_task: tokio::task::JoinHandle<String>) {
    let _ = kill_process_tree(&mut child).await;
    let stderr = tokio::time::timeout(Duration::from_secs(2), stderr_task)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    assert!(!stderr.contains("Traceback"), "Hermes fixture failed:\n{stderr}");
}

#[tokio::test]
#[ignore = "run via scripts/test-command-eve-durable-wake-e2e.sh with a pinned Hermes checkout"]
async fn provider_free_durable_wake_cross_language_busy_retry_then_accepts() {
    let hermes_source = required_path("COMMAND_EVE_HERMES_SOURCE");
    let python = required_path("COMMAND_EVE_HERMES_PYTHON");
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hermes_provider_free_async_completion.py");
    let temp = tempfile::tempdir().expect("tempdir");
    let hermes_home = temp.path().join("hermes-home");
    let home = temp.path().join("home");
    let trace_path = temp.path().join("wire.ndjson");
    let workspace = temp.path().join("workspace");
    std::fs::create_dir_all(&hermes_home).expect("Hermes home");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let command = fixture_command(&python, &fixture, &hermes_source, &home, &hermes_home, &trace_path);
    let mut child = command.spawn().expect("spawn provider-free Hermes ACP fixture");
    let stdin = child.stdin.take().expect("Hermes stdin");
    let stdout = child.stdout.take().expect("Hermes stdout");
    let stderr_task = stderr_output(child.stderr.take().expect("Hermes stderr")).await;

    let (event_tx, _event_rx) = broadcast::channel::<AgentStreamEvent>(16);
    let (permission_tx, _permission_rx) = mpsc::channel::<PermissionRequest>(4);
    let (notification_tx, _notification_rx) = mpsc::channel(16);
    let (completion_tx, mut completion_rx) = mpsc::channel(4);
    let route = CommandEveAsyncCompletionRoute {
        conversation_id: "conversation-provider-free".to_owned(),
        sender: completion_tx,
        project_build_options: None,
        session_binding: AcpSessionBinding::default(),
    };
    let protocol = AcpProtocol::connect_with_optional_async_completion(
        stdin,
        stdout,
        event_tx,
        permission_tx,
        notification_tx,
        Some(route),
    )
    .await
    .expect("connect to provider-free Hermes ACP");
    protocol
        .enable_async_completion()
        .expect("enable bound completion route");

    let session = protocol
        .new_session(NewSessionRequest::new(&workspace))
        .await
        .expect("create Hermes ACP session");
    protocol
        .prompt(PromptRequest::new(
            session.session_id.clone(),
            vec![ContentBlock::from(TRIGGER)],
        ))
        .await
        .expect("trigger provider-free background delegation");

    let first = tokio::time::timeout(Duration::from_secs(5), completion_rx.recv())
        .await
        .expect("first completion timeout")
        .expect("first completion dispatch");
    assert_eq!(first.conversation_id, "conversation-provider-free");
    assert_eq!(first.request.version, COMMAND_EVE_ASYNC_COMPLETION_VERSION);
    assert_eq!(first.request.session_id, session.session_id.0.as_ref());
    assert!(first.request.completion_id.starts_with("deleg_"));
    assert!(first.request.content.contains("PROVIDER_FREE_WORKER_DONE"));
    let first_request = serde_json::to_value(&first.request).expect("serialize first request");
    assert_eq!(first_request.as_object().expect("request object").len(), 4);
    first
        .reply
        .send(CommandEveAsyncCompletionResult::RetryableBusy {
            code: "conversation_busy".to_owned(),
        })
        .expect("return retryable acknowledgement");

    let second = tokio::time::timeout(Duration::from_secs(5), completion_rx.recv())
        .await
        .expect("retry completion timeout")
        .expect("retry completion dispatch");
    let second_request = serde_json::to_value(&second.request).expect("serialize retry request");
    assert_eq!(second_request, first_request, "Hermes must retry the exact durable DTO");
    second
        .reply
        .send(CommandEveAsyncCompletionResult::Completed {
            turn_id: "turn-provider-free-1".to_owned(),
        })
        .expect("return accepted acknowledgement");

    let trace = wait_for_trace(&trace_path, 2).await;
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0]["method"], "_command_eve/async_completion");
    assert_eq!(trace[0]["params"], first_request);
    assert_eq!(trace[0]["response"]["status"], "retryable");
    assert_eq!(trace[0]["response"]["code"], "conversation_busy");
    assert_eq!(trace[1]["method"], "_command_eve/async_completion");
    assert_eq!(trace[1]["params"], second_request);
    assert_eq!(trace[1]["response"]["status"], "accepted");
    assert_eq!(trace[1]["response"]["turn_id"], "turn-provider-free-1");

    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert!(
        completion_rx.try_recv().is_err(),
        "accepted completion must not run a third time"
    );

    drop(protocol);
    stop_fixture(child, stderr_task).await;
}

#[tokio::test]
#[ignore = "run via scripts/test-command-eve-durable-wake-e2e.sh with a pinned Hermes checkout"]
async fn provider_free_restart_load_retries_prebind_then_delivers_once() {
    let hermes_source = required_path("COMMAND_EVE_HERMES_SOURCE");
    let python = required_path("COMMAND_EVE_HERMES_PYTHON");
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hermes_provider_free_async_completion.py");
    let temp = tempfile::tempdir().expect("tempdir");
    let hermes_home = temp.path().join("hermes-home");
    let home = temp.path().join("home");
    let workspace = temp.path().join("workspace");
    let first_trace = temp.path().join("first-wire.ndjson");
    let restart_trace = temp.path().join("restart-wire.ndjson");
    std::fs::create_dir_all(&hermes_home).expect("Hermes home");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(&workspace).expect("workspace");

    let mut first_command = fixture_command(&python, &fixture, &hermes_source, &home, &hermes_home, &first_trace);
    first_command
        .env("COMMAND_EVE_HARNESS_PERSIST_SESSIONS", "1")
        .env("COMMAND_EVE_HARNESS_WAIT_FOR_DURABLE", "1");
    let mut first_child = first_command.spawn().expect("spawn first Hermes process");
    let first_stdin = first_child.stdin.take().expect("first Hermes stdin");
    let first_stdout = first_child.stdout.take().expect("first Hermes stdout");
    let first_stderr = stderr_output(first_child.stderr.take().expect("first Hermes stderr")).await;
    let (first_event_tx, _) = broadcast::channel::<AgentStreamEvent>(16);
    let (first_permission_tx, _) = mpsc::channel::<PermissionRequest>(4);
    let (first_notification_tx, _) = mpsc::channel(16);
    let first_protocol = AcpProtocol::connect(
        first_stdin,
        first_stdout,
        first_event_tx,
        first_permission_tx,
        first_notification_tx,
    )
    .await
    .expect("connect first provider-free Hermes process");
    let session = first_protocol
        .new_session(NewSessionRequest::new(&workspace))
        .await
        .expect("create durable Hermes ACP session");
    first_protocol
        .prompt(PromptRequest::new(
            session.session_id.clone(),
            vec![ContentBlock::from(TRIGGER)],
        ))
        .await
        .expect("persist provider-free pending completion");
    assert!(
        !first_trace.exists(),
        "non-capable first process must not deliver a wake"
    );
    drop(first_protocol);
    stop_fixture(first_child, first_stderr).await;

    let mut restart_command = fixture_command(&python, &fixture, &hermes_source, &home, &hermes_home, &restart_trace);
    restart_command
        .env("COMMAND_EVE_HARNESS_PERSIST_SESSIONS", "1")
        .env("COMMAND_EVE_HARNESS_LOAD_DELAY_MS", "1200");
    let mut restart_child = restart_command.spawn().expect("spawn restarted Hermes process");
    let restart_stdin = restart_child.stdin.take().expect("restarted Hermes stdin");
    let restart_stdout = restart_child.stdout.take().expect("restarted Hermes stdout");
    let restart_stderr = stderr_output(restart_child.stderr.take().expect("restarted Hermes stderr")).await;

    let (event_tx, _) = broadcast::channel::<AgentStreamEvent>(16);
    let (permission_tx, _) = mpsc::channel::<PermissionRequest>(4);
    let (notification_tx, _) = mpsc::channel(16);
    let (completion_tx, mut completion_rx) = mpsc::channel(4);
    let route = CommandEveAsyncCompletionRoute {
        conversation_id: "conversation-restart".to_owned(),
        sender: completion_tx,
        project_build_options: None,
        session_binding: AcpSessionBinding::default(),
    };
    let protocol = AcpProtocol::connect_with_optional_async_completion(
        restart_stdin,
        restart_stdout,
        event_tx,
        permission_tx,
        notification_tx,
        Some(route),
    )
    .await
    .expect("connect restarted provider-free Hermes process");
    protocol
        .enable_async_completion()
        .expect("enable restarted completion route");

    let mut load = Box::pin(protocol.load_session(LoadSessionRequest::new(session.session_id.clone(), &workspace)));
    let early_trace = tokio::select! {
        trace = wait_for_trace(&restart_trace, 1) => trace,
        result = &mut load => panic!("session/load returned before the required pre-bind wake: {result:?}"),
    };
    assert_eq!(early_trace.len(), 1);
    assert_eq!(early_trace[0]["method"], "_command_eve/async_completion");
    assert_eq!(early_trace[0]["response"]["status"], "retryable");
    assert_eq!(early_trace[0]["response"]["code"], "session_not_bound");
    assert!(
        completion_rx.try_recv().is_err(),
        "pre-bind wake must stay out of the consumer"
    );
    load.await.expect("load persisted Hermes ACP session after restart");

    let delivered = tokio::time::timeout(Duration::from_secs(5), completion_rx.recv())
        .await
        .expect("post-bind restart completion timeout")
        .expect("post-bind restart completion dispatch");
    assert_eq!(delivered.conversation_id, "conversation-restart");
    assert_eq!(delivered.request.session_id, session.session_id.0.as_ref());
    assert!(delivered.request.content.contains("PROVIDER_FREE_WORKER_DONE"));
    delivered
        .reply
        .send(CommandEveAsyncCompletionResult::Completed {
            turn_id: "turn-restart-1".to_owned(),
        })
        .expect("accept restored provider-free completion");

    let trace = wait_for_trace(&restart_trace, 2).await;
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[1]["method"], "_command_eve/async_completion");
    assert_eq!(trace[1]["params"], trace[0]["params"]);
    assert_eq!(trace[1]["response"]["status"], "accepted");
    assert_eq!(trace[1]["response"]["turn_id"], "turn-restart-1");
    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert!(
        completion_rx.try_recv().is_err(),
        "restored completion must dispatch exactly once after binding"
    );

    drop(protocol);
    stop_fixture(restart_child, restart_stderr).await;
}
