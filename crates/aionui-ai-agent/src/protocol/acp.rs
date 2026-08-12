//! ACP protocol layer: SDK integration for JSON-RPC communication.
//!
//! This module owns the `agent-client-protocol` SDK connection. It provides
//! typed async methods for all ACP operations (wrappers around the SDK's
//! `send_request` / `send_notification`) plus dedicated handlers for the
//! notifications and permission requests the CLI sends back.
//!
//! # Concurrency model
//!
//! We follow the SDK's documented best practice (see
//! `jsonrpc::Builder` "Event Loop and Concurrency" and
//! `jsonrpc::SentRequest::block_task` doc comments): `connect_with` runs the
//! SDK background actors on a dedicated tokio task; its `main_fn` completes
//! the `initialize` handshake, hands the resulting [`ConnectionTo<Agent>`] out
//! to this struct, and then parks on a shutdown oneshot until
//! [`AcpProtocol`] is dropped. The connection handle is `Clone + Send` and
//! is used directly by every method — outgoing requests / notifications go
//! through the SDK's own outgoing actor, so they are naturally concurrent.
//! No hand-rolled command channel is involved.
//!
//! This is what makes `session/cancel` preempt an in-flight `session/prompt`:
//! both requests are just `send_request` / `send_notification` calls on the
//! shared connection, each awaited in its own caller task.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use agent_client_protocol::schema::{
    AGENT_METHOD_NAMES, AuthenticateResponse, ClientCapabilities, ClientNotification, ClientRequest,
    CloseSessionResponse, ExtResponse, ForkSessionResponse, Implementation, InitializeRequest, LoadSessionResponse,
    PromptResponse, ProtocolVersion, RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
    ResumeSessionResponse, SelectedPermissionOutcome, SessionNotification, SetSessionConfigOptionResponse,
    SetSessionModeResponse, SetSessionModelResponse,
};
use agent_client_protocol::{
    Agent, AgentRequest, ByteStreams, Client, ConnectionTo, Responder, on_receive_notification, on_receive_request,
};
use aionui_common::ErrorChain;
use tokio::process::{ChildStdin, ChildStdout};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, info, warn};

use aionui_api_types::{
    AcpReadPreviewResponse, AcpReadPreviewResponseRequest, AcpReadTerminalResponse, AcpReadTerminalResponseRequest,
};

use crate::CommandEveAsyncCompletionRoute;
use crate::error::AgentError;
use crate::protocol::client_extensions::AcpClientExtensionRouter;
use crate::protocol::error::AcpError;
use crate::protocol::events::{self as stream_event, AgentStreamEvent};

use agent_client_protocol::schema::{
    AgentCapabilities, AuthMethod, AuthenticateRequest, CancelNotification, CloseSessionRequest, ExtNotification,
    ExtRequest, ForkSessionRequest, InitializeResponse, ListSessionsRequest, ListSessionsResponse, LoadSessionRequest,
    NewSessionRequest, NewSessionResponse, PromptRequest, ResumeSessionRequest, SetSessionConfigOptionRequest,
    SetSessionModeRequest, SetSessionModelRequest,
};

/// Timeout for the ACP initialize handshake (seconds).
const INIT_TIMEOUT_SECS: u64 = 30;

/// Client identity reported in the ACP `initialize` handshake (`clientInfo`).
///
/// Some agents forward these fields downstream as client metadata — e.g. Mistral
/// Vibe passes them to the Mistral API as `client_name`/`client_version`, which the
/// API rejects when empty. Always send non-empty values (see issue #3326).
const ACP_CLIENT_NAME: &str = "AionUi";
const ACP_CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMAND_EVE_ASYNC_COMPLETION_CAPABILITY_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcpConnectionPhase {
    Starting,
    Initializing,
    Ready,
    ShuttingDown,
}

/// Build the ACP `initialize` request, always populating `clientInfo` with a
/// non-empty name and version so downstream agents that require client metadata
/// (e.g. Mistral Vibe) accept the request. See issue #3326.
fn build_initialize_request(advertise_async_completion: bool) -> InitializeRequest {
    let mut client_capabilities = ClientCapabilities::new();
    if advertise_async_completion {
        let mut meta = serde_json::Map::new();
        meta.insert(
            "command_eve".to_owned(),
            serde_json::json!({
                "async_completion": {
                    "version": COMMAND_EVE_ASYNC_COMPLETION_CAPABILITY_VERSION
                }
            }),
        );
        client_capabilities = client_capabilities.meta(meta);
    }

    InitializeRequest::new(ProtocolVersion::LATEST)
        .client_capabilities(client_capabilities)
        .client_info(Implementation::new(ACP_CLIENT_NAME, ACP_CLIENT_VERSION))
}

/// A pending permission request from the agent, awaiting user decision.
pub struct PermissionRequest {
    /// Raw ACP permission request as defined by the SDK schema.
    pub request: RequestPermissionRequest,
    /// Channel to send the user's decision back to the SDK responder.
    pub response_tx: oneshot::Sender<PermissionDecision>,
}

/// User's decision on a permission request.
pub enum PermissionDecision {
    /// User selected a permission option.
    Selected { option_id: String },
    /// User cancelled (rejected) the request.
    Cancelled,
}

/// ACP protocol handle: wraps the SDK connection and provides typed operations.
///
/// All request methods are thin wrappers over `connection.send_request(...)
/// .block_task().await` — safe because each caller runs in its own tokio
/// task, separate from the SDK background actors spawned by `connect_with`.
pub struct AcpProtocol {
    /// SDK connection handle. Cheap to clone (channel senders only) and
    /// shared by every method. Kept alive by the background task parked
    /// on `shutdown_rx` in `connect_with`'s `main_fn`.
    connection: ConnectionTo<Agent>,
    /// Signal dropped on `Drop` to make `main_fn` return, which in turn
    /// lets the SDK background actors shut down cleanly.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Flipped to `false` when the background task exits. Used by
    /// [`Self::is_connected`] as a fast synchronous check.
    alive: Arc<AtomicBool>,
    /// Cached initialize response from the ACP handshake.
    initialize_response: Arc<RwLock<Option<InitializeResponse>>>,
    /// Set to `true` for the duration of a `session/load` request so that
    /// the SDK notification handler skips broadcasting the CLI's historical
    /// `session/update` replay to the UI event channel. The flag does NOT
    /// affect `notification_tx` — internal session aggregate updates keep
    /// flowing so metadata like `available_commands_update` still reaches
    /// `event_tracker`.
    ///
    /// Owned by the outer struct; an `Arc` clone is captured by the SDK
    /// background task's `on_receive_notification` closure.
    replay_suppression: Arc<AtomicBool>,
    /// Positive-allowlist agent-to-client extension router. It owns the
    /// canonical session binding and pending bounded renderer-read responders.
    client_extensions: AcpClientExtensionRouter,
}

#[allow(dead_code)] // Full ACP method set; some methods await wiring (fork, close, list, auth, ext).
impl AcpProtocol {
    /// Connect to a running CLI process and execute the ACP initialize handshake.
    ///
    /// Takes ownership of the child's stdin/stdout (from [`CliAgentProcess::take_stdio`]).
    /// Spawns the SDK background task for JSON-RPC message routing.
    /// Returns after the initialize handshake completes successfully.
    pub async fn connect(
        stdin: ChildStdin,
        stdout: ChildStdout,
        event_tx: broadcast::Sender<AgentStreamEvent>,
        permission_tx: mpsc::Sender<PermissionRequest>,
        notification_tx: mpsc::Sender<SessionNotification>,
    ) -> Result<Self, AcpError> {
        Self::connect_with_optional_async_completion(stdin, stdout, event_tx, permission_tx, notification_tx, None)
            .await
    }

    pub(crate) async fn connect_with_optional_async_completion(
        stdin: ChildStdin,
        stdout: ChildStdout,
        event_tx: broadcast::Sender<AgentStreamEvent>,
        permission_tx: mpsc::Sender<PermissionRequest>,
        notification_tx: mpsc::Sender<SessionNotification>,
        async_completion: Option<CommandEveAsyncCompletionRoute>,
    ) -> Result<Self, AcpError> {
        let alive = Arc::new(AtomicBool::new(true));
        let replay_suppression = Arc::new(AtomicBool::new(false));
        let advertise_async_completion = async_completion.is_some();
        let client_extensions = match async_completion {
            Some(route) => AcpClientExtensionRouter::new(event_tx.clone()).with_async_completion(route),
            None => AcpClientExtensionRouter::new(event_tx.clone()),
        };

        // Signals from the background task:
        // - `init_tx`: initialize handshake result (with possible SDK error)
        // - `ready_tx`: connection handle once init succeeded; if init fails
        //   this oneshot is dropped and the caller observes `NotConnected`
        let (init_tx, init_rx) = oneshot::channel::<Result<InitializeResponse, AcpError>>();
        let (ready_tx, ready_rx) = oneshot::channel::<ConnectionTo<Agent>>();

        // Signal from us → background task telling `main_fn` to return,
        // which triggers a clean SDK shutdown.
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(run_sdk_background(
            stdin,
            stdout,
            event_tx,
            permission_tx,
            notification_tx,
            init_tx,
            ready_tx,
            shutdown_rx,
            Arc::clone(&alive),
            Arc::clone(&replay_suppression),
            client_extensions.clone(),
            advertise_async_completion,
        ));

        // Wait for init to complete with timeout.
        let init_response = tokio::time::timeout(std::time::Duration::from_secs(INIT_TIMEOUT_SECS), init_rx)
            .await
            .map_err(|_| AcpError::InitTimeout {
                timeout_secs: INIT_TIMEOUT_SECS,
            })?
            .map_err(|_| AcpError::Disconnected {
                exit_code: None,
                signal: None,
                stderr: "Init channel dropped".into(),
            })??;

        // `ready_rx` should resolve almost immediately after init_tx fires.
        let connection = ready_rx.await.map_err(|_| AcpError::NotConnected)?;

        Ok(Self {
            connection,
            shutdown_tx: Some(shutdown_tx),
            alive,
            initialize_response: Arc::new(RwLock::new(Some(init_response))),
            replay_suppression,
            client_extensions,
        })
    }

    pub fn initialize_response(&self) -> Option<InitializeResponse> {
        self.initialize_response.read().unwrap().clone()
    }

    pub fn agent_capabilities(&self) -> Option<AgentCapabilities> {
        self.initialize_response().map(|response| response.agent_capabilities)
    }

    pub fn auth_methods(&self) -> Option<Vec<AuthMethod>> {
        self.initialize_response().map(|response| response.auth_methods)
    }

    /// Create a new ACP session.
    pub async fn new_session(&self, req: NewSessionRequest) -> Result<NewSessionResponse, AcpError> {
        // Invalidate the previous binding up front: while the request is in
        // flight the route is unbound (completions stay retryable), and a
        // failed request leaves it unbound instead of trusting the old
        // session.
        self.client_extensions.begin_session_binding().await;
        let response = self.send_request(req, AGENT_METHOD_NAMES.session_new).await?;
        self.client_extensions
            .bind_session(response.session_id.0.as_ref())
            .await?;
        Ok(response)
    }

    /// Load (resume) an existing ACP session.
    ///
    /// Backends that support `session/load` (e.g. Codex) will replay the
    /// entire conversation as `session/update` notifications between the
    /// moment the request is sent and the moment the response returns.
    /// Those replayed events are historical and must not reach the UI —
    /// the frontend already renders history from the local DB. The RAII
    /// `ReplaySuppressionGuard` flips `replay_suppression` on for the
    /// duration of the request so the SDK notification handler skips the
    /// UI broadcast path for replay events.
    ///
    /// Note: Claude resumes via `session/new` with `_meta.claudeCode.options.resume`
    /// and never calls this method, so it is unaffected by the guard.
    pub async fn load_session(&self, req: LoadSessionRequest) -> Result<LoadSessionResponse, AcpError> {
        let session_id = req.session_id.0.clone();
        self.client_extensions.begin_session_binding().await;
        let _guard = ReplaySuppressionGuard::new(&self.replay_suppression);
        let response = self.send_request(req, AGENT_METHOD_NAMES.session_load).await?;
        self.client_extensions.bind_session(session_id.as_ref()).await?;
        Ok(response)
    }

    /// Fork an existing ACP session into a new session.
    pub async fn fork_session(&self, req: ForkSessionRequest) -> Result<ForkSessionResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_fork).await
    }

    /// Resume an existing ACP session.
    pub async fn resume_session(&self, req: ResumeSessionRequest) -> Result<ResumeSessionResponse, AcpError> {
        let session_id = req.session_id.0.clone();
        self.client_extensions.begin_session_binding().await;
        let response = self.send_request(req, AGENT_METHOD_NAMES.session_resume).await?;
        self.client_extensions.bind_session(session_id.as_ref()).await?;
        Ok(response)
    }

    /// Close an ACP session.
    pub async fn close_session(&self, req: CloseSessionRequest) -> Result<CloseSessionResponse, AcpError> {
        let session_id = req.session_id.0.clone();
        let response = self.send_request(req, AGENT_METHOD_NAMES.session_close).await?;
        self.client_extensions.unbind_session(session_id.as_ref()).await;
        Ok(response)
    }

    /// Deliver the renderer's bounded response to the one matching
    /// agent-to-client `read_preview` request.
    pub fn respond_read_preview(
        &self,
        response: AcpReadPreviewResponseRequest,
    ) -> Result<AcpReadPreviewResponse, AgentError> {
        self.client_extensions.respond_read_preview(response)
    }

    /// Enable the bounded renderer readback extension for verified Hermes
    /// manager instances. Other ACP backends remain method-not-found.
    pub(crate) fn enable_read_preview(&self) -> Result<(), AcpError> {
        self.client_extensions.enable_read_preview()
    }

    /// Deliver the renderer's bounded response to the one matching
    /// agent-to-client `read_terminal` request.
    pub fn respond_read_terminal(
        &self,
        response: AcpReadTerminalResponseRequest,
    ) -> Result<AcpReadTerminalResponse, AgentError> {
        self.client_extensions.respond_read_terminal(response)
    }

    /// Enable the bounded terminal readback extension for verified Hermes
    /// manager instances. Other ACP backends remain method-not-found.
    pub(crate) fn enable_read_terminal(&self) -> Result<(), AcpError> {
        self.client_extensions.enable_read_terminal()
    }

    pub(crate) fn enable_async_completion(&self) -> Result<(), AcpError> {
        self.client_extensions.enable_async_completion()
    }

    /// Send a prompt to the agent in an active session.
    ///
    /// Blocks until the agent returns a `PromptResponse` (turn completed).
    /// Streaming events arrive via the `event_tx` broadcast channel.
    pub async fn prompt(&self, req: PromptRequest) -> Result<PromptResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_prompt).await
    }

    /// Submit a cancellation notification to the live ACP transport. This is
    /// only a local transport admission receipt, never terminal worker proof.
    /// A disconnected or closed outbound channel returns an error so callers
    /// cannot truthfully report cancellation as accepted.
    pub fn cancel(&self, notification: CancelNotification) -> Result<(), AcpError> {
        self.ensure_connected()?;
        log_client_notify(AGENT_METHOD_NAMES.session_cancel, &json_str(&notification));
        self.connection
            .send_notification(notification)
            .map_err(|error| AcpError::AgentInternal {
                message: "ACP cancel notification transport failed".to_owned(),
                code: i32::from(error.code),
                data: error.data,
            })
    }

    /// Set the session mode.
    pub async fn set_mode(&self, req: SetSessionModeRequest) -> Result<SetSessionModeResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_set_mode).await
    }

    /// Set the session model.
    pub async fn set_model(&self, req: SetSessionModelRequest) -> Result<SetSessionModelResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_set_model).await
    }

    /// Set a session config option.
    pub async fn set_config_option(
        &self,
        req: SetSessionConfigOptionRequest,
    ) -> Result<SetSessionConfigOptionResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_set_config_option)
            .await
    }

    /// List sessions, optionally filtered by working directory.
    pub async fn list_sessions(&self, req: ListSessionsRequest) -> Result<ListSessionsResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.session_list).await
    }

    /// Authenticate with the agent using a previously advertised auth method.
    pub async fn authenticate(&self, req: AuthenticateRequest) -> Result<AuthenticateResponse, AcpError> {
        self.send_request(req, AGENT_METHOD_NAMES.authenticate).await
    }

    /// Send an extension request (method name must start with `_`).
    ///
    /// Returns the raw JSON response value from the agent.
    pub async fn ext_request(&self, req: ExtRequest) -> Result<ExtResponse, AcpError> {
        self.ensure_connected()?;
        let method = format!("_{}", req.method);
        let wrapped = ClientRequest::ExtMethodRequest(req);
        let value = self.send_request(wrapped, &method).await?;
        let raw = serde_json::value::to_raw_value(&value).map_err(|e| AcpError::AgentInternal {
            message: format!("Failed to convert ext response: {e}"),
            code: -32603,
            data: None,
        })?;
        Ok(ExtResponse::new(raw.into()))
    }

    /// Send an extension notification (fire-and-forget, method name must start with `_`).
    pub fn ext_notify(&self, notification: ExtNotification) {
        if !self.is_connected() {
            return;
        }
        let method = format!("_{}", notification.method);
        log_client_notify(&method, &json_str(&notification));
        let wrapped = ClientNotification::ExtNotification(notification);
        let _ = self.connection.send_notification(wrapped);
    }

    /// Check whether the SDK connection is still alive.
    pub fn is_connected(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    // ── Private helpers ──────────────────────────────────────────────────

    /// Shared request path: connectivity check, structured logging, SDK call.
    async fn send_request<Req>(&self, req: Req, method: &str) -> Result<Req::Response, AcpError>
    where
        Req: agent_client_protocol::JsonRpcRequest + serde::Serialize + std::fmt::Debug,
        Req::Response: serde::Serialize + std::fmt::Debug + Send,
    {
        self.ensure_connected()?;
        log_client_request(method, &json_str(&req));
        let rsp = self.connection.send_request(req).block_task().await;
        log_agent_response(method, &json_or_err(&rsp));
        rsp.map_err(|e| AcpError::from_sdk(e, method))
    }

    /// Return `Err(NotConnected)` if the connection is dead.
    fn ensure_connected(&self) -> Result<(), AcpError> {
        if self.is_connected() {
            Ok(())
        } else {
            Err(AcpError::NotConnected)
        }
    }
}

impl Drop for AcpProtocol {
    fn drop(&mut self) {
        self.client_extensions.cancel_all("protocol_dropped");
        // Releasing the oneshot wakes `main_fn` in the background task, which
        // returns, which drives SDK shutdown. The bg_task joins naturally
        // (we don't await it here — Drop can't be async; the task is
        // `tokio::spawn`ed, so it gets cleaned up by the runtime).
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Scoped guard: set an `AtomicBool` to `true` on construction, reset to
/// `false` on drop. Used to mark the inclusive time window of a
/// `session/load` request so that the SDK notification handler can
/// suppress UI broadcasts of the CLI's historical replay.
///
/// Using a guard (instead of manual `store` around `send_request`) ensures
/// the flag is cleared even if the future is cancelled, the request fails,
/// or the task panics.
struct ReplaySuppressionGuard<'a> {
    flag: &'a AtomicBool,
}

impl<'a> ReplaySuppressionGuard<'a> {
    fn new(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);
        Self { flag }
    }
}

impl Drop for ReplaySuppressionGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

/// Run the SDK `connect_with` future: register notification/request
/// handlers, execute the initialize handshake, publish the connection
/// handle, then park on the shutdown signal until [`AcpProtocol`] is dropped.
#[allow(clippy::too_many_arguments)]
async fn run_sdk_background(
    stdin: ChildStdin,
    stdout: ChildStdout,
    event_tx: broadcast::Sender<AgentStreamEvent>,
    permission_tx: mpsc::Sender<PermissionRequest>,
    notification_tx: mpsc::Sender<SessionNotification>,
    init_tx: oneshot::Sender<Result<InitializeResponse, AcpError>>,
    ready_tx: oneshot::Sender<ConnectionTo<Agent>>,
    shutdown_rx: oneshot::Receiver<()>,
    alive: Arc<AtomicBool>,
    replay_suppression: Arc<AtomicBool>,
    client_extensions: AcpClientExtensionRouter,
    advertise_async_completion: bool,
) {
    let transport = ByteStreams::new(stdin.compat_write(), stdout.compat());

    // `init_tx` / `ready_tx` are consumed inside the main_fn closure; wrap
    // them in Option so we can .take() without moving out of captured state.
    let mut init_tx = Some(init_tx);
    let mut ready_tx = Some(ready_tx);
    let mut shutdown_rx = Some(shutdown_rx);
    let phase = Arc::new(Mutex::new(AcpConnectionPhase::Starting));
    let phase_for_main = Arc::clone(&phase);

    let result = Client
        .builder()
        .on_receive_notification(
            {
                let event_tx = event_tx.clone();
                let notification_tx = notification_tx.clone();
                let replay_suppression = Arc::clone(&replay_suppression);
                async move |notification: SessionNotification, _cx: ConnectionTo<Agent>| {
                    // Fan out the raw SDK notification to the manager's apply-loop
                    // FIRST, so session state is consistent by the time the UI
                    // event hits the broadcast channel. Swallow send errors — if
                    // the manager has dropped the receiver, session consistency
                    // is moot anyway (we're on our way down).
                    let _ = notification_tx.send(notification.clone()).await;

                    // During a session/load request, the CLI replays historical
                    // session/update notifications back to us. The frontend
                    // already renders history from the local DB, so broadcasting
                    // the replay would produce duplicate UI blocks. Keep feeding
                    // notification_tx (event_tracker still needs metadata like
                    // available_commands_update), but skip the UI broadcast.
                    if !replay_suppression.load(Ordering::Acquire) {
                        handle_session_notification(notification, &event_tx).await;
                    }
                    Ok(())
                }
            },
            on_receive_notification!(),
        )
        .on_receive_request(
            {
                async move |request: RequestPermissionRequest, responder, _cx| {
                    handle_permission_request(request, responder, &permission_tx).await;
                    Ok(())
                }
            },
            on_receive_request!(),
        )
        .on_receive_request(
            {
                let client_extensions = client_extensions.clone();
                async move |request: AgentRequest, responder, _cx| {
                    client_extensions.handle_agent_request(request, responder);
                    Ok(())
                }
            },
            on_receive_request!(),
        )
        .connect_with(transport, async move |connection: ConnectionTo<Agent>| {
            // Step 1 — initialize handshake. main_fn is the canonical place
            // to call `block_task` (see SDK `connect_with` doc example).
            let init_result = {
                let req = build_initialize_request(advertise_async_completion);
                log_client_request("initialize", &json_str(&req));
                *phase_for_main.lock().unwrap() = AcpConnectionPhase::Initializing;
                let raw = connection.send_request(req).block_task().await;
                log_agent_response("initialize", &json_or_err(&raw));
                raw.map_err(|e| AcpError::from_sdk(e, "initialize"))
            };

            let Some(tx) = init_tx.take() else {
                return Ok(());
            };
            match init_result {
                Ok(resp) => {
                    let _ = tx.send(Ok(resp));
                }
                Err(err) => {
                    let _ = tx.send(Err(err));
                    // init failure: let main_fn return so SDK cleans up.
                    return Ok(());
                }
            }

            // Step 2 — publish the connection handle so the outer
            // AcpProtocol can start issuing requests.
            if let Some(tx) = ready_tx.take()
                && tx.send(connection).is_err()
            {
                // Owner dropped before we became ready — nothing more to do.
                return Ok(());
            }
            *phase_for_main.lock().unwrap() = AcpConnectionPhase::Ready;

            // Step 3 — keep the connection alive until AcpProtocol::drop
            // releases the shutdown oneshot.
            if let Some(rx) = shutdown_rx.take() {
                let _ = rx.await;
                *phase_for_main.lock().unwrap() = AcpConnectionPhase::ShuttingDown;
            }
            Ok(())
        })
        .await;

    alive.store(false, Ordering::Release);
    client_extensions.cancel_all("connection_closed");

    let close_phase = *phase.lock().unwrap();
    match result {
        Ok(_) => debug!(?close_phase, "ACP SDK connection closed normally"),
        Err(e) => warn!(?close_phase, error = %ErrorChain(&e), "ACP SDK connection closed with error"),
    }
}

/// Fan out a CLI session notification to the event broadcast channel.
async fn handle_session_notification(
    notification: SessionNotification,
    event_tx: &broadcast::Sender<AgentStreamEvent>,
) {
    log_agent_notify("session/update", &json_str(&notification));

    let events = stream_event::session_notification_to_events(&notification);
    for event in events {
        if let Err(e) = event_tx.send(event) {
            // broadcast::SendError means no active receivers — expected when
            // no subscribers are attached to this agent. Log at debug so it
            // doesn't spam after a turn finishes.
            debug!(error = %e, "Dropping ACP event: no active broadcast receivers");
        }
    }
}

/// Relay a CLI permission request to the pending-permission channel and
/// forward the user's decision back to the SDK responder.
async fn handle_permission_request(
    request: RequestPermissionRequest,
    responder: Responder<RequestPermissionResponse>,
    event_tx: &mpsc::Sender<PermissionRequest>,
) {
    log_agent_request("session/request_permission", &json_str(&request));

    let (response_tx, response_rx) = oneshot::channel();

    if event_tx.send(PermissionRequest { request, response_tx }).await.is_err() {
        warn!("Permission channel closed, cancelling request");
        let _ = responder.respond(RequestPermissionResponse::new(RequestPermissionOutcome::Cancelled));
        return;
    }

    let response = match response_rx.await {
        Ok(PermissionDecision::Selected { option_id }) => RequestPermissionResponse::new(
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(option_id)),
        ),
        Ok(PermissionDecision::Cancelled) | Err(_) => {
            RequestPermissionResponse::new(RequestPermissionOutcome::Cancelled)
        }
    };

    log_client_response("session/request_permission", &json_str(&response));
    let _ = responder.respond(response);
}

/// Serialize a value to a compact JSON string, falling back to Debug on failure.
fn json_str(value: &(impl serde::Serialize + std::fmt::Debug)) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}"))
}

/// Serialize the Ok side of a Result to JSON, or format the Err with Debug.
fn json_or_err<T: serde::Serialize + std::fmt::Debug, E: std::fmt::Debug>(result: &Result<T, E>) -> String {
    match result {
        Ok(v) => json_str(v),
        Err(e) => format!("{e:?}"),
    }
}

/// Returns `true` when the `session/update` notification body carries a
/// piece of the prompt-reply stream (high-frequency, high-volume content).
///
/// Unknown / new `sessionUpdate` kinds default to `false` so newly added
/// metadata events stay visible at `info!` until explicitly classified.
fn is_streaming_chunk(body: &str) -> bool {
    // Streaming chunks of the prompt reply: token-level message / thought
    // text, and the incremental tool_call / plan structures the agent emits
    // mid-response. Their `_update` siblings are part of the same stream.
    const STREAMING_KINDS: &[&str] = &[
        "agent_message_chunk",
        "agent_thought_chunk",
        "user_message_chunk",
        "tool_call",
        "tool_call_update",
        "plan",
    ];
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let kind = value
        .pointer("/update/sessionUpdate")
        .and_then(serde_json::Value::as_str);
    matches!(kind, Some(k) if STREAMING_KINDS.contains(&k))
}

struct AcpLogSummary {
    payload_bytes: usize,
    payload_json: bool,
    session_id: Option<String>,
    session_update_kind: Option<String>,
}

impl AcpLogSummary {
    fn from_payload(payload: &str) -> Self {
        let payload_bytes = payload.len();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            return Self {
                payload_bytes,
                payload_json: false,
                session_id: None,
                session_update_kind: None,
            };
        };

        Self {
            payload_bytes,
            payload_json: true,
            session_id: string_pointer(&value, &["/sessionId", "/session_id"]),
            session_update_kind: string_pointer(&value, &["/update/sessionUpdate", "/update/session_update"]),
        }
    }
}

fn string_pointer(value: &serde_json::Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer).and_then(serde_json::Value::as_str))
        .map(str::to_owned)
}

/// Log a JSON-RPC request from AionUi to the ACP agent.
/// `session/prompt` carries large user input and stays at debug.
fn log_client_request(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    if method == "session/prompt" {
        debug!(
            direction = "client_request",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            "[ACP] ->"
        );
    } else {
        info!(
            direction = "client_request",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            "[ACP] ->"
        );
    }
}

/// Log a JSON-RPC response from the ACP agent.
/// `session/prompt` reply is large; stays at debug.
fn log_agent_response(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    if method == "session/prompt" {
        debug!(
            direction = "agent_response",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            "[ACP] <- ${method}"
        );
    } else {
        info!(
            direction = "agent_response",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            "[ACP] <- ${method}"
        );
    }
}

/// Log a fire-and-forget notification from AionUi to the agent.
fn log_client_notify(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    info!(
        direction = "client_notify",
        method,
        payload_bytes = summary.payload_bytes,
        payload_json = summary.payload_json,
        session_id = summary.session_id.as_deref().unwrap_or("none"),
        "[ACP] -> ${method}"
    );
}

/// Log an inbound notification from the agent.
/// `session/update` requires per-kind filtering — streaming chunks stay at debug.
fn log_agent_notify(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    if method == "session/update" && is_streaming_chunk(body) {
        debug!(
            direction = "agent_notify",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            session_update_kind = summary.session_update_kind.as_deref().unwrap_or("none"),
            "[ACP] <- ${method}"
        );
    } else {
        info!(
            direction = "agent_notify",
            method,
            payload_bytes = summary.payload_bytes,
            payload_json = summary.payload_json,
            session_id = summary.session_id.as_deref().unwrap_or("none"),
            session_update_kind = summary.session_update_kind.as_deref().unwrap_or("none"),
            "[ACP] <- ${method}"
        );
    }
}

/// Log an inbound request from the agent (e.g. session/request_permission).
fn log_agent_request(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    info!(
        direction = "agent_request",
        method,
        payload_bytes = summary.payload_bytes,
        payload_json = summary.payload_json,
        session_id = summary.session_id.as_deref().unwrap_or("none"),
        "[ACP] <- ${method}"
    );
}

/// Log a JSON-RPC response from AionUi back to the agent.
fn log_client_response(method: &str, body: &str) {
    let summary = AcpLogSummary::from_payload(body);
    info!(
        direction = "client_response",
        method,
        payload_bytes = summary.payload_bytes,
        payload_json = summary.payload_json,
        session_id = summary.session_id.as_deref().unwrap_or("none"),
        "[ACP] -> ${method}"
    );
}

impl std::fmt::Debug for AcpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpProtocol")
            .field("alive", &self.is_connected())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[cfg(unix)]
    const MOCK_ACP_AGENT: &str = r#"
import json
import pathlib
import sys
import time

marker = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] else None
preview_sent = False

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method is None:
        if message.get("id") == "preview-rpc" and marker is not None:
            marker.write_text(json.dumps(message))
        continue

    request_id = message.get("id")
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {}, "authMethods": []}
    elif method == "session/new":
        result = {"sessionId": "new-session"}
    elif method in ("session/load", "session/resume", "session/close"):
        result = {}
    else:
        result = None

    if request_id is not None:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)

    if method == "session/new" and not preview_sent:
        preview_sent = True
        time.sleep(0.05)
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": "preview-rpc",
            "method": "_command_eve/read_preview",
            "params": {
                "version": "command-eve-read-preview/v1",
                "request_id": "preview-request",
                "session_id": "new-session",
                "start": 0,
                "count": 10
            }
        }), flush=True)
"#;

    #[cfg(unix)]
    async fn connect_mock_agent(
        marker: Option<&std::path::Path>,
    ) -> (
        AcpProtocol,
        broadcast::Receiver<AgentStreamEvent>,
        tokio::process::Child,
    ) {
        use std::process::Stdio;

        let python = which::which("python3").expect("python3 is required for ACP lifecycle regression tests");
        let mut child = tokio::process::Command::new(python)
            .arg("-u")
            .arg("-c")
            .arg(MOCK_ACP_AGENT)
            .arg(
                marker
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mock ACP agent");
        let stdin = child.stdin.take().expect("mock stdin");
        let stdout = child.stdout.take().expect("mock stdout");
        let (event_tx, event_rx) = broadcast::channel(16);
        let (permission_tx, _permission_rx) = mpsc::channel(4);
        let (notification_tx, _notification_rx) = mpsc::channel(4);
        let protocol = AcpProtocol::connect(stdin, stdout, event_tx, permission_tx, notification_tx)
            .await
            .expect("connect mock ACP agent");
        (protocol, event_rx, child)
    }

    fn capture_logs(max_level: tracing::Level, f: impl FnOnce()) -> String {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt;

        #[derive(Clone)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let make_writer = {
            let buffer = Arc::clone(&buffer);
            move || SharedBuf(Arc::clone(&buffer))
        };

        let subscriber = fmt::Subscriber::builder()
            .with_max_level(max_level)
            .with_writer(make_writer)
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, f);

        String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn connect_new_load_resume_close_bind_the_canonical_extension_session() {
        let (protocol, mut event_rx, mut child) = connect_mock_agent(None).await;
        protocol.enable_read_preview().unwrap();
        assert_eq!(protocol.client_extensions.bound_session_id(), None);

        let temp = tempfile::tempdir().unwrap();
        let created = protocol
            .new_session(NewSessionRequest::new(temp.path()))
            .await
            .expect("session/new");
        assert_eq!(created.session_id.0.as_ref(), "new-session");
        assert_eq!(
            protocol.client_extensions.bound_session_id().as_deref(),
            Some("new-session")
        );

        let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("read_preview event timeout")
            .expect("read_preview event");
        assert!(matches!(
            event,
            AgentStreamEvent::AcpReadPreviewRequest(data)
                if data.request_id == "preview-request" && data.session_id == "new-session"
        ));
        assert_eq!(protocol.client_extensions.pending_count(), 1);
        protocol
            .respond_read_preview(AcpReadPreviewResponseRequest {
                version: aionui_api_types::COMMAND_EVE_READ_PREVIEW_VERSION.to_owned(),
                request_id: "preview-request".to_owned(),
                session_id: "new-session".to_owned(),
                result: None,
            })
            .expect("correlated read_preview response");
        assert_eq!(protocol.client_extensions.pending_count(), 0);

        protocol
            .load_session(LoadSessionRequest::new("loaded-session", temp.path()))
            .await
            .expect("session/load");
        assert_eq!(
            protocol.client_extensions.bound_session_id().as_deref(),
            Some("loaded-session")
        );

        protocol
            .resume_session(ResumeSessionRequest::new("resumed-session", temp.path()))
            .await
            .expect("session/resume");
        assert_eq!(
            protocol.client_extensions.bound_session_id().as_deref(),
            Some("resumed-session")
        );

        protocol
            .close_session(CloseSessionRequest::new("resumed-session"))
            .await
            .expect("session/close");
        assert_eq!(protocol.client_extensions.bound_session_id(), None);

        drop(protocol);
        if tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .is_err()
        {
            let _ = child.kill().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn protocol_drop_rejects_pending_read_preview_exactly_once() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("drop-response.json");
        let (protocol, mut event_rx, mut child) = connect_mock_agent(Some(&marker)).await;
        protocol.enable_read_preview().unwrap();
        protocol
            .new_session(NewSessionRequest::new(temp.path()))
            .await
            .expect("session/new");
        let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("read_preview event timeout")
            .expect("read_preview event");
        assert!(matches!(event, AgentStreamEvent::AcpReadPreviewRequest(_)));
        assert_eq!(protocol.client_extensions.pending_count(), 1);

        drop(protocol);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("drop response marker");
        let response: serde_json::Value = serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        assert_eq!(response["id"], "preview-rpc");
        assert_eq!(response["error"]["code"], -32603);
        assert_eq!(response["error"]["data"]["reason"], "protocol_dropped");

        if tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .is_err()
        {
            let _ = child.kill().await;
        }
    }

    #[test]
    fn replay_suppression_guard_sets_and_clears_flag() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::Acquire));

        {
            let _guard = ReplaySuppressionGuard::new(&flag);
            assert!(flag.load(Ordering::Acquire));
        }

        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn replay_suppression_guard_clears_on_panic_unwind() {
        // Use catch_unwind to ensure Drop runs even when the scope panics.
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let flag_for_closure = std::sync::Arc::clone(&flag);

        // &AtomicBool is not UnwindSafe (shared ref), so AssertUnwindSafe is required.
        // This test also relies on panic = "unwind" (the default); it would not run under panic = "abort".
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ReplaySuppressionGuard::new(&flag_for_closure);
            assert!(flag_for_closure.load(Ordering::Acquire));
            panic!("simulated failure inside load_session");
        }));

        assert!(!flag.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn replay_suppression_guard_scopes_to_future_lifetime() {
        // Simulate load_session's body: guard lives across an await point
        // then drops at function return. Verify the flag sees true during
        // the await and false afterward.
        let flag = Arc::new(AtomicBool::new(false));
        let flag_probe = Arc::clone(&flag);

        async fn simulated_load(flag: &AtomicBool, probe: Arc<AtomicBool>) -> bool {
            let _guard = ReplaySuppressionGuard::new(flag);
            // Yield to the runtime so we know the guard survives .await.
            tokio::task::yield_now().await;
            probe.load(Ordering::Acquire)
        }

        let seen_during = simulated_load(&flag, Arc::clone(&flag_probe)).await;
        assert!(seen_during, "flag should be true inside guarded scope");
        assert!(!flag.load(Ordering::Acquire), "flag should be false after guard drop");
    }

    #[test]
    fn log_agent_notify_filters_streaming_chunks_and_omits_raw_body() {
        use tracing::Level;

        let captured = capture_logs(Level::INFO, || {
            log_agent_notify(
                "session/update",
                r#"{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hidden stream text"}}}"#,
            );
            log_agent_notify(
                "session/update",
                r#"{"sessionId":"s1","update":{"sessionUpdate":"current_mode_update","modeId":"yolo"}}"#,
            );
        });

        assert!(
            !captured.contains("agent_message_chunk"),
            "streaming chunk should NOT appear at info level: {captured}"
        );
        assert!(
            captured.contains("current_mode_update"),
            "non-streaming update should appear at info level: {captured}"
        );
        assert!(
            !captured.contains("hidden stream text"),
            "streaming content should not be logged: {captured}"
        );
        assert!(
            !captured.contains("modeId") && !captured.contains("yolo"),
            "raw notification body should not be logged: {captured}"
        );
        assert!(
            captured.contains("agent_notify"),
            "structured `direction` field should be `agent_notify`: {captured}"
        );
        assert!(
            captured.contains("session/update"),
            "structured `method` field should be present: {captured}"
        );
        assert!(
            captured.contains("payload_bytes"),
            "payload size summary should be present: {captured}"
        );
    }

    #[test]
    fn log_client_request_omits_prompt_body_even_at_debug_level() {
        use tracing::Level;

        let captured = capture_logs(Level::DEBUG, || {
            log_client_request(
                "session/prompt",
                r#"{"sessionId":"s1","prompt":[{"type":"text","text":"secret prompt text"}]}"#,
            );
        });

        assert!(
            captured.contains("client_request"),
            "structured `direction` field should be present: {captured}"
        );
        assert!(
            captured.contains("session/prompt"),
            "structured `method` field should be present: {captured}"
        );
        assert!(
            captured.contains("payload_bytes"),
            "payload size summary should be present: {captured}"
        );
        assert!(
            !captured.contains("secret prompt text") && !captured.contains("\"prompt\""),
            "raw prompt body should not be logged: {captured}"
        );
    }

    #[test]
    fn is_streaming_chunk_recognises_prompt_stream_kinds() {
        // SDK delivers `params` already unwrapped — `body` here mirrors what
        // the log helpers receive: the JSON-RPC params object with `sessionId`
        // and `update` at the top level.
        let body_chunk = r#"{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}"#;
        let mode_update = r#"{"sessionId":"s1","update":{"sessionUpdate":"current_mode_update","modeId":"yolo"}}"#;
        let unknown = r#"{"sessionId":"s1","update":{"sessionUpdate":"future_unknown_kind"}}"#;
        let malformed = "not json";

        assert!(is_streaming_chunk(body_chunk));
        assert!(!is_streaming_chunk(mode_update));
        assert!(!is_streaming_chunk(unknown), "unknown kinds default to keep");
        assert!(!is_streaming_chunk(malformed), "malformed bodies default to keep");
    }

    #[test]
    fn initialize_request_sends_non_empty_client_info() {
        // Regression test for #3326: agents like Mistral Vibe forward clientInfo
        // downstream as client_name/client_version and reject empty values.
        let req = build_initialize_request(false);

        let client_info = req.client_info.as_ref().expect("clientInfo must be present");
        assert_eq!(client_info.name, "AionUi");
        assert!(!client_info.name.is_empty(), "client name must not be empty");
        assert!(!client_info.version.is_empty(), "client version must not be empty");

        // The serialized handshake must carry non-empty camelCase clientInfo fields.
        let json = serde_json::to_value(&req).expect("request serializes");
        assert_eq!(json["clientInfo"]["name"], "AionUi");
        assert_ne!(json["clientInfo"]["version"], "");
        assert!(
            json["clientCapabilities"].get("_meta").is_none(),
            "ordinary ACP clients must not advertise Command EVE async completion"
        );
    }

    #[test]
    fn initialize_request_advertises_async_completion_only_for_a_configured_route() {
        let enabled = serde_json::to_value(build_initialize_request(true)).expect("request serializes");
        assert_eq!(
            enabled["clientCapabilities"]["_meta"]["command_eve"]["async_completion"]["version"],
            COMMAND_EVE_ASYNC_COMPLETION_CAPABILITY_VERSION
        );

        let disabled = serde_json::to_value(build_initialize_request(false)).expect("request serializes");
        assert!(disabled["clientCapabilities"].get("_meta").is_none());
    }
}
