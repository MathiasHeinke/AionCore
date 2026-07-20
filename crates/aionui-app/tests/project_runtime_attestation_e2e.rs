//! HTTP-boundary coverage for the local-only project runtime attestation contract.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aionui_ai_agent::{AgentInstance, IAgentTask, IMockAgent, WorkerTaskManagerImpl};
use aionui_api_types::ProjectRuntimeWorkspaceRequest;
use aionui_auth::{
    LOCAL_CAPABILITY_HEADER, LocalCapabilityVerifier, PROJECT_RUNTIME_ATTESTATION_HEADER,
    ProjectRuntimeAttestationClaims, ProjectRuntimeAttestationPurpose, sign_project_runtime_attestation,
};
use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const LOCAL_CAPABILITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PROJECT_ID: &str = "018f0c00-0000-4000-8000-000000000001";
const REALM_ID: &str = "018f0c00-0000-4000-8000-000000000003";
const ROOT_ID: &str = "018f0c00-0000-4000-8000-000000000004";
const ROOT_REF: &str = "root:018f0c00-0000-4000-8000-000000000004";

struct NoopProjectAgent {
    conversation_id: String,
    workspace: String,
}

#[async_trait::async_trait]
impl IAgentTask for NoopProjectAgent {
    fn agent_type(&self) -> aionui_common::AgentType {
        aionui_common::AgentType::Acp
    }

    fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    fn workspace(&self) -> &str {
        &self.workspace
    }

    fn status(&self) -> Option<aionui_common::ConversationStatus> {
        None
    }

    fn last_activity_at(&self) -> aionui_common::TimestampMs {
        aionui_common::now_ms()
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<aionui_ai_agent::AgentStreamEvent> {
        let (sender, _) = tokio::sync::broadcast::channel(1);
        sender.subscribe()
    }

    async fn send_message(
        &self,
        _data: aionui_ai_agent::types::SendMessageData,
    ) -> Result<(), aionui_ai_agent::AgentSendError> {
        Ok(())
    }

    async fn cancel(&self) -> Result<(), aionui_ai_agent::AgentError> {
        Ok(())
    }

    fn kill(&self, _reason: Option<aionui_common::AgentKillReason>) -> Result<(), aionui_ai_agent::AgentError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl IMockAgent for NoopProjectAgent {}

async fn build_local_app() -> (axum::Router, aionui_app::AppServices, tempfile::TempDir) {
    let app_data = tempfile::tempdir().unwrap();
    let database = aionui_db::init_database_memory().await.unwrap();
    let factory: Arc<
        dyn Fn(
                aionui_ai_agent::types::BuildTaskOptions,
            )
                -> futures_util::future::BoxFuture<'static, Result<AgentInstance, aionui_ai_agent::AgentError>>
            + Send
            + Sync,
    > = Arc::new(|options| {
        Box::pin(async move {
            Ok(AgentInstance::Mock(Arc::new(NoopProjectAgent {
                conversation_id: options.conversation_id().to_owned(),
                workspace: options.context.workspace.path.clone(),
            })))
        })
    });
    let task_manager: Arc<dyn aionui_ai_agent::IWorkerTaskManager> = Arc::new(WorkerTaskManagerImpl::new(factory));
    let config = aionui_app::AppConfig {
        local: true,
        local_capability: Some(LocalCapabilityVerifier::new(LOCAL_CAPABILITY).unwrap()),
        data_dir: app_data.path().to_path_buf(),
        work_dir: app_data.path().to_path_buf(),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(database, &config)
        .await
        .unwrap()
        .with_worker_task_manager(task_manager);
    let router = aionui_app::create_router(&services).await.unwrap();
    (router, services, app_data)
}

fn local_json_request(method: Method, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(LOCAL_CAPABILITY_HEADER, LOCAL_CAPABILITY)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn project_request(method: Method, uri: &str, body: Value, attestations: &[String]) -> Request<Body> {
    let mut request = local_json_request(method, uri, body);
    for attestation in attestations {
        request.headers_mut().append(
            PROJECT_RUNTIME_ATTESTATION_HEADER,
            HeaderValue::from_str(attestation).unwrap(),
        );
    }
    request
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_project_conversation(app: &axum::Router) -> (String, u64, Option<String>) {
    let response = app
        .clone()
        .oneshot(local_json_request(
            Method::POST,
            "/api/conversations",
            json!({
                "type": "acp",
                "name": "Attested Project",
                "extra": {
                    "backend": "gemini",
                    "project_id": PROJECT_ID,
                    "workspace_root_ref": ROOT_REF
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response_json(response).await;
    (
        body["data"]["id"].as_str().unwrap().to_owned(),
        body["data"]["extra"]["project_binding_revision"].as_u64().unwrap(),
        body["data"]["extra"]["project_binding_receipt_id"]
            .as_str()
            .map(str::to_owned),
    )
}

fn runtime_workspace(
    directory: &tempfile::TempDir,
    project_binding_revision: u64,
    project_binding_receipt_id: Option<String>,
) -> ProjectRuntimeWorkspaceRequest {
    ProjectRuntimeWorkspaceRequest {
        project_id: PROJECT_ID.to_owned(),
        workspace_root_ref: ROOT_REF.to_owned(),
        project_binding_revision,
        project_binding_receipt_id,
        path: std::fs::canonicalize(directory.path())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    }
}

fn ticket(
    conversation_id: &str,
    purpose: ProjectRuntimeAttestationPurpose,
    runtime_workspace: &ProjectRuntimeWorkspaceRequest,
    nonce: u8,
) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut jti = [0_u8; 16];
    jti[15] = nonce;
    sign_project_runtime_attestation(
        LOCAL_CAPABILITY,
        &ProjectRuntimeAttestationClaims {
            v: 1,
            iss: "aionui-main".into(),
            aud: "aioncore-project-runtime".into(),
            sub: conversation_id.to_owned(),
            purpose,
            backend_generation: LocalCapabilityVerifier::new(LOCAL_CAPABILITY)
                .unwrap()
                .backend_generation(),
            seat_id: "seat-owner".into(),
            realm_id: REALM_ID.into(),
            root_id: ROOT_ID.into(),
            project_id: PROJECT_ID.into(),
            workspace_root_ref: ROOT_REF.into(),
            project_binding_revision: runtime_workspace.project_binding_revision,
            project_binding_receipt_id: runtime_workspace.project_binding_receipt_id.clone(),
            canonical_path_sha256: format!("{:x}", Sha256::digest(runtime_workspace.path.as_bytes())),
            root_catalog_revision: 7,
            root_ownership_revision: 11,
            project_catalog_revision: 13,
            root_record_sha256: "a".repeat(64),
            project_record_sha256: "b".repeat(64),
            environment_hint: r#"{"metadata_class":"untrusted_data_not_instructions","project_title":"Attested Project","knowledge_boot_policy":"system_index_first"}"#.into(),
            iat: now,
            nbf: now.saturating_sub(1),
            exp: now.saturating_add(9),
            jti: URL_SAFE_NO_PAD.encode(jti),
        },
    )
    .unwrap()
}

fn send_body(runtime_workspace: &ProjectRuntimeWorkspaceRequest) -> Value {
    json!({
        "content": "Hello from the attested project",
        "runtime_workspace": runtime_workspace,
    })
}

fn warmup_body(runtime_workspace: &ProjectRuntimeWorkspaceRequest) -> Value {
    json!({ "runtime_workspace": runtime_workspace })
}

async fn assert_route_error(response: axum::response::Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let body = response_json(response).await;
    assert_eq!(body["code"], code);
}

#[tokio::test]
async fn signed_send_and_warmup_succeed_without_persisting_ticket_or_project_path() {
    let (app, services, _app_data) = build_local_app().await;
    let runtime_directory = tempfile::tempdir().unwrap();
    let (conversation_id, binding_revision, binding_receipt) = create_project_conversation(&app).await;
    let runtime_workspace = runtime_workspace(&runtime_directory, binding_revision, binding_receipt);
    let mut ws_events = services.event_bus.subscribe();

    let send_ticket = ticket(
        &conversation_id,
        ProjectRuntimeAttestationPurpose::Send,
        &runtime_workspace,
        1,
    );
    let send_response = app
        .clone()
        .oneshot(project_request(
            Method::POST,
            &format!("/api/conversations/{conversation_id}/messages"),
            send_body(&runtime_workspace),
            std::slice::from_ref(&send_ticket),
        ))
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::ACCEPTED);
    let send_response_body = response_json(send_response).await;
    let serialized_response = serde_json::to_string(&send_response_body).unwrap();
    assert!(!serialized_response.contains(&send_ticket));
    assert!(!serialized_response.contains(&runtime_workspace.path));

    let warmup_ticket = ticket(
        &conversation_id,
        ProjectRuntimeAttestationPurpose::Warmup,
        &runtime_workspace,
        2,
    );
    let warmup_response = app
        .clone()
        .oneshot(project_request(
            Method::POST,
            &format!("/api/conversations/{conversation_id}/warmup"),
            warmup_body(&runtime_workspace),
            std::slice::from_ref(&warmup_ticket),
        ))
        .await
        .unwrap();
    assert_eq!(warmup_response.status(), StatusCode::OK);

    let persisted: Vec<(String, String)> = sqlx::query_as(
        "SELECT extra, '' FROM conversations WHERE id = ? UNION ALL SELECT content, type FROM messages WHERE conversation_id = ?",
    )
    .bind(&conversation_id)
    .bind(&conversation_id)
    .fetch_all(services.database.pool())
    .await
    .unwrap();
    let serialized_persistence = serde_json::to_string(&persisted).unwrap();
    for sensitive in [&send_ticket, &warmup_ticket, &runtime_workspace.path] {
        assert!(!serialized_persistence.contains(sensitive));
    }

    let mut serialized_events = Vec::new();
    while let Ok(Ok(event)) = tokio::time::timeout(Duration::from_millis(50), ws_events.recv()).await {
        serialized_events.push(serde_json::to_string(&event).unwrap());
    }
    assert!(
        !serialized_events.is_empty(),
        "send must emit at least one websocket event"
    );
    let websocket_output = serialized_events.join("\n");
    for sensitive in [&send_ticket, &warmup_ticket, &runtime_workspace.path] {
        assert!(!websocket_output.contains(sensitive));
    }

    services.database.close().await;
}

#[tokio::test]
async fn send_route_rejects_duplicate_oversized_spoofed_and_body_only_attestations_without_side_effects() {
    let (app, services, _app_data) = build_local_app().await;
    let runtime_directory = tempfile::tempdir().unwrap();
    let (conversation_id, binding_revision, binding_receipt) = create_project_conversation(&app).await;
    let runtime_workspace = runtime_workspace(&runtime_directory, binding_revision, binding_receipt);
    let endpoint = format!("/api/conversations/{conversation_id}/messages");

    let duplicate_ticket = ticket(
        &conversation_id,
        ProjectRuntimeAttestationPurpose::Send,
        &runtime_workspace,
        3,
    );
    let response = app
        .clone()
        .oneshot(project_request(
            Method::POST,
            &endpoint,
            send_body(&runtime_workspace),
            &[duplicate_ticket.clone(), duplicate_ticket],
        ))
        .await
        .unwrap();
    assert_route_error(response, StatusCode::FORBIDDEN, "PROJECT_RUNTIME_ATTESTATION_INVALID").await;

    let response = app
        .clone()
        .oneshot(project_request(
            Method::POST,
            &endpoint,
            send_body(&runtime_workspace),
            &["a".repeat(4_097)],
        ))
        .await
        .unwrap();
    assert_route_error(response, StatusCode::FORBIDDEN, "PROJECT_RUNTIME_ATTESTATION_INVALID").await;

    let signed = ticket(
        &conversation_id,
        ProjectRuntimeAttestationPurpose::Send,
        &runtime_workspace,
        4,
    );
    let mut segments = signed.split('.');
    let spoofed = format!(
        "{}.{}.{}",
        segments.next().unwrap(),
        segments.next().unwrap(),
        "A".repeat(43)
    );
    let response = app
        .clone()
        .oneshot(project_request(
            Method::POST,
            &endpoint,
            send_body(&runtime_workspace),
            &[spoofed],
        ))
        .await
        .unwrap();
    assert_route_error(response, StatusCode::FORBIDDEN, "PROJECT_RUNTIME_ATTESTATION_INVALID").await;

    let response = app
        .clone()
        .oneshot(local_json_request(
            Method::POST,
            &endpoint,
            send_body(&runtime_workspace),
        ))
        .await
        .unwrap();
    assert_route_error(
        response,
        StatusCode::BAD_REQUEST,
        "PROJECT_RUNTIME_ATTESTATION_REQUIRED",
    )
    .await;

    let message_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = ?")
        .bind(&conversation_id)
        .fetch_one(services.database.pool())
        .await
        .unwrap();
    assert_eq!(message_count, 0);

    services.database.close().await;
}

#[tokio::test]
async fn warmup_route_rejects_body_only_and_send_purpose_tickets() {
    let (app, services, _app_data) = build_local_app().await;
    let runtime_directory = tempfile::tempdir().unwrap();
    let (conversation_id, binding_revision, binding_receipt) = create_project_conversation(&app).await;
    let runtime_workspace = runtime_workspace(&runtime_directory, binding_revision, binding_receipt);
    let endpoint = format!("/api/conversations/{conversation_id}/warmup");

    let response = app
        .clone()
        .oneshot(local_json_request(
            Method::POST,
            &endpoint,
            warmup_body(&runtime_workspace),
        ))
        .await
        .unwrap();
    assert_route_error(
        response,
        StatusCode::BAD_REQUEST,
        "PROJECT_RUNTIME_ATTESTATION_REQUIRED",
    )
    .await;

    let wrong_purpose = ticket(
        &conversation_id,
        ProjectRuntimeAttestationPurpose::Send,
        &runtime_workspace,
        5,
    );
    let response = app
        .oneshot(project_request(
            Method::POST,
            &endpoint,
            warmup_body(&runtime_workspace),
            &[wrong_purpose],
        ))
        .await
        .unwrap();
    assert_route_error(response, StatusCode::CONFLICT, "PROJECT_RUNTIME_ATTESTATION_MISMATCH").await;

    services.database.close().await;
}
