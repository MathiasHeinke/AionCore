//! E2E coverage for the authenticated, restart-safe Hermes completion receipt projection.

mod common;

use aionui_app::{AppConfig, AppServices, create_router};
use aionui_db::RecordRejectedAsyncCompletionReceiptParams;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, get_request, get_with_token, json_with_token, setup_and_login};

async fn create_conversation(app: &axum::Router, token: &str, csrf: &str) -> String {
    let response = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/conversations",
            json!({ "type": "acp", "name": "Durable work", "extra": {} }),
            token,
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    body_json(response).await["data"]["id"].as_str().unwrap().to_owned()
}

async fn insert_receipt(
    services: &AppServices,
    conversation_id: &str,
    completion_id: &str,
    state: &str,
    outcome: &str,
    code: Option<&str>,
    timestamp: i64,
) {
    sqlx::query(
        "INSERT INTO command_eve_async_completion_receipts \
         (completion_id, conversation_id, acp_session_id, payload_sha256, state, owner_instance_id, \
          turn_id, attempt_count, last_error_code, created_at, updated_at, completed_at, \
          last_ack_status, last_ack_code, last_ack_at) \
         VALUES (?, ?, 'session-1', 'payload', ?, NULL, ?, 2, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(completion_id)
    .bind(conversation_id)
    .bind(state)
    .bind(format!("turn-{completion_id}"))
    .bind(code)
    .bind(timestamp - 10)
    .bind(timestamp)
    .bind((state == "completed").then_some(timestamp))
    .bind(outcome)
    .bind(code)
    .bind(timestamp)
    .execute(services.database.pool())
    .await
    .unwrap();
}

fn receipt_by_id<'a>(payload: &'a Value, id: &str) -> &'a Value {
    payload["data"]["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| receipt["completion_id"] == id)
        .unwrap()
}

#[tokio::test]
async fn receipt_outcomes_are_distinct_and_conversation_owned() {
    let (mut app, services) = common::build_app().await;
    let (owner_token, owner_csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let conversation_id = create_conversation(&app, &owner_token, &owner_csrf).await;

    insert_receipt(
        &services,
        &conversation_id,
        "accepted",
        "completed",
        "accepted",
        None,
        2_000,
    )
    .await;
    insert_receipt(
        &services,
        &conversation_id,
        "already",
        "completed",
        "already_applied",
        None,
        3_000,
    )
    .await;
    insert_receipt(
        &services,
        &conversation_id,
        "busy",
        "pending",
        "retryable",
        Some("conversation_busy"),
        4_000,
    )
    .await;
    assert!(
        services
            .async_completion_receipt_repo
            .record_rejected(&RecordRejectedAsyncCompletionReceiptParams {
                completion_id: "rejected",
                conversation_id: &conversation_id,
                bound_acp_session_id: "session-1",
                requested_acp_session_id: "session-foreign",
                payload_sha256: "rejected-payload",
                code: "session_mismatch",
            })
            .await
            .unwrap()
    );
    insert_receipt(
        &services,
        &conversation_id,
        "unknown",
        "unknown",
        "explicit_unknown",
        Some("outcome_unknown_turn_timeout"),
        6_000,
    )
    .await;

    let unauthenticated = app
        .clone()
        .oneshot(get_request(&format!(
            "/api/conversations/{conversation_id}/async-completion-receipts"
        )))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(get_with_token(
            &format!("/api/conversations/{conversation_id}/async-completion-receipts"),
            &owner_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["data"]["version"], "command-eve-async-completion-receipts/v1");
    assert_eq!(receipt_by_id(&payload, "accepted")["last_outcome"], "accepted");
    assert_eq!(receipt_by_id(&payload, "already")["last_outcome"], "already_applied");
    assert_eq!(receipt_by_id(&payload, "busy")["last_outcome"], "retryable");
    assert_eq!(receipt_by_id(&payload, "rejected")["state"], "rejected");
    assert_eq!(receipt_by_id(&payload, "rejected")["last_outcome"], "rejected");
    assert!(receipt_by_id(&payload, "rejected")["turn_id"].is_null());
    assert_eq!(receipt_by_id(&payload, "unknown")["state"], "explicit_unknown");
    assert_eq!(receipt_by_id(&payload, "unknown")["last_outcome"], "explicit_unknown");

    let (other_token, _other_csrf) = setup_and_login(&mut app, &services, "other", "StrongP@ss2").await;
    let foreign = app
        .oneshot(get_with_token(
            &format!("/api/conversations/{conversation_id}/async-completion-receipts"),
            &other_token,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn receipt_projection_survives_database_and_app_restart() {
    let temp = tempfile::TempDir::new().unwrap();
    let config = AppConfig {
        data_dir: temp.path().join("data"),
        work_dir: temp.path().join("work"),
        ..Default::default()
    };
    let database_path = config.database_path();
    let database = aionui_db::init_database(&database_path).await.unwrap();
    let services = AppServices::from_config(database, &config).await.unwrap();
    let mut app = create_router(&services).await.unwrap();
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let conversation_id = create_conversation(&app, &token, &csrf).await;
    insert_receipt(
        &services,
        &conversation_id,
        "restart-unknown",
        "unknown",
        "explicit_unknown",
        Some("owner_changed"),
        9_000,
    )
    .await;

    drop(app);
    services.database.close().await;
    drop(services);

    let reopened_database = aionui_db::init_database(&database_path).await.unwrap();
    let reopened_services = AppServices::from_config(reopened_database, &config).await.unwrap();
    let mut reopened_app = create_router(&reopened_services).await.unwrap();
    let (reopened_token, _) = setup_and_login(&mut reopened_app, &reopened_services, "admin", "StrongP@ss1").await;
    let response = reopened_app
        .oneshot(get_with_token(
            &format!("/api/conversations/{conversation_id}/async-completion-receipts"),
            &reopened_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(receipt_by_id(&payload, "restart-unknown")["state"], "explicit_unknown");
    assert_eq!(payload["data"]["reconstructed_from"], "persistent_receipts");

    reopened_services.database.close().await;
}
