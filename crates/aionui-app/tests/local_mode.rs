use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

const LOCAL_CAPABILITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn local_request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(aionui_auth::LOCAL_CAPABILITY_HEADER, LOCAL_CAPABILITY)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn test_local_mode_requires_per_launch_capability() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let config = aionui_app::AppConfig {
        local: true,
        local_capability: Some(aionui_auth::LocalCapabilityVerifier::new(LOCAL_CAPABILITY).unwrap()),
        ..Default::default()
    };
    let services = aionui_app::AppServices::from_config(db, &config).await.unwrap();

    let ws_state = aionui_app::build_ws_state(&services);
    let mut ws_headers = axum::http::HeaderMap::new();
    ws_headers.insert(
        axum::http::HeaderName::from_static(aionui_auth::LOCAL_CAPABILITY_HEADER),
        LOCAL_CAPABILITY.parse().unwrap(),
    );
    let ws_token = (ws_state.token_extractor)(&ws_headers).expect("websocket capability");
    assert!((ws_state.token_validator)(&ws_token));
    assert!(!(ws_state.token_validator)("invalid-capability"));

    let router = aionui_app::create_router(&services).await.expect("build router");

    // Health check should work
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Local APIs fail closed without the per-launch capability.
    let response = router
        .clone()
        .oneshot(Request::builder().uri("/api/settings").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(local_request(Method::GET, "/api/settings"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Local-only credential administration is protected by the same gate.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/internal/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .clone()
        .oneshot(local_request(Method::GET, "/api/auth/internal/users"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Browser origins are exact; arbitrary pages cannot drive the loopback API.
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("origin", "https://attacker.example")
                .header(aionui_auth::LOCAL_CAPABILITY_HEADER, LOCAL_CAPABILITY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    services.database.close().await;
}

#[tokio::test]
async fn test_non_local_mode_requires_auth() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let services = aionui_app::AppServices::from_config(db, &aionui_app::AppConfig::default())
        .await
        .unwrap();

    let router = aionui_app::create_router(&services).await.expect("build router");

    let response = router
        .oneshot(Request::builder().uri("/api/settings").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "UNAUTHORIZED");

    services.database.close().await;
}
