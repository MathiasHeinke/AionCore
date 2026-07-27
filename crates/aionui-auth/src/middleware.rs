#![allow(clippy::disallowed_types)]

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use aionui_common::ApiError;
use aionui_db::IUserRepository;

use crate::JwtService;
use crate::LocalCapabilityVerifier;
use crate::extract::{extract_local_capability_from_headers, extract_token_from_headers};

/// Authenticated user injected into request extensions by the auth middleware.
///
/// Route handlers extract this from `request.extensions()` to identify
/// the current user.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User ID from the database.
    pub id: String,
    /// Username.
    pub username: String,
    /// Server-authenticated provenance for this principal. Route handlers may
    /// use this to distinguish a per-launch local capability from a normal
    /// remote JWT; request JSON cannot set or upgrade it.
    pub auth_provenance: AuthenticationProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationProvenance {
    Jwt,
    LocalCapability,
}

/// Shared state for the authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
    pub user_repo: Arc<dyn IUserRepository>,
    /// When `true`, require the per-launch capability and inject the embedded user.
    pub local: bool,
    pub local_capability: Option<LocalCapabilityVerifier>,
}

/// Authentication middleware that verifies JWT tokens and injects `CurrentUser`.
///
/// Flow:
/// 1. Extract bearer token from `Authorization` header or `aionui-session` cookie
/// 2. Verify JWT signature, expiration, and blacklist
/// 3. Look up user in the database to ensure they still exist
/// 4. Insert [`CurrentUser`] into request extensions
///
/// Returns HTTP 401 for authentication failures.
///
/// Use with `axum::middleware::from_fn_with_state`.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Local mode is reachable over loopback and must not be an authentication
    // bypass. User JWTs and cookies are separate from this process boundary.
    if state.local {
        let verifier = state
            .local_capability
            .as_ref()
            .ok_or_else(|| ApiError::Unauthorized("Local capability is not configured".into()))?;
        let token = extract_local_capability_from_headers(request.headers())
            .ok_or_else(|| ApiError::Unauthorized("Local capability is required".into()))?;
        if !verifier.verify(&token) {
            return Err(ApiError::Unauthorized("Invalid local capability".into()));
        }
        request.extensions_mut().insert(CurrentUser {
            id: "system_default_user".to_string(),
            username: "system_default_user".to_string(),
            auth_provenance: AuthenticationProvenance::LocalCapability,
        });
        return Ok(next.run(request).await);
    }

    let token = extract_token_from_headers(request.headers())
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".into()))?;

    let payload = state.jwt_service.verify(&token).map_err(|e| {
        tracing::debug!("Token verification failed: {e}");
        ApiError::Unauthorized("Invalid or expired token".into())
    })?;

    let user = state
        .user_repo
        .find_by_id(&payload.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth middleware user lookup failed");
            ApiError::Internal("Authentication service unavailable".into())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username,
        auth_provenance: AuthenticationProvenance::Jwt,
    });

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    async fn echo_user(request: Request<Body>) -> String {
        let user = request.extensions().get::<CurrentUser>().unwrap();
        format!("{}:{}:{:?}", user.id, user.username, user.auth_provenance)
    }

    #[tokio::test]
    async fn local_auth_requires_matching_bearer_and_injects_default_user() {
        let capability = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let db = aionui_db::init_database_memory().await.unwrap();
        let state = AuthState {
            jwt_service: Arc::new(JwtService::new("test-secret".into())),
            user_repo: Arc::new(aionui_db::SqliteUserRepository::new(db.pool().clone())),
            local: true,
            local_capability: Some(LocalCapabilityVerifier::new(capability).unwrap()),
        };
        let app = Router::new()
            .route("/test", get(echo_user))
            .route_layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        let missing = app
            .clone()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header(crate::LOCAL_CAPABILITY_HEADER, capability)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "system_default_user:system_default_user:LocalCapability"
        );
    }
}
