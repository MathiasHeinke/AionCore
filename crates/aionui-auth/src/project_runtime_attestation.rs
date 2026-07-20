use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aionui_api_types::{MAX_SAFE_PROJECT_BINDING_REVISION, ProjectRuntimeWorkspaceRequest};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "test-support"))]
use crate::LocalCapabilityError;
use crate::LocalCapabilityVerifier;
use crate::local_capability::{constant_time_eq, encode_lower_hex, hmac_sha256};

pub const DEFAULT_PROJECT_RUNTIME_NONCE_CAPACITY: usize = 4_096;
const MAX_ATTESTATION_BYTES: usize = 4_096;
const MAX_TTL_SECONDS: i64 = 10;
const CLOCK_SKEW_SECONDS: i64 = 2;
const EXPECTED_ISSUER: &str = "aionui-main";
const EXPECTED_AUDIENCE: &str = "aioncore-project-runtime";
const EXPECTED_TYPE: &str = "AIONUI-PROJECT-RUNTIME";
const HEADER_KEYS: &[&str] = &["alg", "typ", "v"];
const CLAIM_KEYS: &[&str] = &[
    "v",
    "iss",
    "aud",
    "sub",
    "purpose",
    "backend_generation",
    "seat_id",
    "realm_id",
    "root_id",
    "project_id",
    "workspace_root_ref",
    "project_binding_revision",
    "project_binding_receipt_id",
    "environment_hint",
    "canonical_path_sha256",
    "root_catalog_revision",
    "root_ownership_revision",
    "project_catalog_revision",
    "root_record_sha256",
    "project_record_sha256",
    "iat",
    "nbf",
    "exp",
    "jti",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProjectRuntimeAttestationPurpose {
    Send,
    Warmup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectRuntimeAttestationClaims {
    pub v: u8,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub purpose: ProjectRuntimeAttestationPurpose,
    pub backend_generation: String,
    pub seat_id: String,
    pub realm_id: String,
    pub root_id: String,
    pub project_id: String,
    pub workspace_root_ref: String,
    pub project_binding_revision: u64,
    pub project_binding_receipt_id: Option<String>,
    pub canonical_path_sha256: String,
    pub root_catalog_revision: u64,
    pub root_ownership_revision: u64,
    pub project_catalog_revision: u64,
    pub root_record_sha256: String,
    pub project_record_sha256: String,
    pub environment_hint: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRuntimeJwsHeader {
    alg: String,
    typ: String,
    v: u8,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedProjectRuntimeAttestation {
    claims: ProjectRuntimeAttestationClaims,
    runtime_fingerprint: String,
    environment_hint_fingerprint: String,
}

impl std::fmt::Debug for VerifiedProjectRuntimeAttestation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedProjectRuntimeAttestation")
            .field("runtime_fingerprint", &self.runtime_fingerprint)
            .field("environment_hint", &"[REDACTED]")
            .field("environment_hint_fingerprint", &self.environment_hint_fingerprint)
            .finish_non_exhaustive()
    }
}

impl VerifiedProjectRuntimeAttestation {
    #[cfg(any(test, feature = "test-support"))]
    pub fn claims(&self) -> &ProjectRuntimeAttestationClaims {
        &self.claims
    }

    pub fn backend_generation(&self) -> &str {
        &self.claims.backend_generation
    }

    pub fn root_catalog_revision(&self) -> u64 {
        self.claims.root_catalog_revision
    }

    pub fn root_ownership_revision(&self) -> u64 {
        self.claims.root_ownership_revision
    }

    pub fn project_catalog_revision(&self) -> u64 {
        self.claims.project_catalog_revision
    }

    pub fn runtime_fingerprint(&self) -> &str {
        &self.runtime_fingerprint
    }

    pub fn environment_hint_fingerprint(&self) -> &str {
        &self.environment_hint_fingerprint
    }

    pub fn environment_hint(&self) -> &str {
        &self.claims.environment_hint
    }

    pub fn project_binding_revision(&self) -> u64 {
        self.claims.project_binding_revision
    }

    pub fn project_binding_receipt_id(&self) -> Option<&str> {
        self.claims.project_binding_receipt_id.as_deref()
    }

    pub fn matches_runtime_workspace(&self, runtime_workspace: &ProjectRuntimeWorkspaceRequest) -> bool {
        self.claims.project_id == runtime_workspace.project_id
            && self.claims.workspace_root_ref == runtime_workspace.workspace_root_ref
            && self.claims.project_binding_revision == runtime_workspace.project_binding_revision
            && self.claims.project_binding_receipt_id == runtime_workspace.project_binding_receipt_id
            && canonical_path_hash(runtime_workspace)
                .is_ok_and(|path_hash| path_hash == self.claims.canonical_path_sha256)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ProjectRuntimeAttestationError {
    #[error("project runtime attestation is required")]
    Required,
    #[error("project runtime attestation is invalid")]
    Invalid,
    #[error("project runtime attestation does not match the request")]
    Mismatch,
    #[error("project runtime attestation was already consumed")]
    Replayed,
    #[error("project runtime attestation nonce cache is full")]
    CacheFull,
}

#[derive(Debug, thiserror::Error)]
#[cfg(any(test, feature = "test-support"))]
pub enum ProjectRuntimeAttestationSigningError {
    #[error(transparent)]
    Capability(#[from] LocalCapabilityError),
    #[error("failed to serialize project runtime attestation")]
    Serialization(#[from] serde_json::Error),
}

/// Reference encoder for the byte-exact Main-to-Core compact JWS contract.
/// Test fixtures use this to prove Main/Core byte compatibility without
/// exposing an issuer API in production AionCore builds.
#[cfg(any(test, feature = "test-support"))]
pub fn sign_project_runtime_attestation(
    capability: &str,
    claims: &ProjectRuntimeAttestationClaims,
) -> Result<String, ProjectRuntimeAttestationSigningError> {
    let local_capability = LocalCapabilityVerifier::new(capability)?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"AIONUI-PROJECT-RUNTIME","v":1}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header}.{payload}");
    let signature = hmac_sha256(&local_capability.project_attestation_key(), signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

pub struct ProjectRuntimeAttestationVerifier {
    key: [u8; 32],
    backend_generation: String,
    consumed_nonces: DashMap<String, i64>,
    consumed_count: AtomicUsize,
    nonce_capacity: usize,
}

pub struct ProjectRuntimeVerificationExpectation<'a> {
    conversation_id: &'a str,
    purpose: ProjectRuntimeAttestationPurpose,
    project_id: &'a str,
    workspace_root_ref: &'a str,
    project_binding_revision: u64,
    project_binding_receipt_id: Option<&'a str>,
    runtime_workspace: &'a ProjectRuntimeWorkspaceRequest,
}

impl<'a> ProjectRuntimeVerificationExpectation<'a> {
    pub fn new(
        conversation_id: &'a str,
        purpose: ProjectRuntimeAttestationPurpose,
        project_id: &'a str,
        workspace_root_ref: &'a str,
        project_binding_revision: u64,
        project_binding_receipt_id: Option<&'a str>,
        runtime_workspace: &'a ProjectRuntimeWorkspaceRequest,
    ) -> Self {
        Self {
            conversation_id,
            purpose,
            project_id,
            workspace_root_ref,
            project_binding_revision,
            project_binding_receipt_id,
            runtime_workspace,
        }
    }
}

impl std::fmt::Debug for ProjectRuntimeAttestationVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectRuntimeAttestationVerifier")
            .field("key", &"[REDACTED]")
            .field("backend_generation", &self.backend_generation)
            .field("consumed_count", &self.consumed_count.load(Ordering::Relaxed))
            .field("nonce_capacity", &self.nonce_capacity)
            .finish()
    }
}

impl ProjectRuntimeAttestationVerifier {
    pub fn new(local_capability: &LocalCapabilityVerifier, nonce_capacity: usize) -> Self {
        Self {
            key: local_capability.project_attestation_key(),
            backend_generation: local_capability.backend_generation(),
            consumed_nonces: DashMap::new(),
            consumed_count: AtomicUsize::new(0),
            nonce_capacity,
        }
    }

    pub fn backend_generation(&self) -> &str {
        &self.backend_generation
    }

    pub fn verify_and_consume(
        &self,
        compact_jws: Option<&str>,
        expectation: &ProjectRuntimeVerificationExpectation<'_>,
    ) -> Result<VerifiedProjectRuntimeAttestation, ProjectRuntimeAttestationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProjectRuntimeAttestationError::Invalid)?
            .as_secs() as i64;
        self.verify_and_consume_at(compact_jws, expectation, now)
    }

    fn verify_and_consume_at(
        &self,
        compact_jws: Option<&str>,
        expectation: &ProjectRuntimeVerificationExpectation<'_>,
        now_seconds: i64,
    ) -> Result<VerifiedProjectRuntimeAttestation, ProjectRuntimeAttestationError> {
        let compact_jws = compact_jws.ok_or(ProjectRuntimeAttestationError::Required)?;
        if compact_jws.is_empty()
            || compact_jws.len() > MAX_ATTESTATION_BYTES
            || compact_jws
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'=')
        {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }
        let mut segments = compact_jws.split('.');
        let (Some(header_segment), Some(payload_segment), Some(signature_segment), None) =
            (segments.next(), segments.next(), segments.next(), segments.next())
        else {
            return Err(ProjectRuntimeAttestationError::Invalid);
        };
        if header_segment.is_empty() || payload_segment.is_empty() || signature_segment.is_empty() {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }

        let header_bytes = decode_segment(header_segment)?;
        require_exact_object_keys(&header_bytes, HEADER_KEYS)?;
        let header: ProjectRuntimeJwsHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| ProjectRuntimeAttestationError::Invalid)?;
        if header.alg != "HS256" || header.typ != EXPECTED_TYPE || header.v != 1 {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }
        let signature_bytes = decode_segment(signature_segment)?;
        let signature: [u8; 32] = signature_bytes
            .try_into()
            .map_err(|_| ProjectRuntimeAttestationError::Invalid)?;
        let signing_input = format!("{header_segment}.{payload_segment}");
        let expected_signature = hmac_sha256(&self.key, signing_input.as_bytes());
        if !constant_time_eq(&expected_signature, &signature) {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }

        let claims_bytes = decode_segment(payload_segment)?;
        require_exact_object_keys(&claims_bytes, CLAIM_KEYS)?;
        let claims: ProjectRuntimeAttestationClaims =
            serde_json::from_slice(&claims_bytes).map_err(|_| ProjectRuntimeAttestationError::Invalid)?;
        self.validate_claims(&claims, expectation, now_seconds)?;
        self.consume_nonce(&claims.jti, claims.exp, now_seconds)?;

        let runtime_fingerprint = runtime_fingerprint(&claims);
        let environment_hint_fingerprint = encode_lower_hex(&Sha256::digest(claims.environment_hint.as_bytes()).into());
        Ok(VerifiedProjectRuntimeAttestation {
            claims,
            runtime_fingerprint,
            environment_hint_fingerprint,
        })
    }

    fn validate_claims(
        &self,
        claims: &ProjectRuntimeAttestationClaims,
        expectation: &ProjectRuntimeVerificationExpectation<'_>,
        now_seconds: i64,
    ) -> Result<(), ProjectRuntimeAttestationError> {
        if claims.v != 1
            || claims.iss != EXPECTED_ISSUER
            || claims.aud != EXPECTED_AUDIENCE
            || claims.sub != expectation.conversation_id
            || claims.purpose != expectation.purpose
            || claims.backend_generation != self.backend_generation
        {
            return Err(ProjectRuntimeAttestationError::Mismatch);
        }
        if claims.project_id != expectation.runtime_workspace.project_id
            || claims.workspace_root_ref != expectation.runtime_workspace.workspace_root_ref
            || claims.project_binding_revision != expectation.runtime_workspace.project_binding_revision
            || claims.project_binding_receipt_id != expectation.runtime_workspace.project_binding_receipt_id
            || claims.project_id != expectation.project_id
            || claims.workspace_root_ref != expectation.workspace_root_ref
            || claims.project_binding_revision != expectation.project_binding_revision
            || claims.project_binding_receipt_id.as_deref() != expectation.project_binding_receipt_id
            || claims.workspace_root_ref != format!("root:{}", claims.root_id)
        {
            return Err(ProjectRuntimeAttestationError::Mismatch);
        }
        if !valid_seat_id(&claims.seat_id)
            || !canonical_uuid(&claims.realm_id)
            || !canonical_uuid(&claims.root_id)
            || !canonical_uuid(&claims.project_id)
            || !valid_conversation_id(&claims.sub)
            || !valid_jti(&claims.jti)
            || !is_lower_hex_64(&claims.canonical_path_sha256)
            || !is_lower_hex_64(&claims.root_record_sha256)
            || !is_lower_hex_64(&claims.project_record_sha256)
            || claims.project_binding_revision > MAX_SAFE_PROJECT_BINDING_REVISION
            || claims.root_catalog_revision > MAX_SAFE_PROJECT_BINDING_REVISION
            || claims.root_ownership_revision > MAX_SAFE_PROJECT_BINDING_REVISION
            || claims.project_catalog_revision > MAX_SAFE_PROJECT_BINDING_REVISION
            || claims
                .project_binding_receipt_id
                .as_deref()
                .is_some_and(|value| !canonical_receipt_uuid(value))
            || !valid_environment_hint(&claims.environment_hint)
        {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }
        let max_safe_timestamp = MAX_SAFE_PROJECT_BINDING_REVISION as i64;
        if claims.iat < 0
            || claims.nbf < 0
            || claims.exp < 0
            || claims.iat > max_safe_timestamp
            || claims.nbf > max_safe_timestamp
            || claims.exp > max_safe_timestamp
            || claims.exp <= claims.iat
            || claims.nbf > claims.iat
            || claims.iat.saturating_sub(claims.nbf) > CLOCK_SKEW_SECONDS
            || claims.exp.saturating_sub(claims.iat) > MAX_TTL_SECONDS
            || claims.iat > now_seconds.saturating_add(CLOCK_SKEW_SECONDS)
            || claims.nbf > now_seconds.saturating_add(CLOCK_SKEW_SECONDS)
            || claims.exp < now_seconds.saturating_sub(CLOCK_SKEW_SECONDS)
        {
            return Err(ProjectRuntimeAttestationError::Invalid);
        }

        let path_hash = canonical_path_hash(expectation.runtime_workspace)?;
        if claims.canonical_path_sha256 != path_hash {
            return Err(ProjectRuntimeAttestationError::Mismatch);
        }
        Ok(())
    }

    fn consume_nonce(
        &self,
        jti: &str,
        expires_at: i64,
        now_seconds: i64,
    ) -> Result<(), ProjectRuntimeAttestationError> {
        use dashmap::mapref::entry::Entry;

        self.cleanup_expired_nonces(now_seconds);
        match self.consumed_nonces.entry(jti.to_owned()) {
            Entry::Occupied(_) => Err(ProjectRuntimeAttestationError::Replayed),
            Entry::Vacant(entry) => {
                let reserved = self
                    .consumed_count
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < self.nonce_capacity).then_some(count + 1)
                    })
                    .is_ok();
                if !reserved {
                    return Err(ProjectRuntimeAttestationError::CacheFull);
                }
                entry.insert(expires_at);
                Ok(())
            }
        }
    }

    fn cleanup_expired_nonces(&self, now_seconds: i64) {
        const MAX_CLEANUP_PER_VERIFY: usize = 64;
        let expired: Vec<(String, i64)> = self
            .consumed_nonces
            .iter()
            .filter(|entry| *entry.value() < now_seconds.saturating_sub(CLOCK_SKEW_SECONDS))
            .take(MAX_CLEANUP_PER_VERIFY)
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        for (jti, expiry) in expired {
            if self
                .consumed_nonces
                .remove_if(&jti, |_, stored_expiry| *stored_expiry == expiry)
                .is_some()
            {
                self.consumed_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

fn canonical_path_hash(
    runtime_workspace: &ProjectRuntimeWorkspaceRequest,
) -> Result<String, ProjectRuntimeAttestationError> {
    let path = std::path::Path::new(&runtime_workspace.path);
    if runtime_workspace.path.is_empty()
        || runtime_workspace.path.trim() != runtime_workspace.path
        || !path.is_absolute()
    {
        return Err(ProjectRuntimeAttestationError::Mismatch);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ProjectRuntimeAttestationError::Mismatch)?;
    if !canonical.is_dir() || canonical != path || canonical.to_str() != Some(runtime_workspace.path.as_str()) {
        return Err(ProjectRuntimeAttestationError::Mismatch);
    }
    Ok(encode_lower_hex(
        &Sha256::digest(runtime_workspace.path.as_bytes()).into(),
    ))
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, ProjectRuntimeAttestationError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ProjectRuntimeAttestationError::Invalid)
}

fn require_exact_object_keys(bytes: &[u8], expected: &[&str]) -> Result<(), ProjectRuntimeAttestationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProjectRuntimeAttestationError::Invalid)?;
    let object = value.as_object().ok_or(ProjectRuntimeAttestationError::Invalid)?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ProjectRuntimeAttestationError::Invalid);
    }
    Ok(())
}

fn valid_conversation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn valid_seat_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        !parsed.is_nil()
            && (1..=5).contains(&parsed.get_version_num())
            && parsed.get_variant() == uuid::Variant::RFC4122
            && parsed.hyphenated().to_string() == value
    })
}

fn canonical_receipt_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        !parsed.is_nil()
            && parsed.get_version_num() == 4
            && parsed.get_variant() == uuid::Variant::RFC4122
            && parsed.hyphenated().to_string() == value
    })
}

fn valid_environment_hint(value: &str) -> bool {
    static FORBIDDEN_UNICODE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]").expect("valid Unicode policy"));
    !value.is_empty()
        && value.len() <= 600
        && value.trim() == value
        && !FORBIDDEN_UNICODE.is_match(value)
        && !value.contains(['/', '\\'])
}

fn valid_jti(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 16 && URL_SAFE_NO_PAD.encode(decoded) == value)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn runtime_fingerprint(claims: &ProjectRuntimeAttestationClaims) -> String {
    let mut hasher = Sha256::new();
    for field in [
        "aionui-project-runtime-fingerprint/v1",
        claims.backend_generation.as_str(),
        claims.seat_id.as_str(),
        claims.realm_id.as_str(),
        claims.root_id.as_str(),
        claims.project_id.as_str(),
        claims.workspace_root_ref.as_str(),
        claims.canonical_path_sha256.as_str(),
        claims.root_record_sha256.as_str(),
        claims.project_record_sha256.as_str(),
    ] {
        hasher.update(field.as_bytes());
    }
    encode_lower_hex(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    const CAPABILITY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const PROJECT_ID: &str = "018f0c00-0000-4000-8000-000000000001";
    const ROOT_ID: &str = "018f0c00-0000-4000-8000-000000000004";
    const ROOT_REF: &str = "root:018f0c00-0000-4000-8000-000000000004";

    fn fixture() -> (
        tempfile::TempDir,
        ProjectRuntimeWorkspaceRequest,
        ProjectRuntimeAttestationClaims,
    ) {
        let directory = tempfile::TempDir::new().unwrap();
        let path = std::fs::canonicalize(directory.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let request = ProjectRuntimeWorkspaceRequest {
            project_id: PROJECT_ID.into(),
            workspace_root_ref: ROOT_REF.into(),
            project_binding_revision: 1,
            project_binding_receipt_id: Some("00000000-0000-4000-8000-000000000006".into()),
            path: path.clone(),
        };
        let claims = ProjectRuntimeAttestationClaims {
            v: 1,
            iss: EXPECTED_ISSUER.into(),
            aud: EXPECTED_AUDIENCE.into(),
            sub: "conv-test".into(),
            purpose: ProjectRuntimeAttestationPurpose::Send,
            backend_generation: LocalCapabilityVerifier::new(CAPABILITY).unwrap().backend_generation(),
            seat_id: "seat-owner".into(),
            realm_id: "018f0c00-0000-4000-8000-000000000003".into(),
            root_id: ROOT_ID.into(),
            project_id: PROJECT_ID.into(),
            workspace_root_ref: ROOT_REF.into(),
            project_binding_revision: 1,
            project_binding_receipt_id: Some("00000000-0000-4000-8000-000000000006".into()),
            environment_hint: "private founder workspace".into(),
            canonical_path_sha256: encode_lower_hex(&Sha256::digest(path.as_bytes()).into()),
            root_catalog_revision: 7,
            root_ownership_revision: 11,
            project_catalog_revision: 13,
            root_record_sha256: "a".repeat(64),
            project_record_sha256: "b".repeat(64),
            iat: 1_000,
            nbf: 999,
            exp: 1_010,
            jti: URL_SAFE_NO_PAD.encode([0_u8; 16]),
        };
        (directory, request, claims)
    }

    fn verifier(capacity: usize) -> ProjectRuntimeAttestationVerifier {
        ProjectRuntimeAttestationVerifier::new(&LocalCapabilityVerifier::new(CAPABILITY).unwrap(), capacity)
    }

    fn verify_at(
        verifier: &ProjectRuntimeAttestationVerifier,
        compact_jws: Option<&str>,
        conversation_id: &str,
        purpose: ProjectRuntimeAttestationPurpose,
        runtime_workspace: &ProjectRuntimeWorkspaceRequest,
        now_seconds: i64,
    ) -> Result<VerifiedProjectRuntimeAttestation, ProjectRuntimeAttestationError> {
        let expectation = ProjectRuntimeVerificationExpectation {
            conversation_id,
            purpose,
            project_id: PROJECT_ID,
            workspace_root_ref: ROOT_REF,
            project_binding_revision: runtime_workspace.project_binding_revision,
            project_binding_receipt_id: runtime_workspace.project_binding_receipt_id.as_deref(),
            runtime_workspace,
        };
        verifier.verify_and_consume_at(compact_jws, &expectation, now_seconds)
    }

    fn sign_claims(claims: &ProjectRuntimeAttestationClaims) -> String {
        sign_project_runtime_attestation(CAPABILITY, claims).unwrap()
    }

    fn sign_payload(payload: &[u8]) -> String {
        sign_with_header(br#"{"alg":"HS256","typ":"AIONUI-PROJECT-RUNTIME","v":1}"#, payload)
    }

    fn sign_with_header(header: &[u8], payload: &[u8]) -> String {
        let header = URL_SAFE_NO_PAD.encode(header);
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{header}.{payload}");
        let local = LocalCapabilityVerifier::new(CAPABILITY).unwrap();
        let signature = hmac_sha256(&local.project_attestation_key(), signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    #[test]
    fn canonical_path_hash_matches_cross_runtime_vector() {
        assert_eq!(
            encode_lower_hex(&Sha256::digest(b"/tmp/eve/projects/alpha").into()),
            "12c873abf3d097a6b91451d729842c537bc3853a5302531bf28ab10d953eb37b"
        );
    }

    #[test]
    fn compact_jws_matches_cross_language_fixture_segments() {
        let claims = ProjectRuntimeAttestationClaims {
            v: 1,
            iss: "aionui-main".into(),
            aud: "aioncore-project-runtime".into(),
            sub: "00000000-0000-4000-8000-000000000001".into(),
            purpose: ProjectRuntimeAttestationPurpose::Send,
            backend_generation: "bg1:b102a2cddf8391261ddd77b1d9df01cc8a03e2e4c43cffc7070e1e0d739fabac".into(),
            seat_id: "00000000-0000-4000-8000-000000000002".into(),
            realm_id: "00000000-0000-4000-8000-000000000003".into(),
            root_id: "00000000-0000-4000-8000-000000000004".into(),
            project_id: "00000000-0000-4000-8000-000000000005".into(),
            workspace_root_ref: "root:00000000-0000-4000-8000-000000000004".into(),
            project_binding_revision: 13,
            project_binding_receipt_id: Some("77777777-7777-4777-8777-777777777777".into()),
            canonical_path_sha256: "12c873abf3d097a6b91451d729842c537bc3853a5302531bf28ab10d953eb37b".into(),
            root_catalog_revision: 7,
            root_ownership_revision: 5,
            project_catalog_revision: 11,
            root_record_sha256: "907d81f964b0a594332b19c291a7e7785398ccc650e95d91a693438ed417d5ca".into(),
            project_record_sha256: "b9e622e9a3b0cc04ee061a42f135126b860881a70e28e1eb9f5cf8b28db6ec0c".into(),
            environment_hint: "{\"metadata_class\":\"untrusted_data_not_instructions\",\"project_id\":\"00000000-0000-4000-8000-000000000005\",\"workspace_root_ref\":\"root:00000000-0000-4000-8000-000000000004\",\"realm_id\":\"00000000-0000-4000-8000-000000000003\",\"project_title\":\"Synthetic Project\",\"knowledge_boot_policy\":\"system_index_first\"}".into(),
            iat: 2_000_000_000,
            nbf: 1_999_999_999,
            exp: 2_000_000_010,
            jti: "AAECAwQFBgcICQoLDA0ODw".into(),
        };
        let compact = sign_project_runtime_attestation(CAPABILITY, &claims).unwrap();
        let segments: Vec<&str> = compact.split('.').collect();
        const EXPECTED_CLAIMS_SEGMENT: &str = "eyJ2IjoxLCJpc3MiOiJhaW9udWktbWFpbiIsImF1ZCI6ImFpb25jb3JlLXByb2plY3QtcnVudGltZSIsInN1YiI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwMSIsInB1cnBvc2UiOiJzZW5kIiwiYmFja2VuZF9nZW5lcmF0aW9uIjoiYmcxOmIxMDJhMmNkZGY4MzkxMjYxZGRkNzdiMWQ5ZGYwMWNjOGEwM2UyZTRjNDNjZmZjNzA3MGUxZTBkNzM5ZmFiYWMiLCJzZWF0X2lkIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAyIiwicmVhbG1faWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDMiLCJyb290X2lkIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDA0IiwicHJvamVjdF9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwNSIsIndvcmtzcGFjZV9yb290X3JlZiI6InJvb3Q6MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDA0IiwicHJvamVjdF9iaW5kaW5nX3JldmlzaW9uIjoxMywicHJvamVjdF9iaW5kaW5nX3JlY2VpcHRfaWQiOiI3Nzc3Nzc3Ny03Nzc3LTQ3NzctODc3Ny03Nzc3Nzc3Nzc3NzciLCJjYW5vbmljYWxfcGF0aF9zaGEyNTYiOiIxMmM4NzNhYmYzZDA5N2E2YjkxNDUxZDcyOTg0MmM1MzdiYzM4NTNhNTMwMjUzMWJmMjhhYjEwZDk1M2ViMzdiIiwicm9vdF9jYXRhbG9nX3JldmlzaW9uIjo3LCJyb290X293bmVyc2hpcF9yZXZpc2lvbiI6NSwicHJvamVjdF9jYXRhbG9nX3JldmlzaW9uIjoxMSwicm9vdF9yZWNvcmRfc2hhMjU2IjoiOTA3ZDgxZjk2NGIwYTU5NDMzMmIxOWMyOTFhN2U3Nzg1Mzk4Y2NjNjUwZTk1ZDkxYTY5MzQzOGVkNDE3ZDVjYSIsInByb2plY3RfcmVjb3JkX3NoYTI1NiI6ImI5ZTYyMmU5YTNiMGNjMDRlZTA2MWE0MmYxMzUxMjZiODYwODgxYTcwZTI4ZTFlYjlmNWNmOGIyOGRiNmVjMGMiLCJlbnZpcm9ubWVudF9oaW50Ijoie1wibWV0YWRhdGFfY2xhc3NcIjpcInVudHJ1c3RlZF9kYXRhX25vdF9pbnN0cnVjdGlvbnNcIixcInByb2plY3RfaWRcIjpcIjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwNVwiLFwid29ya3NwYWNlX3Jvb3RfcmVmXCI6XCJyb290OjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwNFwiLFwicmVhbG1faWRcIjpcIjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDAwM1wiLFwicHJvamVjdF90aXRsZVwiOlwiU3ludGhldGljIFByb2plY3RcIixcImtub3dsZWRnZV9ib290X3BvbGljeVwiOlwic3lzdGVtX2luZGV4X2ZpcnN0XCJ9IiwiaWF0IjoyMDAwMDAwMDAwLCJuYmYiOjE5OTk5OTk5OTksImV4cCI6MjAwMDAwMDAxMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyJ9";
        assert_eq!(
            segments[0],
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkFJT05VSS1QUk9KRUNULVJVTlRJTUUiLCJ2IjoxfQ"
        );
        let decoded_claims = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
        assert_eq!(
            decoded_claims.as_slice(),
            br#"{"v":1,"iss":"aionui-main","aud":"aioncore-project-runtime","sub":"00000000-0000-4000-8000-000000000001","purpose":"send","backend_generation":"bg1:b102a2cddf8391261ddd77b1d9df01cc8a03e2e4c43cffc7070e1e0d739fabac","seat_id":"00000000-0000-4000-8000-000000000002","realm_id":"00000000-0000-4000-8000-000000000003","root_id":"00000000-0000-4000-8000-000000000004","project_id":"00000000-0000-4000-8000-000000000005","workspace_root_ref":"root:00000000-0000-4000-8000-000000000004","project_binding_revision":13,"project_binding_receipt_id":"77777777-7777-4777-8777-777777777777","canonical_path_sha256":"12c873abf3d097a6b91451d729842c537bc3853a5302531bf28ab10d953eb37b","root_catalog_revision":7,"root_ownership_revision":5,"project_catalog_revision":11,"root_record_sha256":"907d81f964b0a594332b19c291a7e7785398ccc650e95d91a693438ed417d5ca","project_record_sha256":"b9e622e9a3b0cc04ee061a42f135126b860881a70e28e1eb9f5cf8b28db6ec0c","environment_hint":"{\"metadata_class\":\"untrusted_data_not_instructions\",\"project_id\":\"00000000-0000-4000-8000-000000000005\",\"workspace_root_ref\":\"root:00000000-0000-4000-8000-000000000004\",\"realm_id\":\"00000000-0000-4000-8000-000000000003\",\"project_title\":\"Synthetic Project\",\"knowledge_boot_policy\":\"system_index_first\"}","iat":2000000000,"nbf":1999999999,"exp":2000000010,"jti":"AAECAwQFBgcICQoLDA0ODw"}"#
        );
        assert_eq!(segments[2], "O1H2wfgYZZnonOc-1XsjJUApacOrVNCnwh4JyB22c4c");
        assert_eq!(segments[1], EXPECTED_CLAIMS_SEGMENT);
        assert_eq!(
            compact,
            format!(
                "{}.{}.{}",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkFJT05VSS1QUk9KRUNULVJVTlRJTUUiLCJ2IjoxfQ",
                EXPECTED_CLAIMS_SEGMENT,
                "O1H2wfgYZZnonOc-1XsjJUApacOrVNCnwh4JyB22c4c"
            )
        );
    }

    #[test]
    fn verifies_exact_contract_and_consumes_nonce_once() {
        let (_directory, request, claims) = fixture();
        let compact = sign_claims(&claims);
        let verifier = verifier(8);

        let verified = verify_at(
            &verifier,
            Some(&compact),
            "conv-test",
            ProjectRuntimeAttestationPurpose::Send,
            &request,
            1_005,
        )
        .unwrap();
        assert_eq!(verified.claims, claims);
        assert_eq!(verified.runtime_fingerprint.len(), 64);
        assert_eq!(
            verified.environment_hint_fingerprint,
            "39bd76acfd56fa31600986b85f240e874378e527d4622829cbd5724d99b51abc"
        );
        assert_eq!(
            verify_at(
                &verifier,
                Some(&compact),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Replayed)
        );
    }

    #[test]
    fn runtime_fingerprint_excludes_ticket_time_and_purpose() {
        let (_directory, request, claims) = fixture();
        let first_verifier = verifier(8);
        let first = verify_at(
            &first_verifier,
            Some(&sign_claims(&claims)),
            "conv-test",
            ProjectRuntimeAttestationPurpose::Send,
            &request,
            1_005,
        )
        .unwrap();
        let mut rotated = claims;
        rotated.purpose = ProjectRuntimeAttestationPurpose::Warmup;
        rotated.iat = 2_000;
        rotated.nbf = 2_000;
        rotated.exp = 2_010;
        rotated.jti = URL_SAFE_NO_PAD.encode([1_u8; 16]);
        let second_verifier = verifier(8);
        let second = verify_at(
            &second_verifier,
            Some(&sign_claims(&rotated)),
            "conv-test",
            ProjectRuntimeAttestationPurpose::Warmup,
            &request,
            2_005,
        )
        .unwrap();
        assert_eq!(first.runtime_fingerprint, second.runtime_fingerprint);
    }

    #[test]
    fn rejects_wrong_algorithm_unknown_claim_and_signature_tampering() {
        let (_directory, request, claims) = fixture();
        let verifier = verifier(8);

        let mut unknown = serde_json::to_value(&claims).unwrap();
        unknown["unknown"] = serde_json::json!(true);
        let unknown = sign_payload(&serde_json::to_vec(&unknown).unwrap());
        assert_eq!(
            verify_at(
                &verifier,
                Some(&unknown),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Invalid)
        );

        let valid = sign_claims(&claims);
        let mut tampered = valid.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            verify_at(
                &verifier,
                Some(std::str::from_utf8(&tampered).unwrap()),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Invalid)
        );

        let bad_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"AIONUI-PROJECT-RUNTIME"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let unsigned = format!("{bad_header}.{payload}.{}", URL_SAFE_NO_PAD.encode([0_u8; 32]));
        assert_eq!(
            verify_at(
                &verifier,
                Some(&unsigned),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Invalid)
        );

        for strict_header in [
            br#"{"alg":"HS256","typ":"AIONUI-PROJECT-RUNTIME"}"#.as_slice(),
            br#"{"alg":"HS256","typ":"AIONUI-PROJECT-RUNTIME","v":1,"kid":"unexpected"}"#.as_slice(),
        ] {
            let compact = sign_with_header(strict_header, &serde_json::to_vec(&claims).unwrap());
            assert_eq!(
                verify_at(
                    &verifier,
                    Some(&compact),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid)
            );
        }
    }

    #[test]
    fn receipt_claim_key_is_required_even_when_value_is_null() {
        let (_directory, mut request, mut claims) = fixture();
        request.project_binding_receipt_id = None;
        claims.project_binding_receipt_id = None;

        let explicit_null = sign_claims(&claims);
        assert!(
            verify_at(
                &verifier(8),
                Some(&explicit_null),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            )
            .is_ok()
        );

        let mut missing = serde_json::to_value(&claims).unwrap();
        missing.as_object_mut().unwrap().remove("project_binding_receipt_id");
        let missing = sign_payload(&serde_json::to_vec(&missing).unwrap());
        assert_eq!(
            verify_at(
                &verifier(8),
                Some(&missing),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Invalid)
        );
    }

    #[test]
    fn receipt_claim_accepts_only_canonical_lowercase_uuid_v4() {
        for receipt in [
            "00000000-0000-1000-8000-000000000006",
            "00000000-0000-5000-8000-000000000006",
            "00000000-0000-7000-8000-000000000006",
            "00000000-0000-4000-0000-000000000006",
            "00000000-0000-4000-f000-000000000006",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            let (_directory, mut request, mut claims) = fixture();
            request.project_binding_receipt_id = Some(receipt.to_owned());
            claims.project_binding_receipt_id = Some(receipt.to_owned());
            assert_eq!(
                verify_at(
                    &verifier(8),
                    Some(&sign_claims(&claims)),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid),
                "receipt {receipt} must be rejected"
            );
        }
    }

    #[test]
    fn seat_and_opaque_identity_grammars_are_exact() {
        let (_directory, request, claims) = fixture();
        for seat_id in ["seat.with-dot", "seat:with-colon", &"a".repeat(65)] {
            let mut invalid = claims.clone();
            invalid.seat_id = seat_id.to_owned();
            assert_eq!(
                verify_at(
                    &verifier(8),
                    Some(&sign_claims(&invalid)),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid)
            );
        }

        for realm_id in [
            "00000000-0000-0000-0000-000000000000",
            "018f0c00-0000-7000-8000-000000000003",
            "018f0c00-0000-4000-0000-000000000003",
            "018f0c00-0000-4000-f000-000000000003",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            let mut invalid = claims.clone();
            invalid.realm_id = realm_id.to_owned();
            assert_eq!(
                verify_at(
                    &verifier(8),
                    Some(&sign_claims(&invalid)),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid)
            );
        }
    }

    #[test]
    fn conversation_id_grammar_matches_main_runtime_contract() {
        let (_directory, request, claims) = fixture();
        for conversation_id in ["-conversation", "_conversation", ".conversation", ":conversation"] {
            let mut invalid = claims.clone();
            invalid.sub = conversation_id.to_owned();
            assert_eq!(
                verify_at(
                    &verifier(8),
                    Some(&sign_claims(&invalid)),
                    conversation_id,
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid),
                "leading punctuation must be rejected for {conversation_id}"
            );
        }

        for conversation_id in ["a", "A._:-09", &format!("a{}", "-_.:z9".repeat(42))] {
            let mut valid = claims.clone();
            valid.sub = conversation_id.to_owned();
            assert!(
                verify_at(
                    &verifier(8),
                    Some(&sign_claims(&valid)),
                    conversation_id,
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                )
                .is_ok(),
                "valid Main-runtime conversation id was rejected: {conversation_id}"
            );
        }
    }

    #[test]
    fn numeric_claims_are_integer_nonnegative_and_json_safe() {
        let (_directory, request, claims) = fixture();
        for (field, value) in [
            ("project_binding_revision", serde_json::json!(-1)),
            ("root_catalog_revision", serde_json::json!(1.5)),
            ("root_ownership_revision", serde_json::json!(9_007_199_254_740_992_u64)),
            ("project_catalog_revision", serde_json::json!(9_007_199_254_740_992_u64)),
            ("iat", serde_json::json!(-1)),
            ("nbf", serde_json::json!(9_007_199_254_740_992_i64)),
            ("exp", serde_json::json!(9_007_199_254_740_992_i64)),
        ] {
            let mut invalid = serde_json::to_value(&claims).unwrap();
            invalid[field] = value;
            let compact = sign_payload(&serde_json::to_vec(&invalid).unwrap());
            assert_eq!(
                verify_at(
                    &verifier(8),
                    Some(&compact),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                ),
                Err(ProjectRuntimeAttestationError::Invalid),
                "numeric field {field} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_body_conversation_purpose_generation_and_time_window() {
        let (_directory, request, claims) = fixture();
        let compact = sign_claims(&claims);
        for (conversation, purpose, request, now, expected) in [
            (
                "conv-other",
                ProjectRuntimeAttestationPurpose::Send,
                request.clone(),
                1_005,
                ProjectRuntimeAttestationError::Mismatch,
            ),
            (
                "conv-test",
                ProjectRuntimeAttestationPurpose::Warmup,
                request.clone(),
                1_005,
                ProjectRuntimeAttestationError::Mismatch,
            ),
            (
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                ProjectRuntimeWorkspaceRequest {
                    project_id: "018f0c00-0000-7000-8000-000000000002".into(),
                    ..request.clone()
                },
                1_005,
                ProjectRuntimeAttestationError::Mismatch,
            ),
            (
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                request.clone(),
                1_020,
                ProjectRuntimeAttestationError::Invalid,
            ),
        ] {
            let verifier = verifier(8);
            assert_eq!(
                verify_at(&verifier, Some(&compact), conversation, purpose, &request, now),
                Err(expected)
            );
        }

        let mut wrong_generation = claims;
        wrong_generation.backend_generation = format!("bg1:{}", "0".repeat(64));
        let verifier = verifier(8);
        assert_eq!(
            verify_at(
                &verifier,
                Some(&sign_claims(&wrong_generation)),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::Mismatch)
        );
    }

    #[tokio::test]
    async fn concurrent_nonce_consume_has_one_winner_and_cache_never_evicts() {
        let (_directory, request, claims) = fixture();
        let compact = Arc::new(sign_claims(&claims));
        let request = Arc::new(request);
        let verifier = Arc::new(verifier(1));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let compact = Arc::clone(&compact);
            let request = Arc::clone(&request);
            let verifier = Arc::clone(&verifier);
            let barrier = Arc::clone(&barrier);
            joins.push(tokio::spawn(async move {
                barrier.wait().await;
                verify_at(
                    &verifier,
                    Some(&compact),
                    "conv-test",
                    ProjectRuntimeAttestationPurpose::Send,
                    &request,
                    1_005,
                )
            }));
        }
        barrier.wait().await;
        let mut results = Vec::new();
        for join in joins {
            results.push(join.await.unwrap());
        }
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(ProjectRuntimeAttestationError::Replayed))
                .count(),
            1
        );

        let mut second = claims;
        second.jti = URL_SAFE_NO_PAD.encode([1_u8; 16]);
        assert_eq!(
            verify_at(
                &verifier,
                Some(&sign_claims(&second)),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_005,
            ),
            Err(ProjectRuntimeAttestationError::CacheFull)
        );
    }

    #[test]
    fn expired_nonce_cleanup_releases_capacity_without_evicting_live_entries() {
        let (_directory, request, first) = fixture();
        let verifier = verifier(1);
        verify_at(
            &verifier,
            Some(&sign_claims(&first)),
            "conv-test",
            ProjectRuntimeAttestationPurpose::Send,
            &request,
            1_005,
        )
        .unwrap();

        let mut second = first;
        second.iat = 1_013;
        second.nbf = 1_013;
        second.exp = 1_023;
        second.jti = URL_SAFE_NO_PAD.encode([1_u8; 16]);
        verify_at(
            &verifier,
            Some(&sign_claims(&second)),
            "conv-test",
            ProjectRuntimeAttestationPurpose::Send,
            &request,
            1_013,
        )
        .unwrap();

        let mut third = second;
        third.jti = URL_SAFE_NO_PAD.encode([2_u8; 16]);
        assert_eq!(
            verify_at(
                &verifier,
                Some(&sign_claims(&third)),
                "conv-test",
                ProjectRuntimeAttestationPurpose::Send,
                &request,
                1_013,
            ),
            Err(ProjectRuntimeAttestationError::CacheFull)
        );
    }
}
