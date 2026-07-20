use sha2::{Digest, Sha256};

const MIN_CAPABILITY_BYTES: usize = 32;
const MAX_CAPABILITY_BYTES: usize = 512;
const PROJECT_ATTESTATION_KEY_LABEL: &[u8] = b"aionui-project-runtime-attestation/v1";
const BACKEND_GENERATION_LABEL: &[u8] = b"aionui-backend-generation/v1";

/// Error returned when a local embedded capability is too weak or malformed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LocalCapabilityError {
    #[error("local capability must contain between 32 and 512 visible ASCII bytes")]
    InvalidFormat,
}

/// Constant-time verifier for the per-launch embedded-server capability.
///
/// Only a SHA-256 digest is retained after bootstrap. The raw capability stays
/// in the desktop process and its owner-only file, never in router state.
#[derive(Clone)]
pub struct LocalCapabilityVerifier {
    digest: [u8; 32],
}

impl LocalCapabilityVerifier {
    pub fn new(capability: &str) -> Result<Self, LocalCapabilityError> {
        let bytes = capability.as_bytes();
        if !(MIN_CAPABILITY_BYTES..=MAX_CAPABILITY_BYTES).contains(&bytes.len())
            || !bytes.iter().all(u8::is_ascii_graphic)
        {
            return Err(LocalCapabilityError::InvalidFormat);
        }

        Ok(Self {
            digest: Sha256::digest(bytes).into(),
        })
    }

    pub fn verify(&self, candidate: &str) -> bool {
        let candidate_digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        constant_time_eq(&self.digest, &candidate_digest)
    }

    /// Verify a lowercase-hex HMAC-SHA256 signature made with the derived
    /// per-launch capability key. The raw capability is never needed after
    /// bootstrap.
    #[cfg(any(test, feature = "test-support"))]
    pub fn verify_attestation(&self, payload: &str, signature: &str) -> bool {
        let Some(candidate) = decode_lower_hex_32(signature) else {
            return false;
        };
        let expected = hmac_sha256(&self.project_attestation_key(), payload.as_bytes());
        constant_time_eq(&expected, &candidate)
    }

    pub(crate) fn project_attestation_key(&self) -> [u8; 32] {
        hmac_sha256(&self.digest, PROJECT_ATTESTATION_KEY_LABEL)
    }

    pub fn backend_generation(&self) -> String {
        format!(
            "bg1:{}",
            encode_lower_hex(&hmac_sha256(&self.digest, BACKEND_GENERATION_LABEL))
        )
    }
}

/// Sign a Main-owned attestation payload with a key derived from the
/// per-launch local capability. This function exists so independently owned
/// launchers can test byte-for-byte compatibility with Core's verifier.
#[cfg(any(test, feature = "test-support"))]
pub fn sign_local_capability_attestation(capability: &str, payload: &str) -> Result<String, LocalCapabilityError> {
    let verifier = LocalCapabilityVerifier::new(capability)?;
    Ok(encode_lower_hex(&hmac_sha256(
        &verifier.project_attestation_key(),
        payload.as_bytes(),
    )))
}

impl std::fmt::Debug for LocalCapabilityVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalCapabilityVerifier([REDACTED])")
    }
}

pub(crate) fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub(crate) fn hmac_sha256(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(payload);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

pub(crate) fn encode_lower_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(any(test, feature = "test-support"))]
fn decode_lower_hex_32(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

#[cfg(any(test, feature = "test-support"))]
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn verifier_accepts_matching_capability_only() {
        let verifier = LocalCapabilityVerifier::new(TOKEN).unwrap();

        assert!(verifier.verify(TOKEN));
        assert!(!verifier.verify("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn verifier_rejects_short_or_whitespace_capabilities() {
        assert_eq!(
            LocalCapabilityVerifier::new("too-short").unwrap_err(),
            LocalCapabilityError::InvalidFormat
        );
        assert_eq!(
            LocalCapabilityVerifier::new("0123456789abcdef0123456789abcde\n").unwrap_err(),
            LocalCapabilityError::InvalidFormat
        );
    }

    #[test]
    fn debug_output_never_contains_digest_or_capability() {
        let verifier = LocalCapabilityVerifier::new(TOKEN).unwrap();
        let rendered = format!("{verifier:?}");

        assert_eq!(rendered, "LocalCapabilityVerifier([REDACTED])");
        assert!(!rendered.contains(TOKEN));
    }

    #[test]
    fn main_and_core_share_attestation_contract_without_retaining_raw_capability() {
        let payload = "eve-project-root-attestation-v1|4:user|";
        let signature = sign_local_capability_attestation(TOKEN, payload).unwrap();
        let verifier = LocalCapabilityVerifier::new(TOKEN).unwrap();

        assert_eq!(signature.len(), 64);
        assert!(
            signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(verifier.verify_attestation(payload, &signature));
        assert!(!verifier.verify_attestation("eve-project-root-attestation-v1|5:other|", &signature));

        let mut tampered = signature.into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        assert!(!verifier.verify_attestation(payload, std::str::from_utf8(&tampered).unwrap()));
    }

    #[test]
    fn attestation_rejects_malformed_signatures() {
        let verifier = LocalCapabilityVerifier::new(TOKEN).unwrap();
        assert!(!verifier.verify_attestation("payload", "not-hex"));
        assert!(!verifier.verify_attestation("payload", &"a".repeat(62)));
        assert!(!verifier.verify_attestation("payload", &"A".repeat(64)));
    }

    #[test]
    fn project_key_and_backend_generation_match_cross_runtime_vector() {
        let verifier = LocalCapabilityVerifier::new(TOKEN).unwrap();
        assert_eq!(
            encode_lower_hex(&verifier.project_attestation_key()),
            "f9982e4a5366e80fa7e80c2533fc9bd9d4626eb30d16e7d55f3985c60a3e2eaf"
        );
        assert_eq!(
            verifier.backend_generation(),
            "bg1:b102a2cddf8391261ddd77b1d9df01cc8a03e2e4c43cffc7070e1e0d739fabac"
        );
    }
}
