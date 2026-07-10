use sha2::{Digest, Sha256};

const MIN_CAPABILITY_BYTES: usize = 32;
const MAX_CAPABILITY_BYTES: usize = 512;

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
}

impl std::fmt::Debug for LocalCapabilityVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LocalCapabilityVerifier([REDACTED])")
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| difference | (left ^ right))
        == 0
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
}
