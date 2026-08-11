use std::collections::HashSet;
use std::path::Path;

use aionui_ai_agent::types::VerifiedAttachmentGrounding;
use aionui_api_types::{
    ATTACHMENT_GROUNDING_RECEIPT_VERSION, ATTACHMENT_GROUNDING_REQUEST_VERSION, AttachmentGroundingExpectation,
    AttachmentGroundingKind, AttachmentGroundingReceipt, AttachmentGroundingReceiptEntry, AttachmentGroundingRequest,
};
use sha2::{Digest, Sha256};

use crate::ConversationError;

const MAX_GROUNDING_BYTES: u64 = 512 * 1024;
const MAX_TOTAL_GROUNDING_BYTES: u64 = 512 * 1024;
const MAX_GROUNDING_ENTRIES: usize = 12;
const MAX_PDF_SOURCE_BYTES: u64 = 25 * 1024 * 1024;
const MAX_IMAGE_SOURCE_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct VerifiedAttachmentGroundingSet {
    pub receipt: AttachmentGroundingReceipt,
    pub agent_grounding: Vec<VerifiedAttachmentGrounding>,
}

fn grounding_bad_request(reason: &'static str) -> ConversationError {
    ConversationError::BadRequest { reason: reason.into() }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn extension_matches(kind: AttachmentGroundingKind, path: &Path) -> bool {
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
    match kind {
        AttachmentGroundingKind::Pdf => extension.eq_ignore_ascii_case("pdf"),
        AttachmentGroundingKind::Image => ["png", "jpg", "jpeg", "webp", "gif"]
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate)),
    }
}

fn is_visual_source_path(path: &Path) -> bool {
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
    ["pdf", "png", "jpg", "jpeg", "webp", "gif", "bmp", "svg"]
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

fn max_source_bytes(kind: AttachmentGroundingKind) -> u64 {
    match kind {
        AttachmentGroundingKind::Pdf => MAX_PDF_SOURCE_BYTES,
        AttachmentGroundingKind::Image => MAX_IMAGE_SOURCE_BYTES,
    }
}

async fn read_exact_regular_file(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<Vec<u8>, ConversationError> {
    if !path.is_absolute() || !is_sha256(expected_sha256) {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_INVALID"));
    }
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| grounding_bad_request("ATTACHMENT_GROUNDING_UNAVAILABLE"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_MISMATCH"));
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| grounding_bad_request("ATTACHMENT_GROUNDING_UNAVAILABLE"))?;
    if bytes.len() as u64 != expected_bytes || format!("{:x}", Sha256::digest(&bytes)) != expected_sha256 {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_MISMATCH"));
    }
    Ok(bytes)
}

fn validate_file_pair_order(
    files: &[String],
    expectation: &AttachmentGroundingExpectation,
) -> Result<(), ConversationError> {
    let Some(source_index) = files.iter().position(|file| file == &expectation.source_path) else {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_FILES_MISMATCH"));
    };
    if files.get(source_index + 1) != Some(&expectation.grounding_path) {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_FILES_MISMATCH"));
    }
    Ok(())
}

pub(crate) async fn verify_attachment_grounding(
    request: Option<&AttachmentGroundingRequest>,
    files: &[String],
) -> Result<Option<VerifiedAttachmentGroundingSet>, ConversationError> {
    let carries_prepared_visual_pair = files.windows(2).any(|pair| {
        is_visual_source_path(Path::new(&pair[0]))
            && Path::new(&pair[1])
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("md"))
    });
    let Some(request) = request else {
        if carries_prepared_visual_pair {
            return Err(grounding_bad_request("ATTACHMENT_GROUNDING_REQUIRED"));
        }
        return Ok(None);
    };
    if request.version != ATTACHMENT_GROUNDING_REQUEST_VERSION
        || request.entries.is_empty()
        || request.entries.len() > MAX_GROUNDING_ENTRIES
    {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_INVALID"));
    }

    let visual_sources = files
        .iter()
        .filter(|file| is_visual_source_path(Path::new(file)))
        .cloned()
        .collect::<HashSet<_>>();
    let mut seen_sources = HashSet::new();
    let mut seen_groundings = HashSet::new();
    let mut receipt_entries = Vec::with_capacity(request.entries.len());
    let mut agent_grounding = Vec::with_capacity(request.entries.len());
    let mut total_grounding_bytes = 0_u64;

    for expectation in &request.entries {
        if expectation.source_path == expectation.grounding_path
            || !seen_sources.insert(expectation.source_path.clone())
            || !seen_groundings.insert(expectation.grounding_path.clone())
        {
            return Err(grounding_bad_request("ATTACHMENT_GROUNDING_INVALID"));
        }
        validate_file_pair_order(files, expectation)?;
        let source_path = Path::new(&expectation.source_path);
        let grounding_path = Path::new(&expectation.grounding_path);
        if !extension_matches(expectation.kind, source_path)
            || !grounding_path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("md"))
            || expectation.source_bytes == 0
            || expectation.source_bytes > max_source_bytes(expectation.kind)
            || expectation.grounding_bytes == 0
            || expectation.grounding_bytes > MAX_GROUNDING_BYTES
        {
            return Err(grounding_bad_request("ATTACHMENT_GROUNDING_INVALID"));
        }
        total_grounding_bytes = total_grounding_bytes
            .checked_add(expectation.grounding_bytes)
            .filter(|total| *total <= MAX_TOTAL_GROUNDING_BYTES)
            .ok_or_else(|| grounding_bad_request("ATTACHMENT_GROUNDING_INVALID"))?;

        let _source_bytes =
            read_exact_regular_file(source_path, expectation.source_bytes, &expectation.source_sha256).await?;
        let grounding_bytes = read_exact_regular_file(
            grounding_path,
            expectation.grounding_bytes,
            &expectation.grounding_sha256,
        )
        .await?;
        let grounding_text =
            String::from_utf8(grounding_bytes).map_err(|_| grounding_bad_request("ATTACHMENT_GROUNDING_NOT_UTF8"))?;
        if grounding_text.trim().is_empty() {
            return Err(grounding_bad_request("ATTACHMENT_GROUNDING_EMPTY"));
        }

        receipt_entries.push(AttachmentGroundingReceiptEntry {
            kind: expectation.kind,
            source_path: expectation.source_path.clone(),
            source_sha256: expectation.source_sha256.clone(),
            source_bytes: expectation.source_bytes,
            grounding_path: expectation.grounding_path.clone(),
            grounding_sha256: expectation.grounding_sha256.clone(),
            grounding_bytes: expectation.grounding_bytes,
            grounding_embedded: true,
        });
        agent_grounding.push(VerifiedAttachmentGrounding {
            source_path: expectation.source_path.clone(),
            source_sha256: expectation.source_sha256.clone(),
            source_bytes: expectation.source_bytes,
            grounding_path: expectation.grounding_path.clone(),
            grounding_sha256: expectation.grounding_sha256.clone(),
            grounding_bytes: expectation.grounding_bytes,
            grounding_text,
        });
    }

    if seen_sources != visual_sources {
        return Err(grounding_bad_request("ATTACHMENT_GROUNDING_FILES_MISMATCH"));
    }

    Ok(Some(VerifiedAttachmentGroundingSet {
        receipt: AttachmentGroundingReceipt {
            version: ATTACHMENT_GROUNDING_RECEIPT_VERSION.into(),
            status: "verified".into(),
            entries: receipt_entries,
        },
        agent_grounding,
    }))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aionui_api_types::{AttachmentGroundingExpectation, AttachmentGroundingKind, AttachmentGroundingRequest};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{MAX_GROUNDING_BYTES, verify_attachment_grounding};

    fn hash(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[tokio::test]
    async fn verifies_exact_ordered_source_and_sidecar_before_embedding() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("brief.pdf");
        let sidecar = directory.path().join("document.md");
        let source_bytes = b"%PDF-1.4\n%%EOF\n";
        let sidecar_bytes = b"## PDF p. 1\nVerified evidence.\n";
        fs::write(&source, source_bytes).unwrap();
        fs::write(&sidecar, sidecar_bytes).unwrap();
        let source_path = source.to_string_lossy().into_owned();
        let grounding_path = sidecar.to_string_lossy().into_owned();
        let request = AttachmentGroundingRequest {
            version: aionui_api_types::ATTACHMENT_GROUNDING_REQUEST_VERSION.into(),
            entries: vec![AttachmentGroundingExpectation {
                kind: AttachmentGroundingKind::Pdf,
                source_path: source_path.clone(),
                source_sha256: hash(source_bytes),
                source_bytes: source_bytes.len() as u64,
                grounding_path: grounding_path.clone(),
                grounding_sha256: hash(sidecar_bytes),
                grounding_bytes: sidecar_bytes.len() as u64,
            }],
        };

        let verified = verify_attachment_grounding(Some(&request), &[source_path, grounding_path])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified.receipt.status, "verified");
        assert!(verified.receipt.entries[0].grounding_embedded);
        assert_eq!(
            verified.agent_grounding[0].grounding_text,
            String::from_utf8_lossy(sidecar_bytes)
        );
    }

    #[tokio::test]
    async fn rejects_hash_mismatch_without_a_receipt() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("image.png");
        let sidecar = directory.path().join("document.md");
        fs::write(&source, b"image").unwrap();
        fs::write(&sidecar, b"grounding").unwrap();
        let source_path = source.to_string_lossy().into_owned();
        let grounding_path = sidecar.to_string_lossy().into_owned();
        let request = AttachmentGroundingRequest {
            version: aionui_api_types::ATTACHMENT_GROUNDING_REQUEST_VERSION.into(),
            entries: vec![AttachmentGroundingExpectation {
                kind: AttachmentGroundingKind::Image,
                source_path: source_path.clone(),
                source_sha256: "0".repeat(64),
                source_bytes: 5,
                grounding_path: grounding_path.clone(),
                grounding_sha256: hash(b"grounding"),
                grounding_bytes: 9,
            }],
        };
        let error = verify_attachment_grounding(Some(&request), &[source_path, grounding_path])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ATTACHMENT_GROUNDING_MISMATCH"));
    }

    #[tokio::test]
    async fn rejects_sidecars_beyond_the_hermes_resource_ceiling() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("brief.pdf");
        let sidecar = directory.path().join("document.md");
        let source_bytes = b"%PDF";
        let sidecar_bytes = vec![b'x'; MAX_GROUNDING_BYTES as usize + 1];
        fs::write(&source, source_bytes).unwrap();
        fs::write(&sidecar, &sidecar_bytes).unwrap();
        let source_path = source.to_string_lossy().into_owned();
        let grounding_path = sidecar.to_string_lossy().into_owned();
        let request = AttachmentGroundingRequest {
            version: aionui_api_types::ATTACHMENT_GROUNDING_REQUEST_VERSION.into(),
            entries: vec![AttachmentGroundingExpectation {
                kind: AttachmentGroundingKind::Pdf,
                source_path: source_path.clone(),
                source_sha256: hash(source_bytes),
                source_bytes: source_bytes.len() as u64,
                grounding_path: grounding_path.clone(),
                grounding_sha256: hash(&sidecar_bytes),
                grounding_bytes: sidecar_bytes.len() as u64,
            }],
        };
        let error = verify_attachment_grounding(Some(&request), &[source_path, grounding_path])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ATTACHMENT_GROUNDING_INVALID"));
    }

    #[tokio::test]
    async fn rejects_an_uncovered_visual_attachment() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("brief.pdf");
        let uncovered = directory.path().join("uncovered.png");
        let sidecar = directory.path().join("document.md");
        let source_bytes = b"%PDF";
        let sidecar_bytes = b"verified";
        fs::write(&source, source_bytes).unwrap();
        fs::write(&uncovered, b"image").unwrap();
        fs::write(&sidecar, sidecar_bytes).unwrap();
        let source_path = source.to_string_lossy().into_owned();
        let uncovered_path = uncovered.to_string_lossy().into_owned();
        let grounding_path = sidecar.to_string_lossy().into_owned();
        let request = AttachmentGroundingRequest {
            version: aionui_api_types::ATTACHMENT_GROUNDING_REQUEST_VERSION.into(),
            entries: vec![AttachmentGroundingExpectation {
                kind: AttachmentGroundingKind::Pdf,
                source_path: source_path.clone(),
                source_sha256: hash(source_bytes),
                source_bytes: source_bytes.len() as u64,
                grounding_path: grounding_path.clone(),
                grounding_sha256: hash(sidecar_bytes),
                grounding_bytes: sidecar_bytes.len() as u64,
            }],
        };
        let error = verify_attachment_grounding(Some(&request), &[source_path, grounding_path, uncovered_path])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("ATTACHMENT_GROUNDING_FILES_MISMATCH"));
    }

    #[tokio::test]
    async fn rejects_a_prepared_visual_pair_without_a_grounding_request() {
        let error = verify_attachment_grounding(
            None,
            &[
                "/tmp/report.pdf".into(),
                "/tmp/document-intelligence/document.md".into(),
            ],
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("ATTACHMENT_GROUNDING_REQUIRED"));
    }
}
