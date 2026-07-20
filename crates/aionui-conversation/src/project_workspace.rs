//! Portable project identity and transient runtime workspace validation.
//!
//! AionUi main owns seat/realm/root resolution. This module only proves that
//! the request tuple matches the canonical conversation tuple and that the
//! resolved local directory is safe to inject for the current runtime.

use std::path::Path;

use aionui_ai_agent::{AgentError, AgentStreamEvent};
use aionui_api_types::{AgentStreamErrorData, MAX_SAFE_PROJECT_BINDING_REVISION};
use aionui_api_types::{ProjectBindingExpectation, ProjectRuntimeWorkspaceRequest};
use aionui_db::{ConversationProjectBindingExpectation, models::ConversationRow};
use uuid::Uuid;

use crate::ConversationError;

const PROJECT_BINDING_INCOMPLETE: &str = "PROJECT_BINDING_INCOMPLETE";
const PROJECT_BINDING_INVALID: &str = "PROJECT_BINDING_INVALID";
pub(crate) const PROJECT_BINDING_PATH_FORBIDDEN: &str = "PROJECT_BINDING_PATH_FORBIDDEN";
const PROJECT_BINDING_UPDATE_REQUIRES_PAIR: &str = "PROJECT_BINDING_UPDATE_REQUIRES_PAIR";
const PROJECT_BINDING_REVISION_FORBIDDEN: &str = "PROJECT_BINDING_REVISION_FORBIDDEN";
const PROJECT_BINDING_REVISION_EXHAUSTED: &str = "PROJECT_BINDING_REVISION_EXHAUSTED";
const PROJECT_BINDING_RECEIPT_FORBIDDEN: &str = "PROJECT_BINDING_RECEIPT_FORBIDDEN";
const PROJECT_BINDING_OPERATION_REQUIRED: &str = "PROJECT_BINDING_OPERATION_REQUIRED";
pub(crate) const PROJECT_BINDING_EXPECTATION_REQUIRED: &str = "PROJECT_BINDING_EXPECTATION_REQUIRED";
const PROJECT_BINDING_EXPECTATION_INVALID: &str = "PROJECT_BINDING_EXPECTATION_INVALID";
const PROJECT_BINDING_EXPECTATION_UNEXPECTED: &str = "PROJECT_BINDING_EXPECTATION_UNEXPECTED";
pub(crate) const PROJECT_BINDING_INTERNAL_MUTATION_FORBIDDEN: &str = "PROJECT_BINDING_INTERNAL_MUTATION_FORBIDDEN";
pub(crate) const PROJECT_RUNTIME_BINDING_REQUIRED: &str = "PROJECT_RUNTIME_BINDING_REQUIRED";
pub(crate) const PROJECT_RUNTIME_BINDING_UNEXPECTED: &str = "PROJECT_RUNTIME_BINDING_UNEXPECTED";
pub(crate) const PROJECT_RUNTIME_BINDING_MISMATCH: &str = "PROJECT_RUNTIME_BINDING_MISMATCH";
const PROJECT_RUNTIME_PATH_NOT_ABSOLUTE: &str = "PROJECT_RUNTIME_PATH_NOT_ABSOLUTE";
const PROJECT_RUNTIME_PATH_NOT_CANONICAL: &str = "PROJECT_RUNTIME_PATH_NOT_CANONICAL";
const PROJECT_RUNTIME_PATH_UNAVAILABLE: &str = "PROJECT_RUNTIME_PATH_UNAVAILABLE";
const PROJECT_RUNTIME_REDACTED: &str = "[project workspace redacted]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectConversationBinding {
    pub(crate) project_id: String,
    pub(crate) workspace_root_ref: String,
    pub(crate) project_binding_revision: u64,
    pub(crate) project_binding_receipt_id: Option<String>,
}

pub(crate) fn project_bad_request(reason: &'static str) -> ConversationError {
    ConversationError::BadRequest { reason: reason.into() }
}

fn valid_workspace_root_ref(value: &str) -> bool {
    let Some(opaque_id) = value.strip_prefix("root:") else {
        return false;
    };
    valid_opaque_uuid(opaque_id)
}

fn valid_opaque_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| {
        !parsed.is_nil()
            && (1..=5).contains(&parsed.get_version_num())
            && parsed.get_variant() == uuid::Variant::RFC4122
            && parsed.hyphenated().to_string() == value
    })
}

fn valid_project_binding_operation_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| {
        !parsed.is_nil()
            && parsed.get_version_num() == 4
            && parsed.get_variant() == uuid::Variant::RFC4122
            && parsed.hyphenated().to_string() == value
    })
}

fn parse_project_binding_receipt(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<String>, ConversationError> {
    match obj.get("project_binding_receipt_id") {
        Some(serde_json::Value::String(value)) if valid_project_binding_operation_uuid(value) => {
            Ok(Some(value.clone()))
        }
        Some(serde_json::Value::Null) | None => Ok(None),
        Some(_) => Err(project_bad_request(PROJECT_BINDING_INVALID)),
    }
}

pub(crate) fn parse_project_binding(
    extra: &serde_json::Value,
) -> Result<Option<ProjectConversationBinding>, ConversationError> {
    let Some(obj) = extra.as_object() else {
        return Ok(None);
    };
    let project_binding_revision = match obj.get("project_binding_revision") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| project_bad_request(PROJECT_BINDING_INVALID))?,
        None => 0,
    };
    if project_binding_revision > MAX_SAFE_PROJECT_BINDING_REVISION {
        return Err(project_bad_request(PROJECT_BINDING_INVALID));
    }
    let project_binding_receipt_id = parse_project_binding_receipt(obj)?;
    let project_id = obj.get("project_id");
    let workspace_root_ref = obj.get("workspace_root_ref");

    let (Some(project_id), Some(workspace_root_ref)) = (project_id, workspace_root_ref) else {
        if project_id.is_none() && workspace_root_ref.is_none() {
            return Ok(None);
        }
        return Err(project_bad_request(PROJECT_BINDING_INCOMPLETE));
    };
    let (Some(project_id), Some(workspace_root_ref)) = (project_id.as_str(), workspace_root_ref.as_str()) else {
        return Err(project_bad_request(PROJECT_BINDING_INVALID));
    };
    if !valid_opaque_uuid(project_id) || !valid_workspace_root_ref(workspace_root_ref) {
        return Err(project_bad_request(PROJECT_BINDING_INVALID));
    }
    if obj.contains_key("workspace") {
        return Err(project_bad_request(PROJECT_BINDING_PATH_FORBIDDEN));
    }

    Ok(Some(ProjectConversationBinding {
        project_id: project_id.to_owned(),
        workspace_root_ref: workspace_root_ref.to_owned(),
        project_binding_revision,
        project_binding_receipt_id,
    }))
}

pub(crate) fn project_binding_revision(extra: &serde_json::Value) -> Result<u64, ConversationError> {
    let Some(obj) = extra.as_object() else {
        return Ok(0);
    };
    match obj.get("project_binding_revision") {
        Some(value) => value
            .as_u64()
            .filter(|revision| *revision <= MAX_SAFE_PROJECT_BINDING_REVISION)
            .ok_or_else(|| project_bad_request(PROJECT_BINDING_INVALID)),
        None => Ok(0),
    }
}

pub(crate) fn project_binding_receipt_id(extra: &serde_json::Value) -> Result<Option<String>, ConversationError> {
    let Some(obj) = extra.as_object() else {
        return Ok(None);
    };
    parse_project_binding_receipt(obj)
}

pub(crate) fn parse_project_binding_from_row(
    row: &ConversationRow,
) -> Result<Option<ProjectConversationBinding>, ConversationError> {
    let extra: serde_json::Value = serde_json::from_str(&row.extra)
        .map_err(|error| ConversationError::internal(format!("Invalid extra JSON: {error}")))?;
    parse_project_binding(&extra)
}

pub(crate) fn normalize_project_create_extra(
    extra: &mut serde_json::Value,
) -> Result<Option<ProjectConversationBinding>, ConversationError> {
    if let Some(obj) = extra.as_object_mut() {
        if obj.contains_key("project_binding_revision") {
            return Err(project_bad_request(PROJECT_BINDING_REVISION_FORBIDDEN));
        }
        if obj.contains_key("project_binding_receipt_id") {
            return Err(project_bad_request(PROJECT_BINDING_RECEIPT_FORBIDDEN));
        }
        for key in ["project_id", "workspace_root_ref"] {
            if obj.get(key).is_some_and(serde_json::Value::is_null) {
                obj.remove(key);
            }
        }
    }
    let binding = parse_project_binding(extra)?;
    if binding.is_some() {
        let Some(obj) = extra.as_object_mut() else {
            return Err(project_bad_request(PROJECT_BINDING_INVALID));
        };
        obj.insert("project_binding_revision".to_owned(), serde_json::Value::from(1_u64));
        obj.insert(
            "project_binding_receipt_id".to_owned(),
            serde_json::Value::String(Uuid::new_v4().hyphenated().to_string()),
        );
        return parse_project_binding(extra);
    }
    Ok(None)
}

fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(base_obj), Some(patch_obj)) = (base.as_object_mut(), patch.as_object()) {
        for (key, value) in patch_obj {
            base_obj.insert(key.clone(), value.clone());
        }
    }
}

pub(crate) fn merge_and_validate_project_update(
    existing_extra: &serde_json::Value,
    patch: &serde_json::Value,
    project_binding_operation_id: Option<&str>,
) -> Result<(serde_json::Value, bool), ConversationError> {
    let existing_binding = parse_project_binding(existing_extra)?;
    let existing_revision = project_binding_revision(existing_extra)?;
    let Some(patch_obj) = patch.as_object() else {
        return Ok((existing_extra.clone(), false));
    };
    if patch_obj.contains_key("project_binding_revision") {
        return Err(project_bad_request(PROJECT_BINDING_REVISION_FORBIDDEN));
    }
    if patch_obj.contains_key("project_binding_receipt_id") {
        return Err(project_bad_request(PROJECT_BINDING_RECEIPT_FORBIDDEN));
    }
    let project_touched = patch_obj.contains_key("project_id") || patch_obj.contains_key("workspace_root_ref");
    if project_touched && !(patch_obj.contains_key("project_id") && patch_obj.contains_key("workspace_root_ref")) {
        return Err(project_bad_request(PROJECT_BINDING_UPDATE_REQUIRES_PAIR));
    }
    let operation_id = match (project_touched, project_binding_operation_id) {
        (true, Some(value)) if valid_project_binding_operation_uuid(value) => Some(value),
        (true, _) => return Err(project_bad_request(PROJECT_BINDING_OPERATION_REQUIRED)),
        (false, None) => None,
        (false, Some(_)) => return Err(project_bad_request(PROJECT_BINDING_EXPECTATION_UNEXPECTED)),
    };
    if existing_binding.is_some() && patch_obj.contains_key("workspace") && !project_touched {
        return Err(project_bad_request(PROJECT_BINDING_PATH_FORBIDDEN));
    }

    let mut merged = existing_extra.clone();
    merge_json(&mut merged, patch);
    if project_touched {
        let project_value = patch_obj.get("project_id").expect("checked paired project key");
        let root_value = patch_obj.get("workspace_root_ref").expect("checked paired root key");
        let Some(merged_obj) = merged.as_object_mut() else {
            return Err(project_bad_request(PROJECT_BINDING_INVALID));
        };
        if project_value.is_null() && root_value.is_null() {
            merged_obj.remove("project_id");
            merged_obj.remove("workspace_root_ref");
        } else if project_value.is_string() && root_value.is_string() {
            if patch_obj.get("workspace").is_some_and(|value| !value.is_null()) {
                return Err(project_bad_request(PROJECT_BINDING_PATH_FORBIDDEN));
            }
            merged_obj.remove("workspace");
            merged_obj.remove("is_temporary_workspace");
        } else {
            return Err(project_bad_request(PROJECT_BINDING_INVALID));
        }
    }

    let merged_binding = parse_project_binding(&merged)?;
    let binding_changed = existing_binding
        .as_ref()
        .map(|binding| (&binding.project_id, &binding.workspace_root_ref))
        != merged_binding
            .as_ref()
            .map(|binding| (&binding.project_id, &binding.workspace_root_ref));
    if binding_changed {
        let next_revision = existing_revision
            .checked_add(1)
            .filter(|revision| *revision <= MAX_SAFE_PROJECT_BINDING_REVISION)
            .ok_or_else(|| project_bad_request(PROJECT_BINDING_REVISION_EXHAUSTED))?;
        let Some(merged_obj) = merged.as_object_mut() else {
            return Err(project_bad_request(PROJECT_BINDING_INVALID));
        };
        merged_obj.insert(
            "project_binding_revision".to_owned(),
            serde_json::Value::from(next_revision),
        );
        merged_obj.insert(
            "project_binding_receipt_id".to_owned(),
            serde_json::Value::String(operation_id.expect("binding changes require operation id").to_owned()),
        );
    }
    Ok((merged, binding_changed))
}

pub(crate) fn project_binding_expectation_for_update(
    project_touched: bool,
    expected: Option<&ProjectBindingExpectation>,
    project_binding_operation_id: Option<&str>,
) -> Result<Option<ConversationProjectBindingExpectation>, ConversationError> {
    if !project_touched {
        return if expected.is_some() || project_binding_operation_id.is_some() {
            Err(project_bad_request(PROJECT_BINDING_EXPECTATION_UNEXPECTED))
        } else {
            Ok(None)
        };
    }
    let Some(expected) = expected else {
        return Err(project_bad_request(PROJECT_BINDING_EXPECTATION_REQUIRED));
    };
    if project_binding_operation_id.is_none_or(|value| !valid_project_binding_operation_uuid(value))
        || expected.project_binding_revision > MAX_SAFE_PROJECT_BINDING_REVISION
        || expected
            .project_binding_receipt_id
            .as_deref()
            .is_some_and(|value| !valid_project_binding_operation_uuid(value))
    {
        return Err(project_bad_request(PROJECT_BINDING_EXPECTATION_INVALID));
    }
    match (&expected.project_id, &expected.workspace_root_ref) {
        (None, None) => Ok(Some(ConversationProjectBindingExpectation::unbound_with_receipt(
            expected.project_binding_revision,
            expected.project_binding_receipt_id.clone(),
        ))),
        (Some(project_id), Some(workspace_root_ref)) => {
            let candidate = serde_json::json!({
                "project_id": project_id,
                "workspace_root_ref": workspace_root_ref,
            });
            parse_project_binding(&candidate).map_err(|_| project_bad_request(PROJECT_BINDING_EXPECTATION_INVALID))?;
            Ok(Some(ConversationProjectBindingExpectation::bound(
                project_id,
                workspace_root_ref,
                expected.project_binding_revision,
                expected.project_binding_receipt_id.clone(),
            )))
        }
        _ => Err(project_bad_request(PROJECT_BINDING_EXPECTATION_INVALID)),
    }
}

pub(crate) fn is_idempotent_project_binding_retry(
    existing_extra: &serde_json::Value,
    patch: &serde_json::Value,
    expected: &ProjectBindingExpectation,
    project_binding_operation_id: &str,
) -> Result<bool, ConversationError> {
    if !valid_project_binding_operation_uuid(project_binding_operation_id)
        || expected.project_binding_revision >= MAX_SAFE_PROJECT_BINDING_REVISION
    {
        return Ok(false);
    }
    let Some(patch_obj) = patch.as_object() else {
        return Ok(false);
    };
    let (Some(project_id), Some(workspace_root_ref)) =
        (patch_obj.get("project_id"), patch_obj.get("workspace_root_ref"))
    else {
        return Ok(false);
    };
    let requested_pair = match (project_id, workspace_root_ref) {
        (serde_json::Value::Null, serde_json::Value::Null) => None,
        (serde_json::Value::String(project_id), serde_json::Value::String(workspace_root_ref)) => {
            Some((project_id.as_str(), workspace_root_ref.as_str()))
        }
        _ => return Ok(false),
    };
    let current = parse_project_binding(existing_extra)?;
    let current_pair = current
        .as_ref()
        .map(|binding| (binding.project_id.as_str(), binding.workspace_root_ref.as_str()));
    Ok(current_pair == requested_pair
        && project_binding_revision(existing_extra)? == expected.project_binding_revision + 1
        && project_binding_receipt_id(existing_extra)?.as_deref() == Some(project_binding_operation_id))
}

pub(crate) fn validate_project_runtime_path(
    request: &ProjectRuntimeWorkspaceRequest,
) -> Result<String, ConversationError> {
    if request.path.is_empty() || !Path::new(&request.path).is_absolute() {
        return Err(project_bad_request(PROJECT_RUNTIME_PATH_NOT_ABSOLUTE));
    }
    if request.path.trim() != request.path {
        return Err(project_bad_request(PROJECT_RUNTIME_PATH_NOT_CANONICAL));
    }
    let canonical =
        std::fs::canonicalize(&request.path).map_err(|_| project_bad_request(PROJECT_RUNTIME_PATH_UNAVAILABLE))?;
    if !canonical.is_dir() {
        return Err(project_bad_request(PROJECT_RUNTIME_PATH_UNAVAILABLE));
    }
    if canonical != Path::new(&request.path) || canonical.to_str() != Some(request.path.as_str()) {
        return Err(project_bad_request(PROJECT_RUNTIME_PATH_NOT_CANONICAL));
    }
    Ok(request.path.clone())
}

pub(crate) fn map_project_runtime_build_error(error: ConversationError) -> ConversationError {
    match error {
        ConversationError::WorkspacePathUnavailable { .. }
        | ConversationError::WorkspacePathRuntimeUnavailable { .. } => {
            project_bad_request(PROJECT_RUNTIME_PATH_UNAVAILABLE)
        }
        other => other,
    }
}

pub(crate) fn redact_project_runtime_error(
    data: &AgentStreamErrorData,
    canonical_workspace_path: Option<&str>,
) -> AgentStreamErrorData {
    let mut redacted = data.clone();
    let reported_workspace_path = redacted.workspace_path.take();
    for sensitive in [canonical_workspace_path, reported_workspace_path.as_deref()]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
    {
        redacted.message = redact_project_runtime_text(redacted.message, sensitive);
        redacted.detail = redacted
            .detail
            .map(|detail| redact_project_runtime_text(detail, sensitive));
    }
    redacted
}

/// Malformed reserved binding data means the persistence boundary cannot
/// safely determine whether an arbitrary path belongs to a project runtime.
/// Preserve machine-readable classification fields, but replace every
/// free-text/path field instead of guessing which substrings are sensitive.
pub(crate) fn redact_project_runtime_error_fail_closed(data: &AgentStreamErrorData) -> AgentStreamErrorData {
    let mut redacted = data.clone();
    redacted.message = PROJECT_RUNTIME_REDACTED.to_owned();
    redacted.detail = redacted.detail.as_ref().map(|_| PROJECT_RUNTIME_REDACTED.to_owned());
    redacted.workspace_path = None;
    redacted
}

/// Sanitize every string-bearing event field before the event reaches any
/// buffer, persistence adapter, log branch, or WebSocket broadcast. The
/// serialize/redact/deserialize boundary covers typed event structs as well
/// as nested arbitrary JSON payloads without maintaining a fragile variant
/// allow-list.
pub(crate) fn redact_project_runtime_event(
    event: AgentStreamEvent,
    canonical_workspace_path: &str,
) -> AgentStreamEvent {
    let mut sensitive_paths = vec![canonical_workspace_path.to_owned()];
    let mut event = event;
    if let AgentStreamEvent::Error(error) = &mut event
        && let Some(reported) = error.workspace_path.take()
        && !reported.is_empty()
    {
        sensitive_paths.push(reported);
    }

    let sanitized = serde_json::to_value(event).and_then(|mut value| {
        redact_project_runtime_json_value(&mut value, &sensitive_paths);
        serde_json::from_value(value)
    });
    sanitized.unwrap_or_else(|_| {
        AgentStreamEvent::Error(AgentStreamErrorData::legacy(
            "PROJECT_RUNTIME_EVENT_REDACTION_FAILED",
            None,
        ))
    })
}

pub(crate) fn redact_project_runtime_json_value(value: &mut serde_json::Value, sensitive_paths: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            *text = redact_project_runtime_paths(std::mem::take(text), sensitive_paths);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_project_runtime_json_value(value, sensitive_paths);
            }
        }
        serde_json::Value::Object(object) => {
            let old = std::mem::take(object);
            for (key, mut value) in old {
                redact_project_runtime_json_value(&mut value, sensitive_paths);
                object.insert(redact_project_runtime_paths(key, sensitive_paths), value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

pub(crate) fn redact_project_runtime_agent_error(error: AgentError, canonical_workspace_path: &str) -> AgentError {
    let redact = |value| redact_project_runtime_text(value, canonical_workspace_path);
    match error {
        AgentError::BadRequest(value) => AgentError::BadRequest(redact(value)),
        AgentError::Unauthorized(value) => AgentError::Unauthorized(redact(value)),
        AgentError::Forbidden(value) => AgentError::Forbidden(redact(value)),
        AgentError::NotFound(value) => AgentError::NotFound(redact(value)),
        AgentError::Conflict(value) => AgentError::Conflict(redact(value)),
        AgentError::BadGateway(value) => AgentError::BadGateway(redact(value)),
        AgentError::Timeout(value) => AgentError::Timeout(redact(value)),
        AgentError::RateLimited => AgentError::RateLimited,
        AgentError::ConversationArchived(value) => AgentError::ConversationArchived(redact(value)),
        AgentError::WorkspacePathRuntimeUnavailable(_) => AgentError::bad_request(PROJECT_RUNTIME_PATH_UNAVAILABLE),
        AgentError::Internal(value) => AgentError::Internal(redact(value)),
        AgentError::Acp(value) => AgentError::bad_gateway(redact(value.to_string())),
        _ => AgentError::internal("Project runtime failed"),
    }
}

fn redact_project_runtime_text(value: String, sensitive: &str) -> String {
    redact_project_runtime_paths(value, &[sensitive.to_owned()])
}

fn redact_project_runtime_paths(mut value: String, sensitive_paths: &[String]) -> String {
    let mut variants = sensitive_paths
        .iter()
        .filter(|path| !path.is_empty())
        .flat_map(|path| project_path_aliases(path))
        .flat_map(|path| project_path_encodings(&path))
        .collect::<Vec<_>>();
    variants.sort_by_key(|variant| std::cmp::Reverse(variant.len()));
    variants.dedup();
    for sensitive in variants {
        value = redact_exact_path_root(&value, &sensitive);
    }
    value
}

fn project_path_aliases(path: &str) -> Vec<String> {
    let path = path.trim_end_matches(['/', '\\']).to_owned();
    let mut aliases = vec![path.clone()];
    if let Some(alias) = path.strip_prefix("/private/") {
        aliases.push(format!("/{alias}"));
    } else if path.starts_with("/var/") || path.starts_with("/tmp/") {
        aliases.push(format!("/private{path}"));
    }
    aliases
}

fn project_path_encodings(path: &str) -> Vec<String> {
    let mut variants = vec![path.to_owned()];
    for depth in 1..=4 {
        let escaped_separator = format!("{}/", "\\".repeat(depth));
        variants.push(path.replace('/', &escaped_separator));
    }
    let backslash = path.replace('/', "\\");
    variants.push(backslash.clone());
    for depth in 2..=4 {
        variants.push(backslash.replace('\\', &"\\".repeat(depth)));
    }
    variants
}

fn redact_exact_path_root(value: &str, sensitive: &str) -> String {
    if sensitive.is_empty() || !value.contains(sensitive) {
        return value.to_owned();
    }
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(relative) = value[cursor..].find(sensitive) {
        let start = cursor + relative;
        let end = start + sensitive.len();
        let before = value[..start].chars().next_back();
        let after = value[end..].chars().next();
        let boundary_before = before.is_none_or(|character| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '(' | '[' | '{' | '=' | ':' | ',' | ';' | '/' | '\\'
                )
        });
        let boundary_after = after.is_none_or(|character| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | ')' | ']' | '}' | ':' | ',' | ';' | '!' | '?' | '#' | '/' | '\\'
                )
        });
        if boundary_before && boundary_after {
            output.push_str(&value[cursor..start]);
            output.push_str(PROJECT_RUNTIME_REDACTED);
            cursor = end;
        } else {
            let next = value[start..].chars().next().expect("matched string is non-empty");
            let next_end = start + next.len_utf8();
            output.push_str(&value[cursor..next_end]);
            cursor = next_end;
        }
    }
    output.push_str(&value[cursor..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_ai_agent::protocol::events::TextEventData;
    use aionui_ai_agent::protocol::events::{
        ThinkingEventData, TipType, TipsEventData, ToolCallEventData, ToolCallStatus,
    };
    use serde_json::json;

    const PROJECT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ROOT_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const RECEIPT_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    fn binding(project_id: &str, root_ref: &str, receipt: &str) -> serde_json::Value {
        json!({
            "project_id": project_id,
            "workspace_root_ref": root_ref,
            "project_binding_revision": 1,
            "project_binding_receipt_id": receipt
        })
    }

    #[test]
    fn binding_identity_grammar_separates_opaque_ids_from_v4_operations() {
        assert!(parse_project_binding(&binding(PROJECT_ID, &format!("root:{ROOT_ID}"), RECEIPT_ID)).is_ok());
        for invalid_project in [
            "00000000-0000-0000-0000-000000000000",
            "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa",
            "aaaaaaaa-aaaa-4aaa-0aaa-aaaaaaaaaaaa",
            "aaaaaaaa-aaaa-4aaa-faaa-aaaaaaaaaaaa",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
        ] {
            assert!(parse_project_binding(&binding(invalid_project, &format!("root:{ROOT_ID}"), RECEIPT_ID)).is_err());
        }
        for invalid_root in [
            "root:primary-projects",
            "root:bbbbbbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb",
            "root:bbbbbbbb-bbbb-4bbb-0bbb-bbbbbbbbbbbb",
            "root:bbbbbbbb-bbbb-4bbb-fbbb-bbbbbbbbbbbb",
            "root:BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB",
        ] {
            assert!(parse_project_binding(&binding(PROJECT_ID, invalid_root, RECEIPT_ID)).is_err());
        }
        for invalid_receipt in [
            "cccccccc-cccc-1ccc-8ccc-cccccccccccc",
            "cccccccc-cccc-5ccc-8ccc-cccccccccccc",
            "cccccccc-cccc-7ccc-8ccc-cccccccccccc",
            "cccccccc-cccc-4ccc-0ccc-cccccccccccc",
            "cccccccc-cccc-4ccc-fccc-cccccccccccc",
            "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC",
        ] {
            assert!(parse_project_binding(&binding(PROJECT_ID, &format!("root:{ROOT_ID}"), invalid_receipt)).is_err());
        }
    }

    #[test]
    fn structured_event_redaction_covers_typed_json_encoded_alias_and_error_paths() {
        let canonical = "/private/var/folders/eve/project-alpha";
        let leak = format!(
            "normal {canonical}/src escaped \\/private\\/var\\/folders\\/eve\\/project-alpha\\/tool \\private\\var\\folders\\eve\\project-alpha\\secret alias /var/folders/eve/project-alpha/out keep {canonical}-notes.txt"
        );
        let events = vec![
            AgentStreamEvent::Text(TextEventData { content: leak.clone() }),
            AgentStreamEvent::Thinking(ThinkingEventData {
                content: leak.clone(),
                subject: Some(leak.clone()),
                duration: None,
                status: None,
            }),
            AgentStreamEvent::Tips(TipsEventData {
                content: leak.clone(),
                tip_type: TipType::Warning,
                code: Some(leak.clone()),
                params: Some(json!({ leak.clone(): {"nested": leak.clone()} })),
            }),
            AgentStreamEvent::ToolCall(ToolCallEventData {
                call_id: "call-1".into(),
                name: "read_file".into(),
                args: json!({"path": leak.clone()}),
                status: ToolCallStatus::Running,
                input: Some(json!({"nested": [leak.clone()]})),
                output: Some(leak.clone()),
                description: Some(leak.clone()),
            }),
            AgentStreamEvent::Permission(json!({"path": leak.clone()})),
            AgentStreamEvent::System(json!({"path": leak.clone()})),
            AgentStreamEvent::RequestTrace(json!({"trace": leak.clone()})),
            AgentStreamEvent::AcpModelInfo(json!({"model": leak.clone()})),
            AgentStreamEvent::AcpModeInfo(json!({"mode": leak.clone()})),
            AgentStreamEvent::AcpConfigOption(json!({"config": leak.clone()})),
            AgentStreamEvent::AcpSessionInfo(json!({"session": leak.clone()})),
            AgentStreamEvent::SlashCommandsUpdated(json!({"command": leak.clone()})),
        ];

        for event in events {
            let encoded = serde_json::to_string(&redact_project_runtime_event(event, canonical)).unwrap();
            assert!(!encoded.contains("project-alpha/src"));
            assert!(!encoded.contains("project-alpha\\\\/tool"));
            assert!(!encoded.contains("project-alpha\\\\secret"));
            assert!(!encoded.contains("project-alpha/out"));
            assert!(encoded.contains("[project workspace redacted]"));
            assert!(encoded.contains("project-alpha-notes.txt"));
        }

        let mut error = AgentStreamErrorData::legacy(format!("failed at {canonical}/secret"), None);
        error.workspace_path = Some(canonical.to_owned());
        error.detail = Some(format!("detail {canonical}/secret"));
        let sanitized = redact_project_runtime_event(AgentStreamEvent::Error(error), canonical);
        let encoded = serde_json::to_string(&sanitized).unwrap();
        assert!(!encoded.contains(canonical));
        assert!(!encoded.contains("workspacePath"));
    }
}
