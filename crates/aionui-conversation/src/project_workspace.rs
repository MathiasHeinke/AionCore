//! Portable project identity and transient runtime workspace validation.
//!
//! AionUi main owns seat/realm/root resolution. This module only proves that
//! the request tuple matches the canonical conversation tuple and that the
//! resolved local directory is safe to inject for the current runtime.

use std::path::Path;

use aionui_api_types::ProjectRuntimeWorkspaceRequest;
use aionui_db::models::ConversationRow;
use uuid::Uuid;

use crate::ConversationError;

const PROJECT_BINDING_INCOMPLETE: &str = "PROJECT_BINDING_INCOMPLETE";
const PROJECT_BINDING_INVALID: &str = "PROJECT_BINDING_INVALID";
pub(crate) const PROJECT_BINDING_PATH_FORBIDDEN: &str = "PROJECT_BINDING_PATH_FORBIDDEN";
const PROJECT_BINDING_UPDATE_REQUIRES_PAIR: &str = "PROJECT_BINDING_UPDATE_REQUIRES_PAIR";
pub(crate) const PROJECT_BINDING_INTERNAL_MUTATION_FORBIDDEN: &str = "PROJECT_BINDING_INTERNAL_MUTATION_FORBIDDEN";
pub(crate) const PROJECT_RUNTIME_BINDING_REQUIRED: &str = "PROJECT_RUNTIME_BINDING_REQUIRED";
pub(crate) const PROJECT_RUNTIME_BINDING_UNEXPECTED: &str = "PROJECT_RUNTIME_BINDING_UNEXPECTED";
pub(crate) const PROJECT_RUNTIME_BINDING_MISMATCH: &str = "PROJECT_RUNTIME_BINDING_MISMATCH";
const PROJECT_RUNTIME_PATH_NOT_ABSOLUTE: &str = "PROJECT_RUNTIME_PATH_NOT_ABSOLUTE";
const PROJECT_RUNTIME_PATH_NOT_CANONICAL: &str = "PROJECT_RUNTIME_PATH_NOT_CANONICAL";
const PROJECT_RUNTIME_PATH_UNAVAILABLE: &str = "PROJECT_RUNTIME_PATH_UNAVAILABLE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectConversationBinding {
    pub(crate) project_id: String,
    pub(crate) workspace_root_ref: String,
}

pub(crate) fn project_bad_request(reason: &'static str) -> ConversationError {
    ConversationError::BadRequest { reason: reason.into() }
}

fn valid_workspace_root_ref(value: &str) -> bool {
    let Some(opaque_id) = value.strip_prefix("root:") else {
        return false;
    };
    !opaque_id.is_empty()
        && opaque_id.len() <= 128
        && opaque_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn parse_project_binding(
    extra: &serde_json::Value,
) -> Result<Option<ProjectConversationBinding>, ConversationError> {
    let Some(obj) = extra.as_object() else {
        return Ok(None);
    };
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
    let parsed_id = Uuid::parse_str(project_id).map_err(|_| project_bad_request(PROJECT_BINDING_INVALID))?;
    if parsed_id.hyphenated().to_string() != project_id || !valid_workspace_root_ref(workspace_root_ref) {
        return Err(project_bad_request(PROJECT_BINDING_INVALID));
    }
    if obj.contains_key("workspace") {
        return Err(project_bad_request(PROJECT_BINDING_PATH_FORBIDDEN));
    }

    Ok(Some(ProjectConversationBinding {
        project_id: project_id.to_owned(),
        workspace_root_ref: workspace_root_ref.to_owned(),
    }))
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
        for key in ["project_id", "workspace_root_ref"] {
            if obj.get(key).is_some_and(serde_json::Value::is_null) {
                obj.remove(key);
            }
        }
    }
    parse_project_binding(extra)
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
) -> Result<(serde_json::Value, bool), ConversationError> {
    let existing_binding = parse_project_binding(existing_extra)?;
    let Some(patch_obj) = patch.as_object() else {
        return Ok((existing_extra.clone(), false));
    };
    let project_touched = patch_obj.contains_key("project_id") || patch_obj.contains_key("workspace_root_ref");
    if project_touched && !(patch_obj.contains_key("project_id") && patch_obj.contains_key("workspace_root_ref")) {
        return Err(project_bad_request(PROJECT_BINDING_UPDATE_REQUIRES_PAIR));
    }
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
    Ok((merged, existing_binding != merged_binding))
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
