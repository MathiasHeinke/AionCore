use agent_client_protocol::schema::Meta as SdkMeta;
use aionui_common::{Confirmation, ConfirmationAuthorityMetadata, ConfirmationOption};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tool_call::{AcpToolCallContentItem, AcpToolCallKind, AcpToolCallLocationItem, AcpToolCallStatus};

const COMMAND_EVE_AUTHORITY_META_KEY: &str = "command_eve_authority";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AcpPermissionEventData {
    Request(AcpPermissionRequestData),
    Confirmation(Confirmation),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPermissionRequestData {
    #[serde(default)]
    pub session_id: String,
    pub tool_call: AcpPermissionToolCall,
    pub options: Vec<AcpPermissionOptionData>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPermissionToolCall {
    pub tool_call_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AcpToolCallStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<AcpToolCallKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<AcpToolCallContentItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<AcpToolCallLocationItem>>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpPermissionOptionData {
    pub option_id: String,
    pub name: String,
    pub kind: AcpPermissionOptionKind,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<SdkMeta>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpPermissionOptionKind {
    AllowOnce,
    AllowAlways,
    RejectOnce,
    RejectAlways,
}

impl AcpPermissionEventData {
    pub fn as_confirmation(&self) -> Option<Confirmation> {
        match self {
            Self::Confirmation(conf) => Some(conf.clone()),
            Self::Request(req) => Some(req.to_confirmation()),
        }
    }
}

impl AcpPermissionRequestData {
    pub fn to_confirmation(&self) -> Confirmation {
        let description = self.safe_confirmation_description();
        Confirmation {
            id: self.tool_call.tool_call_id.clone(),
            call_id: self.tool_call.tool_call_id.clone(),
            title: self.tool_call.title.clone(),
            action: None,
            description,
            command_type: self.tool_call.kind.map(|kind| match kind {
                AcpToolCallKind::Read => "read".to_owned(),
                AcpToolCallKind::Edit => "edit".to_owned(),
                AcpToolCallKind::Execute => "execute".to_owned(),
            }),
            options: self
                .options
                .iter()
                .map(|opt| ConfirmationOption {
                    label: opt.name.clone(),
                    value: Value::String(opt.option_id.clone()),
                    params: None,
                })
                .collect(),
            authority: self.validated_authority_metadata(),
        }
    }

    fn validated_authority_metadata(&self) -> Option<ConfirmationAuthorityMetadata> {
        let metadata = serde_json::from_value(self.meta.as_ref()?.get(COMMAND_EVE_AUTHORITY_META_KEY)?.clone()).ok()?;
        is_valid_authority_metadata(&metadata, &self.tool_call.tool_call_id).then_some(metadata)
    }

    /// Build a useful confirmation summary without serializing the complete
    /// raw input. Edit requests may contain whole file bodies under
    /// `arguments`; echoing that JSON into the card is both noisy and an
    /// avoidable disclosure surface.
    fn safe_confirmation_description(&self) -> String {
        let raw_input = self.tool_call.raw_input.as_ref();
        raw_input
            .and_then(|raw| raw.get("description").and_then(Value::as_str))
            .or_else(|| raw_input.and_then(|raw| raw.get("command").and_then(Value::as_str)))
            .or_else(|| raw_input.and_then(|raw| raw.get("tool").and_then(Value::as_str)))
            .or(self.tool_call.title.as_deref())
            .unwrap_or("Permission required for an unverified operation")
            .to_owned()
    }
}

pub(crate) fn attach_confirmation_authority_metadata(
    event: &mut AcpPermissionEventData,
    metadata: &ConfirmationAuthorityMetadata,
) {
    let AcpPermissionEventData::Request(request) = event else {
        return;
    };
    request
        .meta
        .get_or_insert_with(Default::default)
        .insert(COMMAND_EVE_AUTHORITY_META_KEY.to_owned(), serde_json::json!(metadata));
}

fn is_valid_authority_metadata(metadata: &ConfirmationAuthorityMetadata, call_id: &str) -> bool {
    let digest_is_valid = |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    let authority_matches_class = matches!(
        (metadata.classification.as_str(), metadata.required_authority.as_deref()),
        ("routine_edit" | "routine_terminal" | "hard_blocked" | "unknown", None)
            | ("sensitive", Some("user"))
            | ("hg35", Some("proxy"))
            | ("hg4", Some("founder"))
    );

    metadata.protocol_version == 1
        && metadata.operation_id == call_id
        && digest_is_valid(&metadata.operation_digest)
        && metadata.confirmation_version > 0
        && metadata.policy_revision > 0
        && metadata.session_epoch > 0
        && metadata.created_at_ms <= metadata.expires_at_ms
        && matches!(
            metadata.lifecycle.as_str(),
            "pending" | "allowed" | "denied" | "expired" | "cancelled" | "superseded"
        )
        && authority_matches_class
        && digest_is_valid(&metadata.runtime_receipt_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn edit_confirmation_projection_does_not_serialize_raw_arguments() {
        let request = AcpPermissionRequestData {
            session_id: "session-1".into(),
            tool_call: AcpPermissionToolCall {
                tool_call_id: "call-1".into(),
                status: None,
                title: Some("Edit file".into()),
                kind: Some(AcpToolCallKind::Edit),
                raw_input: Some(json!({
                    "tool": "write_file",
                    "arguments": {
                        "path": "/tmp/example.txt",
                        "content": "sensitive-full-file-body"
                    }
                })),
                raw_output: None,
                content: None,
                locations: None,
                meta: None,
            },
            options: vec![AcpPermissionOptionData {
                option_id: "allow_once".into(),
                name: "Allow edit".into(),
                kind: AcpPermissionOptionKind::AllowOnce,
                meta: None,
            }],
            meta: None,
        };

        let confirmation = request.to_confirmation();
        assert_eq!(confirmation.description, "write_file");
        assert!(!confirmation.description.contains("sensitive-full-file-body"));
        assert_eq!(confirmation.command_type.as_deref(), Some("edit"));
        assert!(confirmation.authority.is_none());
    }

    #[test]
    fn malformed_or_mismatched_authority_meta_fails_closed() {
        let mut request = AcpPermissionRequestData {
            session_id: "session-1".into(),
            tool_call: AcpPermissionToolCall {
                tool_call_id: "call-1".into(),
                status: None,
                title: Some("Run command".into()),
                kind: Some(AcpToolCallKind::Execute),
                raw_input: Some(json!({"command":"pwd"})),
                raw_output: None,
                content: None,
                locations: None,
                meta: None,
            },
            options: vec![],
            meta: Some(serde_json::Map::from_iter([(
                COMMAND_EVE_AUTHORITY_META_KEY.to_owned(),
                json!({"protocol_version":"not-a-number"}),
            )])),
        };
        assert!(request.to_confirmation().authority.is_none());

        request.meta.as_mut().unwrap().insert(
            COMMAND_EVE_AUTHORITY_META_KEY.to_owned(),
            json!({
                "protocol_version": 1,
                "operation_id": "different-call",
                "operation_digest": "a".repeat(64),
                "confirmation_version": 1,
                "policy_revision": 1,
                "session_epoch": 1,
                "created_at_ms": 1,
                "expires_at_ms": 2,
                "lifecycle": "pending",
                "classification": "routine_terminal",
                "required_authority": null,
                "runtime_receipt_digest": "b".repeat(64),
            }),
        );
        assert!(request.to_confirmation().authority.is_none());
    }

    #[test]
    fn validated_authority_meta_projects_from_existing_request_meta() {
        let expected = ConfirmationAuthorityMetadata {
            protocol_version: 1,
            operation_id: "call-1".into(),
            operation_digest: "a".repeat(64),
            confirmation_version: 7,
            policy_revision: 5,
            session_epoch: 3,
            created_at_ms: 100,
            expires_at_ms: 200,
            lifecycle: "pending".into(),
            classification: "hg4".into(),
            required_authority: Some("founder".into()),
            runtime_receipt_digest: "b".repeat(64),
        };
        let mut event = AcpPermissionEventData::Request(AcpPermissionRequestData {
            session_id: "session-1".into(),
            tool_call: AcpPermissionToolCall {
                tool_call_id: "call-1".into(),
                status: None,
                title: Some("Release operation".into()),
                kind: Some(AcpToolCallKind::Execute),
                raw_input: Some(json!({"command":"opaque"})),
                raw_output: None,
                content: None,
                locations: None,
                meta: None,
            },
            options: vec![],
            meta: None,
        });

        attach_confirmation_authority_metadata(&mut event, &expected);
        let confirmation = event.as_confirmation().unwrap();
        assert_eq!(confirmation.authority, Some(expected));
        let AcpPermissionEventData::Request(request) = event else {
            panic!("request event expected");
        };
        assert_eq!(request.tool_call.raw_input, Some(json!({"command":"opaque"})));
    }
}
