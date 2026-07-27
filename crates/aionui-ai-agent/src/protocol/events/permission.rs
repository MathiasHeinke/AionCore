use agent_client_protocol::schema::Meta as SdkMeta;
use aionui_common::{Confirmation, ConfirmationOption};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tool_call::{AcpToolCallContentItem, AcpToolCallKind, AcpToolCallLocationItem, AcpToolCallStatus};

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
        }
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
    }
}
