//! Idempotent Command EVE correction boundary request handling.

use std::collections::HashMap;

use tracing::info;

use super::{
    AcpClientExtensionRouter, MAX_PROMPT_ADMISSION_PAYLOAD_BYTES, ResponseSender, respond_ignoring_transport,
    rpc_internal, validate_identifier,
};
use crate::protocol::events::{AgentStreamEvent, CorrectionBoundaryEventData};

pub(super) const EXT_METHOD: &str = "command_eve/correction_boundary";
#[cfg(test)]
const WIRE_METHOD: &str = "_command_eve/correction_boundary";
const VERSION: &str = "command-eve-correction-boundary/v1";
const MAX_RECEIPTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReceiptState {
    Retryable(u64),
    Accepted(u64),
    Rejected,
}

pub(super) type ReceiptMap = HashMap<(String, String), ReceiptState>;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: String,
    request_id: String,
    session_id: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Response {
    version: String,
    request_id: String,
    status: Status,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Accepted,
    Rejected,
}

pub(super) fn handle(router: &AcpClientExtensionRouter, raw_params: &str, respond: ResponseSender) {
    if raw_params.len() > MAX_PROMPT_ADMISSION_PAYLOAD_BYTES {
        respond_ignoring_transport(respond, Err(rpc_internal("payload_too_large")));
        return;
    }
    let request = match serde_json::from_str::<Request>(raw_params) {
        Ok(request)
            if request.version == VERSION
                && validate_identifier(&request.request_id).is_ok()
                && validate_identifier(&request.session_id).is_ok() =>
        {
            request
        }
        _ => {
            respond_ignoring_transport(respond, Err(rpc_internal("invalid_shape")));
            return;
        }
    };

    let receipt_key = (request.session_id.clone(), request.request_id.clone());

    // The read admission linearizes this event with cancel/close/rebind. A
    // lifecycle transition either owns the writer first and rejects this
    // request, or waits until the exact session boundary is committed.
    let Some(admission) = router.session_binding.try_acquire_admission() else {
        reject_receipt(router, &receipt_key, respond, &request.request_id);
        return;
    };
    if admission.lease().session_id() != request.session_id {
        drop(admission);
        reject_receipt(router, &receipt_key, respond, &request.request_id);
        return;
    }
    let generation = admission.lease().generation();

    let mut state = match router.state.lock() {
        Ok(state) => state,
        Err(_) => {
            respond_ignoring_transport(respond, Err(rpc_internal("state_unavailable")));
            return;
        }
    };
    // Tombstones live for the current bound session. They are bounded and
    // fail closed instead of expiring while a long-running turn may still
    // retry an ambiguously delivered response.
    state
        .correction_boundary_receipts
        .retain(|(session_id, _), _| session_id == &request.session_id);
    match state.correction_boundary_receipts.get(&receipt_key).copied() {
        Some(ReceiptState::Accepted(existing_generation)) if existing_generation == generation => {
            drop(state);
            drop(admission);
            send_response(respond, &request.request_id, true);
            return;
        }
        Some(ReceiptState::Retryable(existing_generation)) if existing_generation == generation => {}
        Some(_) => {
            state
                .correction_boundary_receipts
                .insert(receipt_key, ReceiptState::Rejected);
            drop(state);
            drop(admission);
            send_response(respond, &request.request_id, false);
            return;
        }
        None => {
            if state.correction_boundary_receipts.len() >= MAX_RECEIPTS {
                drop(state);
                drop(admission);
                respond_ignoring_transport(respond, Err(rpc_internal("receipt_capacity_exhausted")));
                return;
            }
            state
                .correction_boundary_receipts
                .insert(receipt_key.clone(), ReceiptState::Retryable(generation));
        }
    }
    if router
        .event_tx
        .send(AgentStreamEvent::CorrectionBoundary(
            CorrectionBoundaryEventData::default(),
        ))
        .is_err()
    {
        drop(state);
        drop(admission);
        send_response(respond, &request.request_id, false);
        return;
    }
    state
        .correction_boundary_receipts
        .insert(receipt_key, ReceiptState::Accepted(generation));
    drop(state);
    drop(admission);
    send_response(respond, &request.request_id, true);
}

fn reject_receipt(
    router: &AcpClientExtensionRouter,
    receipt_key: &(String, String),
    respond: ResponseSender,
    request_id: &str,
) {
    let mut state = match router.state.lock() {
        Ok(state) => state,
        Err(_) => {
            respond_ignoring_transport(respond, Err(rpc_internal("state_unavailable")));
            return;
        }
    };
    if !state.correction_boundary_receipts.contains_key(receipt_key)
        && state.correction_boundary_receipts.len() >= MAX_RECEIPTS
    {
        respond_ignoring_transport(respond, Err(rpc_internal("receipt_capacity_exhausted")));
        return;
    }
    state
        .correction_boundary_receipts
        .insert(receipt_key.clone(), ReceiptState::Rejected);
    drop(state);
    send_response(respond, request_id, false);
}

fn send_response(respond: ResponseSender, request_id: &str, accepted: bool) {
    let response = Response {
        version: VERSION.to_owned(),
        request_id: request_id.to_owned(),
        status: if accepted { Status::Accepted } else { Status::Rejected },
    };
    let Ok(value) = serde_json::to_value(response) else {
        respond_ignoring_transport(respond, Err(rpc_internal("response_encoding_failed")));
        return;
    };
    let queued = respond(Ok(value)).is_ok();
    info!(
        method = EXT_METHOD,
        accepted,
        queued,
        request_id_bytes = request_id.len(),
        "ACP correction boundary decision queued"
    );
}

#[cfg(test)]
mod tests {
    use agent_client_protocol::{JsonRpcMessage, schema::AgentRequest};
    use tokio::sync::{broadcast, oneshot};

    use super::*;

    fn request(request_id: &str, session_id: &str) -> serde_json::Value {
        serde_json::json!({
            "version": VERSION,
            "request_id": request_id,
            "session_id": session_id,
        })
    }

    fn dispatch(
        router: &AcpClientExtensionRouter,
        raw: &str,
    ) -> oneshot::Receiver<Result<serde_json::Value, agent_client_protocol::Error>> {
        let (tx, rx) = oneshot::channel();
        let sender: ResponseSender = Box::new(move |result| {
            tx.send(result)
                .map_err(|_| agent_client_protocol::Error::internal_error())
        });
        handle(router, raw, sender);
        rx
    }

    fn accepted_response(value: serde_json::Value, request_id: &str) -> bool {
        serde_json::from_value::<Response>(value).is_ok_and(|response| {
            response
                == Response {
                    version: VERSION.to_owned(),
                    request_id: request_id.to_owned(),
                    status: Status::Accepted,
                }
        })
    }

    #[test]
    fn sdk_strips_private_wire_prefix_before_router_matching() {
        let parsed = AgentRequest::parse_message(WIRE_METHOD, &request("receipt-wire", "session-1")).unwrap();
        assert!(matches!(
            parsed,
            AgentRequest::ExtMethodRequest(request) if request.method.as_ref() == EXT_METHOD
        ));
    }

    #[tokio::test]
    async fn request_is_idempotent_after_response_delivery_failure() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-correction").await.unwrap();
        let request = request("receipt-1", "session-correction");

        let failed_delivery: ResponseSender = Box::new(|result| {
            assert!(accepted_response(
                result.expect("accepted response before transport failure"),
                "receipt-1",
            ));
            Err(agent_client_protocol::Error::internal_error())
        });
        handle(&router, &request.to_string(), failed_delivery);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));

        let retried = dispatch(&router, &request.to_string()).await.unwrap().unwrap();
        assert!(accepted_response(retried, "receipt-1"));
        assert!(
            event_rx.try_recv().is_err(),
            "the same session receipt must not emit a second boundary"
        );
    }

    #[tokio::test]
    async fn request_rejects_invalid_or_unbound_envelopes_without_an_event() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-correction").await.unwrap();

        let committed_request = request("receipt-committed", "session-correction");
        let committed = dispatch(&router, &committed_request.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(accepted_response(committed, "receipt-committed"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));

        let unbound = dispatch(&router, &request("receipt-unbound", "session-other").to_string())
            .await
            .unwrap()
            .unwrap();
        let unbound: Response = serde_json::from_value(unbound).unwrap();
        assert_eq!(unbound.status, Status::Rejected);

        let committed_replay = dispatch(&router, &committed_request.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(accepted_response(committed_replay, "receipt-committed"));

        for invalid in [
            "{".to_owned(),
            serde_json::json!({
                "version": VERSION,
                "request_id": "receipt-extra",
                "session_id": "session-correction",
                "unexpected": true,
            })
            .to_string(),
            serde_json::json!({
                "version": "command-eve-correction-boundary/v0",
                "request_id": "receipt-version",
                "session_id": "session-correction",
            })
            .to_string(),
            serde_json::json!({
                "version": VERSION,
                "request_id": "receipt\ninvalid",
                "session_id": "session-correction",
            })
            .to_string(),
        ] {
            assert_eq!(
                i32::from(dispatch(&router, &invalid).await.unwrap().unwrap_err().code),
                -32603
            );
        }
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn request_retries_after_no_subscriber_rejection() {
        let (event_tx, event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-correction").await.unwrap();
        drop(event_rx);
        let request = request("receipt-subscriber", "session-correction");

        let rejected = dispatch(&router, &request.to_string()).await.unwrap().unwrap();
        let rejected: Response = serde_json::from_value(rejected).unwrap();
        assert_eq!(rejected.status, Status::Rejected);

        let mut event_rx = router.event_tx.subscribe();
        let accepted = dispatch(&router, &request.to_string()).await.unwrap().unwrap();
        assert!(accepted_response(accepted, "receipt-subscriber"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));
    }

    #[tokio::test]
    async fn request_stays_fenced_for_the_full_session_lifecycle_interval() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-correction").await.unwrap();
        let lifecycle = router.begin_session_binding().await.unwrap();
        let lifecycle_request = request("receipt-lifecycle", "session-correction");

        let rejected = dispatch(&router, &lifecycle_request.to_string())
            .await
            .unwrap()
            .unwrap();
        let rejected: Response = serde_json::from_value(rejected).unwrap();
        assert_eq!(rejected.status, Status::Rejected);
        assert!(event_rx.try_recv().is_err());

        router.finish_session_binding(lifecycle, "session-correction").unwrap();
        let rejected_again = dispatch(&router, &lifecycle_request.to_string())
            .await
            .unwrap()
            .unwrap();
        let rejected_again: Response = serde_json::from_value(rejected_again).unwrap();
        assert_eq!(rejected_again.status, Status::Rejected);
        assert!(event_rx.try_recv().is_err());

        let fresh = dispatch(
            &router,
            &request("receipt-lifecycle-fresh", "session-correction").to_string(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(accepted_response(fresh, "receipt-lifecycle-fresh"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));
    }

    #[tokio::test]
    async fn receipt_capacity_fails_closed_and_a_new_bound_session_recovers() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = AcpClientExtensionRouter::new(event_tx);
        router.bind_session("session-capacity").await.unwrap();
        {
            let mut state = router.state.lock().unwrap();
            state
                .correction_boundary_receipts
                .extend((0..MAX_RECEIPTS).map(|index| {
                    (
                        ("session-capacity".to_owned(), format!("receipt-{index}")),
                        ReceiptState::Accepted(1),
                    )
                }));
        }

        let exhausted = dispatch(&router, &request("receipt-overflow", "session-capacity").to_string())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(i32::from(exhausted.code), -32603);
        assert!(event_rx.try_recv().is_err());

        router.bind_session("session-recovered").await.unwrap();
        let recovered = dispatch(&router, &request("receipt-recovered", "session-recovered").to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(accepted_response(recovered, "receipt-recovered"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));
    }
}
