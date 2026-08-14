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
const VERSION: &str = "command-eve-correction-boundary/v2";
const MAX_RECEIPTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReceiptState {
    Retryable(u64),
    Accepted(u64),
    Rejected(RejectionReason),
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
    rejection: Option<RejectionReason>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Accepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RejectionReason {
    RetryableSameGeneration,
    LifecycleChanged,
    SessionMismatch,
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

    // The read admission linearizes this event with cancel/close/rebind. When
    // a lifecycle writer owns the interval first, the exact current-generation
    // receipt remains retryable but cannot emit or commit until the writer is
    // terminal; a changed/unbound generation is rejected below.
    let Some(admission) = router.session_binding.try_acquire_admission() else {
        // Admission can be unavailable before a lifecycle writer has changed
        // the binding at all (including idempotent same-session prompt ACKs
        // and mismatched close requests). Preserve the exact receipt as
        // retryable while its recorded/current generation is still live. This
        // path never emits the boundary event or grants admission; the caller
        // must retry after the lifecycle owner reaches terminal state.
        if let Some(generation) = router.session_binding.retry_generation_for_session(&request.session_id) {
            retry_receipt_during_lifecycle(router, &receipt_key, generation, respond, &request.request_id);
        } else {
            reject_receipt(
                router,
                &receipt_key,
                RejectionReason::LifecycleChanged,
                respond,
                &request.request_id,
            );
        }
        return;
    };
    if admission.lease().session_id() != request.session_id {
        drop(admission);
        reject_receipt(
            router,
            &receipt_key,
            RejectionReason::SessionMismatch,
            respond,
            &request.request_id,
        );
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
            send_response(respond, &request.request_id, true, None);
            return;
        }
        Some(ReceiptState::Retryable(existing_generation)) if existing_generation == generation => {}
        Some(ReceiptState::Rejected(reason)) => {
            drop(state);
            drop(admission);
            send_response(respond, &request.request_id, false, Some(reason));
            return;
        }
        Some(ReceiptState::Accepted(_) | ReceiptState::Retryable(_)) => {
            state
                .correction_boundary_receipts
                .insert(receipt_key, ReceiptState::Rejected(RejectionReason::LifecycleChanged));
            drop(state);
            drop(admission);
            send_response(
                respond,
                &request.request_id,
                false,
                Some(RejectionReason::LifecycleChanged),
            );
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
        send_response(
            respond,
            &request.request_id,
            false,
            Some(RejectionReason::RetryableSameGeneration),
        );
        return;
    }
    state
        .correction_boundary_receipts
        .insert(receipt_key, ReceiptState::Accepted(generation));
    drop(state);
    drop(admission);
    send_response(respond, &request.request_id, true, None);
}

fn reject_receipt(
    router: &AcpClientExtensionRouter,
    receipt_key: &(String, String),
    reason: RejectionReason,
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
        .insert(receipt_key.clone(), ReceiptState::Rejected(reason));
    drop(state);
    send_response(respond, request_id, false, Some(reason));
}

fn retry_receipt_during_lifecycle(
    router: &AcpClientExtensionRouter,
    receipt_key: &(String, String),
    generation: u64,
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
    match state.correction_boundary_receipts.get(receipt_key).copied() {
        Some(ReceiptState::Accepted(existing_generation) | ReceiptState::Retryable(existing_generation))
            if existing_generation == generation => {}
        Some(ReceiptState::Rejected(reason)) => {
            drop(state);
            send_response(respond, request_id, false, Some(reason));
            return;
        }
        Some(ReceiptState::Accepted(_) | ReceiptState::Retryable(_)) => {
            state.correction_boundary_receipts.insert(
                receipt_key.clone(),
                ReceiptState::Rejected(RejectionReason::LifecycleChanged),
            );
            drop(state);
            send_response(respond, request_id, false, Some(RejectionReason::LifecycleChanged));
            return;
        }
        None => {
            if state.correction_boundary_receipts.len() >= MAX_RECEIPTS {
                drop(state);
                respond_ignoring_transport(respond, Err(rpc_internal("receipt_capacity_exhausted")));
                return;
            }
            state
                .correction_boundary_receipts
                .insert(receipt_key.clone(), ReceiptState::Retryable(generation));
        }
    }
    drop(state);
    send_response(
        respond,
        request_id,
        false,
        Some(RejectionReason::RetryableSameGeneration),
    );
}

fn send_response(respond: ResponseSender, request_id: &str, accepted: bool, rejection: Option<RejectionReason>) {
    let response = Response {
        version: VERSION.to_owned(),
        request_id: request_id.to_owned(),
        status: if accepted { Status::Accepted } else { Status::Rejected },
        rejection,
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
    use std::sync::Arc;

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
                    rejection: None,
                }
        })
    }

    fn rejected_response(value: serde_json::Value, request_id: &str, reason: RejectionReason) -> bool {
        serde_json::from_value::<Response>(value).is_ok_and(|response| {
            response
                == Response {
                    version: VERSION.to_owned(),
                    request_id: request_id.to_owned(),
                    status: Status::Rejected,
                    rejection: Some(reason),
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
        assert!(rejected_response(
            unbound,
            "receipt-unbound",
            RejectionReason::SessionMismatch
        ));

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
        assert!(rejected_response(
            rejected,
            "receipt-subscriber",
            RejectionReason::RetryableSameGeneration,
        ));

        let mut event_rx = router.event_tx.subscribe();
        let accepted = dispatch(&router, &request.to_string()).await.unwrap().unwrap();
        assert!(accepted_response(accepted, "receipt-subscriber"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));
    }

    #[tokio::test]
    async fn committed_receipt_stays_retryable_during_same_generation_bind_fence() {
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let router = Arc::new(AcpClientExtensionRouter::new(event_tx));
        router.bind_session("session-correction").await.unwrap();
        let generation = router.session_binding_generation().unwrap();
        let request = request("receipt-bind-fence", "session-correction");

        let committed = dispatch(router.as_ref(), &request.to_string()).await.unwrap().unwrap();
        assert!(accepted_response(committed, "receipt-bind-fence"));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            AgentStreamEvent::CorrectionBoundary(_)
        ));

        // Hold an admission so the idempotent prompt-ACK bind publishes its
        // transition fence before it can acquire the writer. A replay in this
        // exact window must preserve the accepted receipt and live FIFO.
        let held_admission = router.session_binding.try_acquire_admission().unwrap();
        let bind_router = Arc::clone(&router);
        let bind = tokio::spawn(async move {
            bind_router
                .bind_session_if_generation("session-correction", generation)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !router.session_binding.transition_pending() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("same-generation bind must publish its transition fence");

        let retry = dispatch(router.as_ref(), &request.to_string()).await.unwrap().unwrap();
        assert!(rejected_response(
            retry,
            "receipt-bind-fence",
            RejectionReason::RetryableSameGeneration,
        ));
        assert_eq!(
            router
                .state
                .lock()
                .unwrap()
                .correction_boundary_receipts
                .get(&("session-correction".to_owned(), "receipt-bind-fence".to_owned()))
                .copied(),
            Some(ReceiptState::Accepted(generation)),
        );
        assert!(event_rx.try_recv().is_err());

        drop(held_admission);
        assert!(bind.await.unwrap().unwrap());
        let replayed = dispatch(router.as_ref(), &request.to_string()).await.unwrap().unwrap();
        assert!(accepted_response(replayed, "receipt-bind-fence"));
        assert!(event_rx.try_recv().is_err());
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
        assert!(rejected_response(
            rejected,
            "receipt-lifecycle",
            RejectionReason::LifecycleChanged,
        ));
        assert!(event_rx.try_recv().is_err());

        router.finish_session_binding(lifecycle, "session-correction").unwrap();
        let rejected_again = dispatch(&router, &lifecycle_request.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(rejected_response(
            rejected_again,
            "receipt-lifecycle",
            RejectionReason::LifecycleChanged,
        ));
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
