use std::sync::Arc;

use aionui_ai_agent::types::{BuildTaskOptions, SendMessageData, VerifiedAttachmentGrounding};
use aionui_ai_agent::{
    AgentSendError, AgentSessionKind, IWorkerTaskManager, forget_command_eve_prompt_admission,
    reject_command_eve_prompt_admission,
};
use aionui_common::{AgentType, ConversationStatus, ErrorChain, now_ms};
use aionui_db::models::ConversationRow;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::agent_health_policy::{AgentHealthAction, AgentHealthPolicy};
use crate::project_workspace::redact_project_runtime_error;
use crate::runtime_state::RuntimeLifecycleState;
use crate::runtime_state::TurnClaim;
use crate::service::{
    ConversationService, MAX_CRON_CONTINUATIONS_PER_TURN, agent_error_top_level_code, persist_session_key,
};
use crate::stream_relay::{RelayOutcome, StreamRelay, TurnAttemptSummary};
use crate::turn_continuation_policy::{ContinuationDecision, TurnContinuationPolicy};
use crate::turn_recovery_policy::{TurnRecoveryDecision, TurnRecoveryPolicy};
use aionui_api_types::SendMessageRequest;

fn acp_backend_from_build_options(options: &BuildTaskOptions) -> Option<&str> {
    match &options.context.kind {
        AgentSessionKind::Acp(ctx) => ctx.config.backend.as_deref(),
        AgentSessionKind::Aionrs(_) => None,
    }
}

pub(crate) struct TurnStartInput {
    pub user_id: String,
    pub conversation: ConversationRow,
    pub request: SendMessageRequest,
    pub verified_attachment_grounding: Vec<VerifiedAttachmentGrounding>,
    pub build_options: BuildTaskOptions,
    pub stored_workspace: String,
    pub turn_id: String,
    pub turn_claim: TurnClaim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConversationTurnStatus {
    Completed,
    Failed,
}

pub(crate) struct ConversationTurnResult {
    pub status: ConversationTurnStatus,
}

pub(crate) struct ConversationTurnOrchestrator {
    service: ConversationService,
    task_manager: Arc<dyn IWorkerTaskManager>,
}

struct TurnAttemptInput {
    conv_id: String,
    turn_id: String,
    user_id: String,
    build_options: BuildTaskOptions,
    stored_workspace: String,
    send: SendMessageData,
    msg_id: String,
    allowed_skill_names: Vec<String>,
    continuation_count: usize,
    defer_clean_terminal_errors: bool,
}

struct TurnAttemptResult {
    outcome: RelayOutcome,
    summary: TurnAttemptSummary,
    agent_type: AgentType,
    backend: Option<String>,
}

impl ConversationTurnOrchestrator {
    pub fn new(service: ConversationService, task_manager: Arc<dyn IWorkerTaskManager>) -> Self {
        Self { service, task_manager }
    }

    pub fn spawn_user_turn(self, input: TurnStartInput) {
        tokio::spawn(async move {
            let _ = self.run_user_turn(input).await;
        });
    }

    async fn run_attempt(&self, input: TurnAttemptInput) -> Result<TurnAttemptResult, ConversationTurnResult> {
        let build_started_at = now_ms();
        let availability_agent_id = availability_agent_id(&input.build_options);
        let backend = acp_backend_from_build_options(&input.build_options).map(str::to_owned);
        let project_runtime_workspace_path = input
            .build_options
            .project_runtime_context
            .as_ref()
            .map(|_| input.build_options.context.workspace.path.clone());
        info!(
            conversation_id = %input.conv_id,
            turn_id = %input.turn_id,
            "Agent task build started"
        );

        let agent = match self
            .task_manager
            .get_or_build_task(&input.conv_id, input.build_options)
            .await
        {
            Ok(agent) => agent,
            Err(err) => {
                reject_command_eve_prompt_admission(&input.turn_id, "ATTACHMENT_PROMPT_ADMISSION_AGENT_BUILD_FAILED");
                let top_level_code = agent_error_top_level_code(&err);
                let send_error = redact_project_send_error(
                    AgentSendError::from_agent_error_ref_for_backend(&err, backend.as_deref()),
                    project_runtime_workspace_path.as_deref(),
                );
                let top_level_code = if send_error.is_openclaw_gateway_unreachable() {
                    "USER_AGENT_OPENCLAW_GATEWAY_UNREACHABLE"
                } else {
                    top_level_code
                };
                if send_error.is_openclaw_gateway_unreachable() {
                    warn!(
                        conversation_id = %input.conv_id,
                        turn_id = %input.turn_id,
                        backend = "openclaw",
                        error_kind = "openclaw_gateway_unreachable",
                        port = 18789_u16,
                        phase = "turn_build",
                        "OpenClaw Gateway unreachable during ACP startup"
                    );
                }
                let failure_message = availability_failure_message(&send_error);
                if project_runtime_workspace_path.is_some() {
                    error!(
                        conversation_id = %input.conv_id,
                        turn_id = %input.turn_id,
                        error_code = ?send_error.code(),
                        error_detail = %failure_message,
                        "Agent task build failed"
                    );
                } else {
                    error!(
                        conversation_id = %input.conv_id,
                        turn_id = %input.turn_id,
                        error_code = ?send_error.code(),
                        error = %ErrorChain(&err),
                        "Agent task build failed"
                    );
                }
                record_agent_session_failure(
                    &self.service,
                    availability_agent_id.as_deref(),
                    "session_build_failed",
                    &failure_message,
                )
                .await;
                self.service
                    .persist_and_broadcast_send_failure_tip(
                        &input.conv_id,
                        &input.turn_id,
                        &send_error,
                        Some(top_level_code),
                    )
                    .await;
                return Err(ConversationTurnResult {
                    status: ConversationTurnStatus::Failed,
                });
            }
        };

        if let Err(err) = self
            .service
            .maybe_persist_workspace(&input.conv_id, &input.stored_workspace, agent.workspace())
            .await
        {
            reject_command_eve_prompt_admission(&input.turn_id, "ATTACHMENT_PROMPT_ADMISSION_WORKSPACE_PERSIST_FAILED");
            let top_level_code = err.error_code();
            let send_error = AgentSendError::from_agent_error(err.to_agent_error());
            error!(
                conversation_id = %input.conv_id,
                turn_id = %input.turn_id,
                error_code = err.error_code(),
                error = %ErrorChain(&err),
                "Failed to persist resolved workspace"
            );
            self.service
                .persist_and_broadcast_send_failure_tip(
                    &input.conv_id,
                    &input.turn_id,
                    &send_error,
                    Some(top_level_code),
                )
                .await;
            return Err(ConversationTurnResult {
                status: ConversationTurnStatus::Failed,
            });
        }

        info!(
            conversation_id = %input.conv_id,
            turn_id = %input.turn_id,
            agent_type = ?agent.agent_type(),
            elapsed_ms = now_ms().saturating_sub(build_started_at),
            "Agent task ready"
        );

        let persistence = self.service.runtime_persistence();
        let runtime_state = self.service.runtime_state();
        let mut pending_send = Some((input.send, input.msg_id));
        let mut continuation_count = input.continuation_count;
        let continuation_policy = TurnContinuationPolicy::new(MAX_CRON_CONTINUATIONS_PER_TURN);
        let mut last_outcome = None;
        let mut aggregate_summary = TurnAttemptSummary::default();

        while let Some((current_send, msg_id)) = pending_send.take() {
            let lifecycle = runtime_state.lifecycle_for(&input.conv_id);
            let defer_clean_terminal_errors = input.defer_clean_terminal_errors
                && agent.agent_type() == AgentType::Acp
                && lifecycle == RuntimeLifecycleState::Active
                && aggregate_summary.safe_to_auto_replay();
            let relay = StreamRelay::new(
                input.conv_id.clone(),
                msg_id,
                input.turn_id.clone(),
                input.user_id.clone(),
                self.service.conversation_repo().clone(),
                self.service.broadcaster().clone(),
                self.service.current_cron_service(),
            )
            .with_skill_resolver(self.service.skill_resolver())
            .with_allowed_skill_names(input.allowed_skill_names.clone())
            .with_runtime_state(Arc::clone(&runtime_state))
            .with_persistence(persistence.clone())
            .with_project_runtime_redaction(project_runtime_workspace_path.clone())
            .with_turn_completion(false)
            .with_defer_clean_terminal_errors(defer_clean_terminal_errors);

            let rx = agent.subscribe();
            let send_agent = agent.clone();
            let conv_id_send = input.conv_id.clone();
            let turn_id_for_send = input.turn_id.clone();
            let feedback_service = self.service.clone();
            let feedback_agent_id = availability_agent_id.clone();
            let send_project_runtime_workspace_path = project_runtime_workspace_path.clone();
            let (send_error_tx, send_error_rx) = oneshot::channel();

            tokio::spawn(async move {
                if let Err(e) = send_agent.send_message(current_send).await {
                    reject_command_eve_prompt_admission(
                        &turn_id_for_send,
                        "ATTACHMENT_PROMPT_ADMISSION_AGENT_SEND_FAILED",
                    );
                    let e = redact_project_send_error(e, send_project_runtime_workspace_path.as_deref());
                    let failure_message = availability_failure_message(&e);
                    record_agent_session_failure(
                        &feedback_service,
                        feedback_agent_id.as_deref(),
                        "session_send_failed",
                        &failure_message,
                    )
                    .await;
                    let task_status = send_agent.status();
                    let agent_type = send_agent.agent_type();
                    error!(
                        conversation_id = %conv_id_send,
                        turn_id = %turn_id_for_send,
                        ?agent_type,
                        ?task_status,
                        error = %ErrorChain(&e),
                        "Agent send_message failed"
                    );
                    if task_status == Some(ConversationStatus::Finished) {
                        debug!(
                            conversation_id = %conv_id_send,
                            turn_id = %turn_id_for_send,
                            ?agent_type,
                            "Agent send_message failed on finished task; relay will prefer any runtime terminal before fallback"
                        );
                    }
                    warn!(
                        conversation_id = %conv_id_send,
                        turn_id = %turn_id_for_send,
                        ?agent_type,
                        code = ?e.code(),
                        ownership = ?e.ownership(),
                        "Agent send_message returned error; offering fallback stream error to relay"
                    );
                    let _ = send_error_tx.send(e);
                }
            });

            let outcome = relay.consume_with_send_error(rx, send_error_rx).await;
            aggregate_summary.merge(&outcome.attempt);

            if let Some(session_key) = agent.get_session_key() {
                persist_session_key(
                    self.service.conversation_repo(),
                    &persistence,
                    &input.conv_id,
                    &session_key,
                )
                .await;
            }

            match continuation_policy.decide(&input.conv_id, continuation_count, &outcome, lifecycle) {
                ContinuationDecision::Continue { content, next_count } => {
                    continuation_count = next_count;
                    let next_turn_msg_id = ConversationService::mint_msg_id();
                    pending_send = Some((
                        SendMessageData {
                            content,
                            msg_id: next_turn_msg_id.clone(),
                            turn_id: Some(input.turn_id.clone()),
                            files: vec![],
                            verified_attachment_grounding: vec![],
                            inject_skills: vec![],
                        },
                        next_turn_msg_id,
                    ));
                }
                ContinuationDecision::Stop(_) => {
                    last_outcome = Some(outcome);
                    break;
                }
            }
        }

        Ok(TurnAttemptResult {
            outcome: last_outcome.unwrap_or_default(),
            summary: aggregate_summary,
            agent_type: agent.agent_type(),
            backend,
        })
    }

    pub(crate) async fn run_user_turn(self, input: TurnStartInput) -> ConversationTurnResult {
        // Keep the single revalidated project execution permit alive through
        // stream consumption, persistence and turn completion. Mutation uses
        // a non-blocking write permit and therefore stays BUSY until this
        // exact turn hold is released.
        let _project_runtime_execution = input.build_options.project_runtime_execution.clone();
        let mut turn_claim = input.turn_claim;
        let conv_id = input.conversation.id.clone();
        let turn_id = input.turn_id.clone();
        let runtime_state = self.service.runtime_state();
        let allowed_skill_names = input.build_options.context.skills.clone();
        let first_turn_msg_id = ConversationService::mint_msg_id();
        let initial_send = SendMessageData {
            content: input.request.content,
            msg_id: first_turn_msg_id.clone(),
            turn_id: Some(turn_id.clone()),
            files: input.request.files,
            verified_attachment_grounding: input.verified_attachment_grounding,
            inject_skills: input.request.inject_skills,
        };
        let mut replayed = false;
        let mut replay_started_at = None;

        info!(conversation_id = %conv_id, turn_id = %turn_id, "conversation turn orchestrator started");

        let final_failed = loop {
            let attempt_number = if replayed { 2 } else { 1 };
            let attempt_result = match self
                .run_attempt(TurnAttemptInput {
                    conv_id: conv_id.clone(),
                    turn_id: turn_id.clone(),
                    user_id: input.user_id.clone(),
                    build_options: input.build_options.clone(),
                    stored_workspace: input.stored_workspace.clone(),
                    send: initial_send.clone(),
                    msg_id: first_turn_msg_id.clone(),
                    allowed_skill_names: allowed_skill_names.clone(),
                    continuation_count: 0,
                    defer_clean_terminal_errors: !replayed,
                })
                .await
            {
                Ok(result) => result,
                Err(result) => {
                    break result.status == ConversationTurnStatus::Failed;
                }
            };

            let lifecycle = runtime_state.lifecycle_for(&conv_id);
            if !attempt_result.outcome.terminal.is_error() {
                if replayed {
                    info!(
                        conversation_id = %conv_id,
                        turn_id = %turn_id,
                        attempt = attempt_number,
                        elapsed_ms = replay_started_at
                            .map(|started_at| now_ms().saturating_sub(started_at))
                            .unwrap_or_default(),
                        "conversation turn auto replay completed"
                    );
                }
                break false;
            }
            if replayed {
                warn!(
                    conversation_id = %conv_id,
                    turn_id = %turn_id,
                    attempt = attempt_number,
                    error_code = ?attempt_result.outcome.terminal.code(),
                    retryable = ?attempt_result.outcome.terminal.retryable(),
                    "conversation turn auto replay failed"
                );
            }

            let mut recovery_outcome = attempt_result.outcome.clone();
            recovery_outcome.attempt = attempt_result.summary.clone();
            let decision = TurnRecoveryPolicy::decide(
                attempt_result.agent_type,
                attempt_result.backend.as_deref(),
                &recovery_outcome,
                lifecycle,
                replayed,
            );

            match decision {
                TurnRecoveryDecision::AutoReplayOnce { reason, .. } => {
                    replay_started_at = Some(now_ms());
                    info!(
                        conversation_id = %conv_id,
                        turn_id = %turn_id,
                        attempt = attempt_number,
                        next_attempt = attempt_number + 1,
                        backend = attempt_result.backend.as_deref().unwrap_or("unknown"),
                        error_code = ?attempt_result.outcome.terminal.code(),
                        retryable = ?attempt_result.outcome.terminal.retryable(),
                        ?reason,
                        "conversation turn auto replay starting"
                    );
                    self.service
                        .evict_acp_task_after_terminal_error(
                            &conv_id,
                            attempt_result.agent_type,
                            &attempt_result.outcome,
                            &self.task_manager,
                        )
                        .await;
                    replayed = true;
                    continue;
                }
                TurnRecoveryDecision::None => {
                    if attempt_result.outcome.attempt.terminal_error_deferred
                        && let Some(data) = attempt_result.outcome.attempt.terminal_error.clone()
                    {
                        let send_error = AgentSendError::from_stream_error_data(data);
                        self.service
                            .persist_and_broadcast_send_failure_tip(&conv_id, &turn_id, &send_error, None)
                            .await;
                    }

                    match AgentHealthPolicy::decide(attempt_result.agent_type, &attempt_result.outcome, lifecycle) {
                        AgentHealthAction::Keep => {}
                        AgentHealthAction::EvictAcpTask { .. } => {
                            self.service
                                .evict_acp_task_after_terminal_error(
                                    &conv_id,
                                    attempt_result.agent_type,
                                    &attempt_result.outcome,
                                    &self.task_manager,
                                )
                                .await;
                        }
                    }
                    break true;
                }
            }
        };

        if !final_failed {
            record_agent_session_success(&self.service, availability_agent_id(&input.build_options).as_deref()).await;
        }

        let was_deleting = turn_claim.release_for_turn(&turn_id);
        self.service
            .complete_released_turn(&conv_id, &turn_id, was_deleting)
            .await;
        forget_command_eve_prompt_admission(&turn_id);

        ConversationTurnResult {
            status: if final_failed {
                ConversationTurnStatus::Failed
            } else {
                ConversationTurnStatus::Completed
            },
        }
    }
}

fn availability_agent_id(options: &BuildTaskOptions) -> Option<String> {
    match &options.context.kind {
        AgentSessionKind::Acp(context) => context
            .config
            .agent_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        AgentSessionKind::Aionrs(_) => None,
    }
}

fn availability_failure_message(error: &AgentSendError) -> String {
    error
        .stream_error()
        .detail
        .clone()
        .unwrap_or_else(|| error.stream_error().message.clone())
}

fn redact_project_send_error(error: AgentSendError, canonical_workspace_path: Option<&str>) -> AgentSendError {
    match canonical_workspace_path {
        Some(path) => {
            AgentSendError::from_stream_error_data(redact_project_runtime_error(error.stream_error(), Some(path)))
        }
        None => error,
    }
}

async fn record_agent_session_failure(
    service: &ConversationService,
    agent_id: Option<&str>,
    code: &str,
    message: &str,
) {
    let Some(agent_id) = agent_id else {
        return;
    };
    let Some(feedback) = service.agent_availability_feedback() else {
        return;
    };
    if let Err(error) = feedback.record_session_failure(agent_id, code, message).await {
        warn!(
            agent_id,
            code,
            error = %ErrorChain(&error),
            "Failed to record agent availability session failure"
        );
    }
}

async fn record_agent_session_success(service: &ConversationService, agent_id: Option<&str>) {
    let Some(agent_id) = agent_id else {
        return;
    };
    let Some(feedback) = service.agent_availability_feedback() else {
        return;
    };
    if let Err(error) = feedback.record_session_success(agent_id).await {
        warn!(
            agent_id,
            error = %ErrorChain(&error),
            "Failed to record agent availability session success"
        );
    }
}
