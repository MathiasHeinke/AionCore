# Command EVE 1.820 C7 Runtime Authority — V2 Review Receipt

Status: `READY_FOR_ROOT_REVIEW_V2`, not release-ready.

## Identity

- Worktree: `/Users/mathiasheinke/Developer/.agent-sandboxes/aioncore/eve-1820-authority-runtime`
- Branch: `codex/command-eve-1820-authority-runtime`
- Base and current HEAD: `03abab408255a053b3230445829ae58eaa127578`
- Commit/push/package/release actions: none

## V2 blocker closure

- P1-A: Policy changes enter pending state and revoke router authority under the same linearization lock before any asynchronous Hermes protocol call. Old policy, grants and pending cards cannot produce a side effect while the transport acknowledgement is outstanding or fails.
- P1-B: Every Hermes real config option with `category=Mode` is routed to AionCore policy plus `session/set_mode(default)`. Hermes never receives `session/set_config_option(..., dont_ask)` for that lane. Persisted real-config intent is migrated before reconcile; non-Hermes behavior remains unchanged.
- P1-C: Exact-session grants are revalidated under `policy_linearization` immediately before forwarding. Expired or mismatched grants fall back to one visible Ask card with zero automatic side effects.
- P2: An acknowledged AionCore policy plus the pinned Hermes transport mode `default` is treated as reconciled, preventing endless SetMode drift.
- Edge hardening: same-mode retries still create a fresh pending revision; unsupported modes revoke old authority; transport updates cannot republish an older acknowledgement while a newer policy is pending.

## Verification

- Focused permission suite: 70 passed, 0 failed.
- Final full `cargo test -p aionui-ai-agent -q`: 653 unit tests passed; integration binaries executed 31 passed, 0 failed, 12 ignored.
- `cargo check -p aionui-ai-agent -p aionui-conversation -p aionui-team -p aionui-app`: pass.
- `cargo clippy -p aionui-ai-agent -p aionui-conversation -p aionui-team -p aionui-app --lib -- -D warnings`: pass.
- `cargo fmt --all -- --check`: pass.
- `git diff --check`: pass.
- GitNexus final `list_repos` and `detect_changes(scope=all)` retries: unavailable with `Transport closed`. The last valid pre-V2 scan classified the existing C7 diff as CRITICAL: 24 files, 207 symbols and 23 execution flows. This receipt does not claim a fresh final GitNexus PASS.

## Dirty worktree inventory

Tracked modifications:

- `crates/aionui-ai-agent/src/agent_task.rs`
- `crates/aionui-ai-agent/src/capability/backend_protocol_sink.rs`
- `crates/aionui-ai-agent/src/manager/acp/agent.rs`
- `crates/aionui-ai-agent/src/manager/acp/agent_event_tracker.rs`
- `crates/aionui-ai-agent/src/manager/acp/agent_reconcile.rs`
- `crates/aionui-ai-agent/src/manager/acp/agent_session_flow.rs`
- `crates/aionui-ai-agent/src/manager/acp/mod.rs`
- `crates/aionui-ai-agent/src/manager/acp/permission_router.rs`
- `crates/aionui-ai-agent/src/manager/acp/session.rs`
- `crates/aionui-ai-agent/src/manager/acp/session_tests.rs`
- `crates/aionui-ai-agent/src/protocol/events/mod.rs`
- `crates/aionui-ai-agent/src/protocol/events/permission.rs`
- `crates/aionui-api-types/src/confirmation.rs`
- `crates/aionui-app/tests/agent_integration_e2e.rs`
- `crates/aionui-auth/src/lib.rs`
- `crates/aionui-auth/src/middleware.rs`
- `crates/aionui-auth/tests/middleware_tests.rs`
- `crates/aionui-common/src/lib.rs`
- `crates/aionui-common/src/types.rs`
- `crates/aionui-conversation/src/routes.rs`
- `crates/aionui-conversation/src/service.rs`
- `crates/aionui-conversation/src/service_test.rs`
- `crates/aionui-conversation/src/stream_relay.rs`
- `crates/aionui-team/tests/session_service_integration.rs`

New files:

- `crates/aionui-ai-agent/src/manager/acp/permission_authority.rs`
- `crates/aionui-ai-agent/src/manager/acp/permission_authority_tests.rs`
- `crates/aionui-ai-agent/src/manager/acp/permission_router_c7_tests.rs`
- `reports/command-eve/2026-07-27/1820/c7-runtime-authority-v2-review.md`

## Residual release blockers

- No signed packaged application or GUI packaged E2E was produced by this worker.
- No private updater canary, notarization, public R2 upload or public canary was performed.
- Root still needs integration review against the desktop permission UI and its current AionCore bundle boundary.
- The final GitNexus change scan must be retried when its MCP transport is available.
