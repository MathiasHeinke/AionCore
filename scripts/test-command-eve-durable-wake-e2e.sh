#!/usr/bin/env bash
set -euo pipefail

# Provider-free release gate for the cross-repository Command EVE durable-wake
# contract. This deliberately exercises the pinned Hermes implementation and
# AionCore transport/receipt code without credentials or model/provider calls.

aioncore_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hermes_root="${1:-/Users/mathiasheinke/Developer/.agent-sandboxes/hermes-agent/eve-gl1-acp-durable-work}"
hermes_python="${COMMAND_EVE_HERMES_PYTHON:-/tmp/eve-hermes-gl1-venv/bin/python}"

expected_aioncore_base="8a71ed74238f7ab87471d1b0ccf690ddecc24786"
expected_hermes_commit="c72363fc572a8a72d6b6e23e53b82da5753a1bc9"

if ! git -C "$aioncore_root" merge-base --is-ancestor "$expected_aioncore_base" HEAD; then
  echo "AionCore checkout does not contain required base $expected_aioncore_base" >&2
  exit 1
fi

actual_hermes_commit="$(git -C "$hermes_root" rev-parse HEAD)"
if [[ "$actual_hermes_commit" != "$expected_hermes_commit" ]]; then
  echo "Hermes checkout must be pinned to $expected_hermes_commit (got $actual_hermes_commit)" >&2
  exit 1
fi
if ! git -C "$hermes_root" diff --quiet --ignore-submodules -- \
  || ! git -C "$hermes_root" diff --cached --quiet --ignore-submodules --; then
  echo "Hermes tracked tree must be clean at $expected_hermes_commit" >&2
  exit 1
fi

if [[ ! -x "$hermes_python" ]]; then
  echo "Hermes Python is not executable: $hermes_python" >&2
  exit 1
fi

echo "[1/6] Hermes canonical async-completion contract tests"
(
  cd "$hermes_root"
  HERMES_PYTHON="$hermes_python" scripts/run_tests.sh tests/acp_adapter/test_async_completion.py
)

echo "[2/6] AionCore route-scoped initialize capability tests"
cargo test --manifest-path "$aioncore_root/Cargo.toml" -q -p aionui-ai-agent initialize_request_

echo "[3/6] Real Hermes-to-AionCore Busy -> Retry -> Accepted wire proof"
COMMAND_EVE_HERMES_SOURCE="$hermes_root" \
COMMAND_EVE_HERMES_PYTHON="$hermes_python" \
  cargo test --manifest-path "$aioncore_root/Cargo.toml" -q -p aionui-ai-agent \
  provider_free_ -- --ignored --nocapture

echo "[4/6] Persistent receipt replay and stable-turn-id tests"
cargo test --manifest-path "$aioncore_root/Cargo.toml" -q -p aionui-db \
  busy_retry_reuses_the_atomically_assigned_turn_id

echo "[5/6] Persistent owner-change/crash uncertainty test"
cargo test --manifest-path "$aioncore_root/Cargo.toml" -q -p aionui-db \
  owner_change_after_possible_start_is_durable_unknown_and_never_reruns

echo "[6/6] Real ConversationService follow-up execution tests"
cargo test --manifest-path "$aioncore_root/Cargo.toml" -q -p aionui-conversation \
  project_bound_async_completion_

echo "PASS: provider-free durable-wake contract and persistent receipt gates"
echo "LIMITATION: the cross-language harness does not fake a provider/model follow-up; real ConversationService follow-up execution is covered by step 6."
