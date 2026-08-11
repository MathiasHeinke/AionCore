#!/usr/bin/env python3
"""Provider-free Hermes ACP fixture for the Command EVE durable-wake gate.

The fixture imports the pinned Hermes checkout supplied by the caller and runs
its real ACP server, durable async-delegation registry, completion queue, and
Command EVE completion pump.  Only the model-facing conversation call is
replaced with a deterministic local response, so the gate never needs an API
key or provider account.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import threading
import time


HERMES_SOURCE = Path(os.environ["COMMAND_EVE_HERMES_SOURCE"]).resolve()
TRACE_FILE = Path(os.environ["COMMAND_EVE_HARNESS_TRACE_FILE"]).resolve()
sys.path.insert(0, str(HERMES_SOURCE))

for key in (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
):
    os.environ.pop(key, None)

import acp  # noqa: E402
from acp_adapter.server import HermesACPAgent  # noqa: E402
from acp_adapter.session import SessionManager  # noqa: E402
from tools.async_delegation import (  # noqa: E402
    dispatch_async_delegation,
    get_durable_delegation,
)


class _NoopSessionDb:
    def get_session(self, *_args, **_kwargs):
        return None

    def create_session(self, *_args, **_kwargs):
        return None

    def update_session_meta(self, *_args, **_kwargs):
        return None

    def replace_messages(self, *_args, **_kwargs):
        return None

    def search_sessions(self, *_args, **_kwargs):
        return []

    def delete_session(self, *_args, **_kwargs):
        return None


class _ProviderFreeAgent:
    model = "provider-free"
    provider = "provider-free"
    base_url = None
    api_mode = "provider-free"
    enabled_toolsets = ["hermes-acp"]
    disabled_toolsets = []
    tools = []
    valid_tool_names: set[str] = set()
    _supports_active_turn_redirect = True

    def __init__(self) -> None:
        self._dispatch_lock = threading.Lock()
        self._dispatched = False

    def run_conversation(
        self,
        *,
        user_message: str,
        conversation_history: list[dict],
        task_id: str,
        **_kwargs,
    ) -> dict:
        if "TRIGGER_PROVIDER_FREE_DURABLE_WAKE" in user_message:
            with self._dispatch_lock:
                if not self._dispatched:
                    self._dispatched = True
                    result = dispatch_async_delegation(
                        goal="Provider-free durable wake proof",
                        context="No provider or model call is permitted.",
                        toolsets=None,
                        role="test-worker",
                        model="provider-free",
                        session_key=task_id,
                        parent_session_id=task_id,
                        origin_ui_session_id=task_id,
                        origin_session_id=task_id,
                        runner=lambda: {
                            "status": "completed",
                            "summary": "PROVIDER_FREE_WORKER_DONE",
                            "model": "provider-free",
                            "api_calls": 0,
                            "duration_seconds": 0.0,
                        },
                    )
                    if result.get("status") != "dispatched":
                        raise RuntimeError(f"provider-free delegation rejected: {result}")
                    if os.environ.get("COMMAND_EVE_HARNESS_WAIT_FOR_DURABLE") == "1":
                        delegation_id = str(result.get("delegation_id") or "")
                        deadline = time.monotonic() + 5.0
                        while time.monotonic() < deadline:
                            durable = get_durable_delegation(delegation_id)
                            if (
                                durable is not None
                                and durable.get("state") != "running"
                                and durable.get("delivery_state") == "pending"
                            ):
                                break
                            time.sleep(0.01)
                        else:
                            raise RuntimeError(
                                f"provider-free completion was not durably pending: {delegation_id}"
                            )

        messages = list(conversation_history or [])
        messages.append({"role": "user", "content": user_message})
        final = "PROVIDER_FREE_PROMPT_ACK"
        messages.append({"role": "assistant", "content": final})
        return {"final_response": final, "messages": messages}


class _TracingRawConnection:
    def __init__(self, inner) -> None:
        self._inner = inner

    async def send_request(self, method, params):
        response = await self._inner.send_request(method, params)
        if method == "_command_eve/async_completion":
            TRACE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with TRACE_FILE.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"method": method, "params": params, "response": response},
                        sort_keys=True,
                        default=str,
                    )
                    + "\n"
                )
        return response

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _TracingHermesAgent(HermesACPAgent):
    def on_connect(self, conn) -> None:
        super().on_connect(conn)
        conn._conn = _TracingRawConnection(conn._conn)

    async def load_session(self, *, cwd, session_id, mcp_servers=None, **kwargs):
        delay_ms = int(os.environ.get("COMMAND_EVE_HARNESS_LOAD_DELAY_MS", "0"))
        if delay_ms > 0:
            # Restore through Hermes' real SessionManager first, then hold the
            # ACP load response open so the real completion pump deterministically
            # exercises the client's pre-bind startup window.
            if self.session_manager.update_cwd(session_id, cwd) is None:
                return await super().load_session(
                    cwd=cwd,
                    session_id=session_id,
                    mcp_servers=mcp_servers,
                    **kwargs,
                )
            await asyncio.sleep(delay_ms / 1000.0)
        return await super().load_session(
            cwd=cwd,
            session_id=session_id,
            mcp_servers=mcp_servers,
            **kwargs,
        )


def main() -> None:
    TRACE_FILE.unlink(missing_ok=True)
    persistent_sessions = os.environ.get("COMMAND_EVE_HARNESS_PERSIST_SESSIONS") == "1"
    manager = SessionManager(
        agent_factory=lambda **_kwargs: _ProviderFreeAgent(),
        db=None if persistent_sessions else _NoopSessionDb(),
    )
    agent = _TracingHermesAgent(session_manager=manager)
    asyncio.run(acp.run_agent(agent, use_unstable_protocol=True))


if __name__ == "__main__":
    main()
