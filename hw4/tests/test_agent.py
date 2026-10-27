"""Exercise the agent's two real STDIO MCP connections without an API key."""

import asyncio
import importlib.util
import subprocess
import sys
from contextlib import AsyncExitStack
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastmcp import Client
from google.genai import types
from test_mcp_server import server


AGENT_FILE = Path(__file__).resolve().parents[1] / "agent.py"


@pytest.fixture
def agent():
    """Import the CLI module without running it."""
    spec = importlib.util.spec_from_file_location("security_agent", AGENT_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_mcp_sessions_and_read_only_git_dispatch(agent, monkeypatch, tmp_path) -> None:
    """Connect to both child processes; reject any model-selected Git write."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    monkeypatch.setattr(agent, "REPO_DIR", tmp_path)

    async def check() -> None:
        async with AsyncExitStack() as stack:
            bridge = await agent._connect(stack)
            events = await bridge.call("list_security_events", {"limit": 2})
            assert [event["id"] for event in events] == ["evt-001", "evt-002"]
            groups = await bridge.call("detect_failed_logins", {})
            assert groups[0]["event_ids"] == ["evt-008", "evt-009", "evt-010"]
            status = await bridge.call("git_status", {})
            assert isinstance(status, str) and "branch" in status.lower()
            with pytest.raises(agent.AgentError, match="not authorized"):
                await bridge.call("git_add", {"files": ["."]})
            with pytest.raises(agent.AgentError, match="model-selected paths"):
                await bridge.call("git_status", {"repo_path": str(AGENT_FILE.parent)})

            class ScriptedModels:
                """Drive Gemini's response shape; MCP connections remain real."""

                def __init__(self) -> None:
                    self.turn = 0

                async def generate_content(self, **kwargs):
                    self.turn += 1
                    if self.turn == 1:
                        assert "evt-008" in kwargs["contents"][0].parts[0].text
                        parts = [types.Part.from_function_call(name="git_status", args={})]
                    else:
                        assert kwargs["contents"][-1].parts[0].function_response
                        parts = [types.Part.from_text(
                            text="Three failed logins from 203.0.113.77: evt-008, evt-009, evt-010."
                        )]
                    return types.GenerateContentResponse(candidates=[types.Candidate(
                        content=types.Content(role="model", parts=parts)
                    )])

            scripted = ScriptedModels()
            model = SimpleNamespace(aio=SimpleNamespace(models=scripted))
            answer = await agent._ask("Which IP had repeated failures?", bridge, model)
            assert "evt-010" in answer
            assert scripted.turn == 2

    asyncio.run(check())


def test_gemini_function_list_excludes_writes(agent) -> None:
    """The model cannot request shell, Git write, or report-path tools."""
    exposed = {declaration.name for declaration in agent._function_declarations()}
    assert exposed == {
        "list_security_events", "search_security_events", "get_security_event",
        "detect_failed_logins", "git_status", "git_log",
    }
    assert "save_investigation_report" not in exposed
    assert "git_add" not in exposed


def test_mcp_children_do_not_receive_gemini_key(agent, monkeypatch) -> None:
    """The API key must stay in the agent process, not either MCP subprocess."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-only-placeholder")
    assert "GEMINI_API_KEY" not in agent._child_environment()


def test_agent_saves_report_through_custom_mcp(agent, server, monkeypatch, tmp_path) -> None:
    """Application-selected report names stay under the custom server's directory."""
    monkeypatch.setattr(server, "BASE_DIR", tmp_path)
    monkeypatch.setattr(server, "REPORTS_DIR", tmp_path / "reports")

    async def check() -> None:
        async with Client(server.mcp) as security:
            bridge = agent.McpBridge(security, security)
            bridge.evidence_ids.add("evt-008")
            path = await bridge.save_report("Investigate failed logins", "See evt-008.")
            assert path.startswith("reports/investigation-")
            report = tmp_path / path
            assert report.is_file()
            assert "Evidence IDs returned by MCP tools: evt-008" in report.read_text(encoding="utf-8")

    asyncio.run(check())
