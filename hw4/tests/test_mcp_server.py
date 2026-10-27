"""Validate the fixture, registered tools, and local STDIO transport."""

import json
import asyncio
import importlib.util
import sys
from datetime import datetime
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.transports import PythonStdioTransport


SAMPLE_EVENTS = Path(__file__).resolve().parents[1] / "data" / "sample_events.json"


@pytest.fixture
def server():
    """Import the hyphenated server filename without starting its transport."""
    spec = importlib.util.spec_from_file_location("security_mcp_server", SAMPLE_EVENTS.parents[1] / "mcp-server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_events_have_required_fields_and_unique_ids() -> None:
    """The shared synthetic fixture must have valid, individually traceable events."""
    events = json.loads(SAMPLE_EVENTS.read_text(encoding="utf-8"))
    assert isinstance(events, list)
    assert len(events) >= 20
    required = {"id", "timestamp", "username", "ip_address", "event_type"}
    ids: set[str] = set()
    for event in events:
        assert required <= event.keys()
        assert all(isinstance(event[key], str) and event[key].strip() for key in required)
        assert event["id"] not in ids
        ids.add(event["id"])
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        assert timestamp.utcoffset() is not None


def test_mcp_tools_filter_events(server) -> None:
    """Exercise registered tools through an actual MCP client."""
    async def check() -> None:
        async with Client(server.mcp) as client:
            assert len((await client.call_tool("list_security_events", {})).data) == 20
            assert len((await client.call_tool("list_security_events", {"limit": 100})).data) == 24
            for filters, expected in [
                ({"username": "alex_demo"}, 3),
                ({"ip_address": "203.0.113.77"}, 7),
                ({"event_type": "login_failure"}, 8),
                ({"username": "admin_demo", "event_type": "login_failure"}, 3),
                ({"username": "missing"}, 0),
            ]:
                assert len((await client.call_tool("search_security_events", filters)).data) == expected
            found = await client.call_tool("get_security_event", {"event_id": "evt-019"})
            assert found.structured_content["result"]["event_type"] == "login_success"
            assert (await client.call_tool("get_security_event", {"event_id": "missing"})).structured_content["result"] is None
            groups = (await client.call_tool("detect_failed_logins", {})).data
            assert len(groups) == 1
            assert groups[0]["username"] == "admin_demo"
            assert groups[0]["count"] == 3
            assert groups[0]["event_ids"] == ["evt-008", "evt-009", "evt-010"]
            assert (await client.call_tool("detect_failed_logins", {"threshold": 4})).data == []
    asyncio.run(check())


def test_mcp_server_exposes_tool_contracts() -> None:
    """Initialize a real STDIO client and check tools against the JSON fixture."""
    events = json.loads(SAMPLE_EVENTS.read_text(encoding="utf-8"))
    expected_failures = [
        event for event in events
        if event["event_type"] == "login_failure"
        and event["ip_address"] == "203.0.113.77"
        and event["username"] == "admin_demo"
    ]
    assert len(expected_failures) == 3

    async def check() -> None:
        transport = PythonStdioTransport(
            script_path=str(SAMPLE_EVENTS.parents[1] / "mcp-server.py"),
            python_cmd=sys.executable,
            cwd=str(SAMPLE_EVENTS.parents[1]),
        )
        async with Client(transport) as client:
            assert await client.ping()  # The context manager initialized the MCP session.
            tools = await client.list_tools()
            assert {tool.name for tool in tools} == {
                "list_security_events", "search_security_events", "get_security_event",
                "detect_failed_logins", "save_investigation_report",
            }
            listed = (await client.call_tool("list_security_events", {"limit": 3})).structured_content["result"]
            assert listed == events[:3]

            groups = (await client.call_tool("detect_failed_logins", {
                "window_minutes": 5, "threshold": 3,
            })).structured_content["result"]
            assert groups == [{
                "ip_address": "203.0.113.77",
                "username": "admin_demo",
                "count": len(expected_failures),
                "first_timestamp": expected_failures[0]["timestamp"],
                "last_timestamp": expected_failures[-1]["timestamp"],
                "event_ids": [event["id"] for event in expected_failures],
            }]
    asyncio.run(check())


def test_failed_login_window_boundary(server, monkeypatch, tmp_path) -> None:
    """Include exact boundaries, sort timestamps, and keep IP/user groups separate."""
    original = json.loads(SAMPLE_EVENTS.read_text(encoding="utf-8"))[7]
    events = []
    for index, timestamp in enumerate(("09:05:01", "09:00:00", "09:05:00")):
        events.append({**original, "id": f"boundary-{index}", "timestamp": f"2026-10-20T{timestamp}Z"})
    events.append({**events[0], "id": "other-user", "username": "other_demo"})
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    monkeypatch.setattr(server, "EVENTS_FILE", path)
    result = server.detect_failed_logins(window_minutes=5, threshold=2)
    assert len(result) == 1
    assert result[0]["event_ids"] == ["boundary-1", "boundary-2"]
