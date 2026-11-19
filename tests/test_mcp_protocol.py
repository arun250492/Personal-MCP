"""End-to-end MCP tests: in-process, streamable HTTP (the production app) and stdio."""

import json
import socket
import sys
import threading
import time

import httpx
import pytest
import uvicorn
from mcp.client.client import Client

from personal_mcp.hosted import build_app, build_server
from personal_mcp.triage.tools import WIDGET_URI

SAFE_TOOLS = {"diagnose", "check_dns", "check_tls", "check_http", "check_email_auth", "vendor_status"}


async def test_hosted_exposes_only_safe_tools():
    async with Client(build_server()) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert set(tools) == SAFE_TOOLS
        for t in tools.values():
            assert t.annotations.read_only_hint is True and t.annotations.destructive_hint is False
        d = tools["diagnose"]
        assert d.meta["ui"]["resourceUri"] == WIDGET_URI
        assert d.meta["openai/outputTemplate"] == WIDGET_URI
        res = await c.read_resource(WIDGET_URI)
        assert res.contents[0].mime_type == "text/html;profile=mcp-app"
        assert "ui/initialize" in res.contents[0].text


@pytest.mark.parametrize("tool,args", [
    ("diagnose", {"url": "http://169.254.169.254/latest/meta-data/"}),
    ("diagnose", {"url": "http://127.1:8080/"}),
    ("check_tls", {"url": "https://10.0.0.1"}),
    ("check_http", {"url": "http://localhost/"}),
    ("check_dns", {"name": "db.internal"}),
    ("check_email_auth", {"domain": "192.168.0.1"}),
    ("vendor_status", {"vendors": ["not-a-vendor"]}),
])
async def test_hosted_refuses_unsafe_targets(tool, args):
    async with Client(build_server()) as c:
        r = await c.call_tool(tool, args)
        assert r.is_error
        text = r.content[0].text.lower()
        assert "private" in text or "internal" in text or "unknown vendor" in text or "ip address" in text, text


async def test_local_server_has_personal_and_triage_tools():
    import personal_mcp
    async with Client(personal_mcp.mcp) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert SAFE_TOOLS <= names
    assert {"run_command", "gmail_send", "read_file", "calendar_today"} <= names
    assert len(names) == 39


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def hosted_http(monkeypatch):
    monkeypatch.setenv("OPENAI_APPS_CHALLENGE", "test-token-123")
    monkeypatch.setenv("ISITME_API_RATE_PER_MIN", "4")
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(build_app(), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(5)


async def test_hosted_over_streamable_http(hosted_http):
    async with Client(f"{hosted_http}/mcp") as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert tools == SAFE_TOOLS
        r = await c.call_tool("diagnose", {"url": "http://10.1.2.3/"})
        assert r.is_error and "private" in r.content[0].text


async def test_hosted_routes_and_rate_limit(hosted_http):
    async with httpx.AsyncClient() as h:
        assert (await h.get(f"{hosted_http}/healthz")).json()["status"] == "ok"
        ch = await h.get(f"{hosted_http}/.well-known/openai-apps-challenge")
        assert ch.status_code == 200 and ch.text == "test-token-123"
        assert "IsItMe" in (await h.get(f"{hosted_http}/")).text
        r = await h.get(f"{hosted_http}/api/v1/diagnose", params={"url": "http://192.168.1.1"})
        assert r.status_code == 400 and "private" in r.json()["error"]
        codes = [(await h.get(f"{hosted_http}/api/v1/diagnose", params={"url": "http://10.0.0.1"})).status_code
                 for _ in range(6)]
        assert 429 in codes


async def test_stdio_entry_point():
    from mcp import StdioServerParameters
    params = StdioServerParameters(command=sys.executable, args=["-m", "personal_mcp"],
                                   env={"PERSONAL_MCP_SAFE_MODE": "1", "PATH": "/usr/bin:/bin"})
    async with Client(params) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        r = await c.call_tool("calculate", {"expression": "6*7"})
    assert SAFE_TOOLS <= names
    assert not ({"run_command", "delete_file", "gmail_send", "twitter_post", "kill_process"} & names)  # safe mode
    assert json.loads(r.content[0].text)["result"] == 42
