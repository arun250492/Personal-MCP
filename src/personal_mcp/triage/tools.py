"""MCP tool registration for the triage toolset (shared by local and hosted modes)."""

from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from importlib import resources
from typing import Annotated, Any, Awaitable, Callable

from pydantic import Field

from mcp.server.apps import Apps
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from ..netguard import NetPolicy, TargetError
from .diagnose import diagnose, diagnose_text
from .dns import check_dns
from .email_auth import check_email_auth
from .http_check import check_http
from .tls import check_tls
from .vendors import VENDORS, vendor_status, vendor_text

WIDGET_URI = "ui://isitme/verdict-v1.html"

Url = Annotated[str, Field(description="Website or API address, e.g. 'example.com' or 'https://api.example.com/health'.",
                           max_length=2048)]
Domain = Annotated[str, Field(description="Domain name, e.g. 'example.com'. A URL or e-mail address is also accepted.",
                              max_length=255)]

READ_ONLY = dict(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def widget_html() -> str:
    return resources.files("personal_mcp").joinpath("widget/verdict.html").read_text(encoding="utf-8")


class CallGate:
    """Concurrency limit + short-lived result cache, so repeated checks of the same
    target don't hammer it (and the server can't be used as a traffic amplifier)."""

    def __init__(self, max_concurrent: int, cache_ttl: float, max_entries: int = 500):
        self._sem = asyncio.Semaphore(max_concurrent)
        self._ttl = cache_ttl
        self._max = max_entries
        self._cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()

    async def run(self, key: str, fn: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
        if self._ttl:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self._ttl:
                return hit[1]
        async with self._sem:
            result = await fn()
        if self._ttl:
            self._cache[key] = (time.monotonic(), result)
            self._cache.move_to_end(key)
            while len(self._cache) > self._max:
                self._cache.popitem(last=False)
        return result


def _result(text: str, data: dict[str, Any]) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], structuredContent=data)


async def _guarded(gate: CallGate, key: str, fn: Callable[[], Awaitable[dict[str, Any]]]) -> dict[str, Any]:
    try:
        return await gate.run(key, fn)
    except (TargetError, ValueError) as exc:
        raise ToolError(str(exc)) from None
    except (asyncio.TimeoutError, TimeoutError):
        raise ToolError("The check timed out. The target may be very slow or dropping traffic.") from None


def build_apps(policy: NetPolicy, *, local_mode: bool, gate: CallGate) -> Apps:
    """The UI-bound `diagnose` tool + its verdict-card resource."""
    apps = Apps()
    meta = {
        "openai/outputTemplate": WIDGET_URI,
        "openai/toolInvocation/invoking": "Checking DNS, TLS, HTTP and provider status…",
        "openai/toolInvocation/invoked": "Diagnosis ready",
    }
    description = (
        "Diagnose why a website, API or online service is down or failing, and decide whether the problem is on "
        "the site's side, at an upstream provider (AWS, Azure, Google Cloud, Cloudflare, GitHub, Vercel, ...), "
        "or on the user's side. Runs live DNS, TLS-certificate and HTTP checks against the URL, detects the "
        "hosting/CDN provider and checks that provider's public status page. Returns a verdict (ok / degraded / "
        "down), the likely cause, each finding, suggested fixes and a ticket-ready summary. Use this when the user "
        "says a site 'is down', 'won't load', shows certificate or 5xx errors, or asks 'is it just me?'."
    )
    annotations = ToolAnnotations(title="Diagnose a website outage", **READ_ONLY)

    if local_mode:
        @apps.tool(resource_uri=WIDGET_URI, meta=meta, name="diagnose", description=description +
                   " In local mode checks run from this computer; set compare_cloud=true to also run them from the "
                   "internet (needs PERSONAL_MCP_CLOUD_URL).", annotations=annotations)
        async def diagnose_local(url: Url, compare_cloud: Annotated[bool, Field(description="Also run the checks from the hosted cloud checker and compare.")] = False) -> CallToolResult:
            r = await _guarded(gate, f"diagnose:{url}:{compare_cloud}",
                               lambda: diagnose(url, policy, local_mode=True, compare_cloud=compare_cloud))
            return _result(diagnose_text(r), r)
    else:
        @apps.tool(resource_uri=WIDGET_URI, meta=meta, name="diagnose", description=description,
                   annotations=annotations)
        async def diagnose_hosted(url: Url) -> CallToolResult:
            r = await _guarded(gate, f"diagnose:{url.strip().lower()}", lambda: diagnose(url, policy))
            return _result(diagnose_text(r), r)

    apps.add_html_resource(
        WIDGET_URI, widget_html(), name="isitme-verdict", title="IsItMe verdict card",
        description="Renders the outage diagnosis verdict.", prefers_border=True,
    )
    return apps


def register_triage_tools(server: MCPServer, policy: NetPolicy, *, local_mode: bool, gate: CallGate) -> None:
    """Data tools (no UI). `diagnose` is registered through :func:`build_apps`."""

    async def check_dns_tool(name: Domain, record_types: Annotated[list[str] | None, Field(description="Record types, e.g. ['A','MX','TXT']. Default A, AAAA, CNAME.", max_length=8)] = None) -> CallToolResult:
        r = await _guarded(gate, f"dns:{name}:{record_types}",
                           lambda: check_dns(name, policy, record_types, include_system=local_mode))
        return _result(r["summary"], r)

    async def check_tls_tool(url: Url) -> CallToolResult:
        r = await _guarded(gate, f"tls:{url}", lambda: check_tls(url, policy))
        return _result(r["summary"], r)

    async def check_http_tool(url: Url) -> CallToolResult:
        r = await _guarded(gate, f"http:{url}", lambda: check_http(url, policy))
        return _result(r["summary"], r)

    async def check_email_auth_tool(domain: Domain, dkim_selectors: Annotated[list[str] | None, Field(description="Extra DKIM selectors to try (the s= value in a DKIM-Signature header).", max_length=5)] = None) -> CallToolResult:
        r = await _guarded(gate, f"email:{domain}:{dkim_selectors}",
                           lambda: check_email_auth(domain, policy, dkim_selectors))
        return _result(r["summary"], r)

    async def vendor_status_tool(vendors: Annotated[list[str], Field(description="Vendor names, e.g. ['aws', 'github', 'microsoft365'].", min_length=1, max_length=10)]) -> CallToolResult:
        if not vendors:
            raise ToolError("Pass at least one vendor, e.g. ['aws', 'github'].")
        if len(vendors) > 10:
            raise ToolError("At most 10 vendors per call.")

        async def run() -> dict[str, Any]:
            return {"vendors": await vendor_status(vendors, policy)}

        r = await _guarded(gate, f"vendors:{json.dumps(sorted(vendors))}", run)
        return _result(vendor_text(r["vendors"]), r)

    known = ", ".join(sorted(VENDORS))
    tools: list[tuple[Callable[..., Any], str, str, str]] = [
        (check_dns_tool, "check_dns", "Check DNS records",
         "Look up DNS records for a domain using several public resolvers (Google, Cloudflare"
         + (" and this computer's own resolver" if local_mode else "")
         + ") and flag NXDOMAIN, missing records, inconsistent answers and propagation issues. "
         "record_types defaults to A, AAAA and CNAME; also supports MX, TXT, NS, CAA and SOA."),
        (check_tls_tool, "check_tls", "Check TLS certificate",
         "Inspect a site's TLS/SSL certificate: expiry date and days left, whether it matches the hostname, "
         "issuer, trust chain and TLS protocol version. Use for 'certificate expired', 'not secure' or "
         "'NET::ERR_CERT' errors."),
        (check_http_tool, "check_http", "Check HTTP response",
         "Request a URL and report the HTTP status, redirect chain, response time and identifying server/CDN "
         "headers, with an explanation of error codes such as 502, 503, 504 and Cloudflare 52x."),
        (check_email_auth_tool, "check_email_auth", "Check e-mail authentication",
         "Check a domain's e-mail deliverability setup: MX records, SPF (syntax, -all/~all, 10-lookup limit), "
         "DMARC policy and DKIM keys under common selectors. Use when mail goes to spam, bounces, or for a "
         "security review. Optionally pass dkim_selectors from a DKIM-Signature header (s=...)."),
        (vendor_status_tool, "vendor_status", "Check cloud/SaaS status pages",
         f"Get the current public status and active incidents for cloud and SaaS providers. Known vendors: {known}. "
         "Common aliases work (e.g. 'office365', 'teams', 'cloudfront')."),
    ]
    for fn, name, title, desc in tools:
        server.add_tool(fn, name=name, title=title, description=desc,
                        annotations=ToolAnnotations(title=title, **READ_ONLY))
