"""Public, read-only IsItMe? server — the deployment behind the ChatGPT app.

Only the IT-triage tools are exposed. None of the personal tools (files, shell,
clipboard, Gmail, ...) are registered here, so nothing on the host machine is
reachable through this server.

Safety layers:
  * HOSTED_POLICY  - public IPs only, ports 80/443/8080/8443, IP-pinned connections
  * CallGate       - max concurrent checks + 60 s result cache per target
  * RateLimit      - per-client-IP token bucket on /mcp and /api
  * no auth, no user data stored, no request logging of payloads

Environment variables:
  PORT                         port to listen on (default 8000)
  OPENAI_APPS_CHALLENGE        token served at /.well-known/openai-apps-challenge
  ISITME_TRUST_PROXY=1         use the X-Forwarded-For hop added by your load balancer as the client IP
  ISITME_RATE_PER_MIN          requests per minute per client IP on /mcp (default 600; ChatGPT traffic
                               arrives from a small set of OpenAI egress IPs, so keep this generous)
  ISITME_API_RATE_PER_MIN      requests per minute per client IP on /api/v1/diagnose (default 10)
  ISITME_ALLOWED_HOSTS         optional comma list of Host headers to accept (enables Host checking)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from ._version import __version__
from .netguard import HOSTED_POLICY, TargetError
from .triage.diagnose import diagnose
from .triage.tools import CallGate, build_apps, register_triage_tools

logger = logging.getLogger("personal-mcp.hosted")

INSTRUCTIONS = (
    "IsItMe? diagnoses website and service outages for IT people. Call `diagnose` with the URL whenever the user "
    "says a site or API is down, slow, shows certificate or 5xx errors, or asks whether a problem is on their "
    "side. Use check_dns / check_tls / check_http / check_email_auth / vendor_status for focused follow-ups. "
    "Only public internet services can be checked; private and internal addresses are refused by design."
)

LANDING = """<!doctype html><meta charset=utf-8><title>IsItMe? MCP server</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px}code{background:#f2f2f2;padding:2px 5px;border-radius:4px}</style>
<h1>IsItMe? — outage triage for ChatGPT</h1>
<p>This is the MCP endpoint for the IsItMe? app. Connect an MCP client to <code>/mcp</code>.</p>
<p>Source and docs: <a href="https://github.com/arun250492/Personal-MCP">github.com/arun250492/Personal-MCP</a></p>
<p>Version VERSION</p>"""


class RateLimit:
    """Pure-ASGI per-client token bucket. Lifespan and other scopes pass straight through."""

    def __init__(self, app: Any, *, per_min: int, api_per_min: int, trust_proxy: bool):
        self.app = app
        self.trust_proxy = trust_proxy
        self.rules = {"/mcp": (per_min, max(10, per_min // 4)), "/api/": (api_per_min, max(3, api_per_min // 2))}
        self.buckets: dict[tuple[str, str], tuple[float, float]] = {}
        self.last_sweep = time.monotonic()

    def _client(self, scope: dict[str, Any]) -> str:
        if self.trust_proxy:
            for k, v in scope.get("headers") or []:
                if k == b"x-forwarded-for":
                    # Right-most hop is the one our own load balancer appended; left-most is client-controlled.
                    return v.decode("latin-1").split(",")[-1].strip()
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _allow(self, key: tuple[str, str], rate_per_min: int, burst: int) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.get(key, (float(burst), now))
        tokens = min(burst, tokens + (now - last) * rate_per_min / 60.0)
        if tokens < 1:
            self.buckets[key] = (tokens, now)
            return False
        self.buckets[key] = (tokens - 1, now)
        if now - self.last_sweep > 300:
            self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 600}
            self.last_sweep = now
        return True

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            path = scope.get("path", "")
            for prefix, (rate, burst) in self.rules.items():
                if path.startswith(prefix):
                    if not self._allow((prefix, self._client(scope)), rate, burst):
                        resp = JSONResponse({"error": "Too many requests — slow down and retry in a minute."},
                                            status_code=429, headers={"Retry-After": "30"})
                        await resp(scope, receive, send)
                        return
                    break
        await self.app(scope, receive, send)


def build_server() -> MCPServer:
    gate = CallGate(max_concurrent=int(os.environ.get("ISITME_MAX_CONCURRENT", "16")), cache_ttl=60)
    apps = build_apps(HOSTED_POLICY, local_mode=False, gate=gate)
    server = MCPServer(
        "IsItMe",
        title="IsItMe? Outage Triage",
        version=__version__,
        instructions=INSTRUCTIONS,
        website_url="https://github.com/arun250492/Personal-MCP",
        extensions=[apps],
    )
    register_triage_tools(server, HOSTED_POLICY, local_mode=False, gate=gate)

    @server.custom_route("/", methods=["GET"], include_in_schema=False)
    async def landing(_: Request) -> Response:
        return HTMLResponse(LANDING.replace("VERSION", __version__))

    @server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    @server.custom_route("/.well-known/openai-apps-challenge", methods=["GET"], include_in_schema=False)
    async def challenge(_: Request) -> Response:
        token = os.environ.get("OPENAI_APPS_CHALLENGE", "").strip()
        if not token:
            return PlainTextResponse("not configured", status_code=404)
        return PlainTextResponse(token)

    @server.custom_route("/api/v1/diagnose", methods=["GET"], include_in_schema=False)
    async def api_diagnose(request: Request) -> Response:
        """Plain JSON endpoint used by local installs for diagnose(compare_cloud=true)."""
        url = request.query_params.get("url", "")
        try:
            result = await gate.run(f"diagnose:{url.strip().lower()}", lambda: diagnose(url, HOSTED_POLICY))
        except (TargetError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        keep = ("target", "host", "checked_at", "vantage", "status", "likely_cause", "cause_label", "headline",
                "findings", "fixes", "providers")
        return JSONResponse({k: result.get(k) for k in keep})

    return server


def build_app() -> Any:
    server = build_server()
    allowed = [h.strip() for h in os.environ.get("ISITME_ALLOWED_HOSTS", "").split(",") if h.strip()]
    security = TransportSecuritySettings(allowed_hosts=allowed, allowed_origins=["https://chatgpt.com"]) \
        if allowed else None
    app = server.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0",
                                     transport_security=security, max_request_body_size=256 * 1024)
    return RateLimit(
        app,
        per_min=int(os.environ.get("ISITME_RATE_PER_MIN", "600")),
        api_per_min=int(os.environ.get("ISITME_API_RATE_PER_MIN", "10")),
        trust_proxy=os.environ.get("ISITME_TRUST_PROXY", "").lower() in ("1", "true", "yes"),
    )


def serve(host: str = "0.0.0.0", port: int = 8000) -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    # Tool-failure messages contain the hostname that was checked; keep them out of hosted logs.
    logging.getLogger("mcp.server.mcpserver.server").setLevel(logging.WARNING)
    logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
    logger.info("Starting IsItMe? hosted server %s on %s:%s (read-only triage tools only)", __version__, host, port)
    uvicorn.run(build_app(), host=host, port=port, proxy_headers=False, access_log=False, timeout_keep_alive=30)
