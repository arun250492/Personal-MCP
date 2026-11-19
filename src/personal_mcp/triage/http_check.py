"""HTTP reachability check with redirect following and IP pinning."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

import httpx

from ..netguard import NetPolicy, Target, TargetError, format_host_for_url, parse_target, resolve_checked
from .common import USER_AGENT, finding, ssl_context, text_report, worst

# Response headers worth keeping: they identify CDNs/hosts and help explain errors.
INTERESTING_HEADERS = (
    "server", "via", "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid",
    "x-azure-ref", "x-msedge-ref", "x-vercel-id", "x-nf-request-id", "x-github-request-id",
    "x-served-by", "x-cache", "x-powered-by", "content-type", "location", "retry-after",
    "strict-transport-security", "x-goog-generation", "x-cloud-trace-context", "fly-request-id",
    "x-render-origin-server", "x-railway-request-id",
)

MAX_REDIRECTS = 5


async def _fetch_once(target: Target, policy: NetPolicy, ip: str, verify: bool) -> dict[str, Any]:
    url = f"{target.scheme}://{format_host_for_url(ip)}:{target.port}{target.path}"
    headers = {"Host": target.host_header, "User-Agent": USER_AGENT, "Accept": "*/*"}
    extensions: dict[str, Any] = {}
    if target.scheme == "https":
        extensions["sni_hostname"] = target.host
    verify_arg: Any = ssl_context(policy, verify=verify) if target.scheme == "https" else False
    timeout = httpx.Timeout(policy.total_timeout, connect=policy.connect_timeout)
    t0 = time.perf_counter()
    async with httpx.AsyncClient(verify=verify_arg, timeout=timeout, follow_redirects=False,
                                 trust_env=policy.trust_env) as client:
        async with client.stream("GET", url, headers=headers, extensions=extensions) as resp:
            ttfb = time.perf_counter() - t0
            return {
                "url": target.url,
                "ip": ip,
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "http_version": resp.http_version,
                "elapsed_ms": round(ttfb * 1000),
                "headers": {k: v[:300] for k, v in resp.headers.items() if k.lower() in INTERESTING_HEADERS},
            }


async def probe_http(target: Target, policy: NetPolicy) -> dict[str, Any]:
    hops: list[dict[str, Any]] = []
    out: dict[str, Any] = {"start_url": target.url, "hops": hops}
    current = target
    for _ in range(MAX_REDIRECTS + 1):
        try:
            ips = await resolve_checked(current.host, current.port, policy)
        except TargetError as exc:
            out["error"] = str(exc)
            out["error_kind"] = "blocked" if "private" in str(exc) or "internal" in str(exc) else "dns"
            return out
        ip = ips[0]
        try:
            hop = await _fetch_once(current, policy, ip, verify=True)
        except httpx.ConnectError as exc:
            msg = str(exc) or exc.__class__.__name__
            if current.scheme == "https" and ("CERTIFICATE" in msg.upper() or "SSL" in msg.upper()):
                out["tls_error"] = msg
                try:
                    hop = await _fetch_once(current, policy, ip, verify=False)
                    hop["insecure"] = True
                except httpx.HTTPError as exc2:
                    out.update(error=str(exc2) or exc2.__class__.__name__, error_kind="connect", ip=ip)
                    return out
            else:
                out.update(error=msg, error_kind="connect", ip=ip)
                return out
        except httpx.TimeoutException as exc:
            out.update(error=f"Timed out ({exc.__class__.__name__})", error_kind="timeout", ip=ip)
            return out
        except httpx.HTTPError as exc:
            out.update(error=str(exc) or exc.__class__.__name__, error_kind="protocol", ip=ip)
            return out
        hops.append(hop)
        loc = hop["headers"].get("location")
        if hop["status_code"] in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(current.url, loc)
            try:
                current = parse_target(nxt, policy)
            except TargetError as exc:
                out.update(error=f"Redirects to {nxt}, which is not allowed: {exc}", error_kind="blocked")
                return out
            continue
        break
    else:
        out.update(error=f"More than {MAX_REDIRECTS} redirects", error_kind="redirect_loop")
    if hops:
        out["final"] = hops[-1]
    return out


def evaluate_http(info: dict[str, Any]) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []
    kind = info.get("error_kind")
    if kind == "connect":
        f.append(finding("http", "fail", "Server refused or dropped the connection", info.get("error", ""),
                         "Check the server/process is running, the port is open and no firewall/security group blocks it."))
    elif kind == "timeout":
        f.append(finding("http", "fail", "Server did not respond in time", info.get("error", ""),
                         "The origin is overloaded, hung, or traffic is being silently dropped by a firewall."))
    elif kind == "redirect_loop":
        f.append(finding("http", "fail", "Redirect loop", info.get("error", ""),
                         "Check HTTP→HTTPS and www/non-www rules; a CDN set to 'Flexible SSL' often causes this."))
    elif kind in ("blocked", "dns", "protocol"):
        f.append(finding("http", "fail", "HTTP request failed", info.get("error", "")))
    final = info.get("final")
    if final:
        code = final["status_code"]
        hops = len(info["hops"]) - 1
        via = f" after {hops} redirect(s)" if hops else ""
        label = f"HTTP {code} {final.get('reason', '')}".strip()
        if code >= 500:
            hint = {
                502: "The proxy/CDN could not reach your origin server (origin down or wrong upstream).",
                503: "The service is unavailable - overloaded, in maintenance, or no healthy backends.",
                504: "The proxy/CDN timed out waiting for your origin.",
                521: "Cloudflare could not connect to your origin (origin web server is down).",
                522: "Cloudflare timed out connecting to your origin.",
                523: "Cloudflare cannot reach the origin (bad DNS/IP at origin).",
                525: "TLS handshake between Cloudflare and your origin failed.",
                526: "Your origin's certificate is invalid (Cloudflare Full-Strict).",
            }.get(code, "The server hit an internal error. Check application logs.")
            f.append(finding("http", "fail", f"{label}{via}", final["url"], hint))
        elif code in (401, 403):
            f.append(finding("http", "info", f"{label}{via}",
                             "The server is up but requires sign-in or blocks automated requests.",
                             "If real users are blocked too, check WAF/bot rules and IP allow-lists."))
        elif code == 404:
            f.append(finding("http", "warn", f"{label}{via}", final["url"], "The server is up but this path does not exist."))
        elif code == 429:
            f.append(finding("http", "warn", f"{label}{via}", "Rate limited.", "Too many requests - wait or raise limits."))
        elif code >= 400:
            f.append(finding("http", "warn", f"{label}{via}", final["url"]))
        else:
            f.append(finding("http", "pass", f"{label}{via} in {final['elapsed_ms']} ms", final["url"]))
            if final["elapsed_ms"] > 3000:
                f.append(finding("http", "warn", f"Slow response ({final['elapsed_ms']} ms to first byte)", "",
                                 "Check origin load, database queries and CDN caching."))
        if final.get("insecure"):
            f.append(finding("http", "info", "Response was only reachable by ignoring the TLS error",
                             info.get("tls_error", "")[:200]))
    return f


async def check_http(url: str, policy: NetPolicy) -> dict[str, Any]:
    target = parse_target(url, policy)
    info = await probe_http(target, policy)
    findings = evaluate_http(info)
    info.update(findings=findings, status=worst(findings))
    extra = []
    for h in info["hops"]:
        extra.append(f"→ {h['status_code']} {h['url']} ({h['elapsed_ms']} ms, ip {h['ip']})")
    server = (info.get("final") or {}).get("headers", {}).get("server")
    if server:
        extra.append(f"Server header: {server}")
    info["summary"] = text_report(f"HTTP report for {target.url}", findings, extra)
    return info
