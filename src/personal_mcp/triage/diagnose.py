"""One-shot outage triage: "is it me, or is it them?"."""

from __future__ import annotations

import asyncio
import datetime as dt
import os
import time
from typing import Any

import httpx

from ..netguard import NetPolicy, Target, TargetError, parse_target, resolve_checked
from .common import USER_AGENT, finding
from .dns import evaluate_overview, resolve_overview
from .http_check import evaluate_http, probe_http
from .tls import evaluate_tls, inspect_tls
from .vendors import detect_providers, vendor_status

CAUSES = {
    "none": "Everything looks healthy",
    "dns": "DNS problem with the site",
    "tls": "Certificate / TLS problem",
    "origin": "The site's server is failing",
    "unreachable": "The site's server is unreachable",
    "provider_incident": "Upstream provider incident",
    "your_network": "Your network (DNS, VPN, proxy or firewall)",
    "access": "Site is up but restricts access",
    "unknown": "Inconclusive",
}


def _headline(status: str, cause: str, host: str, providers_down: list[str]) -> str:
    if status == "ok":
        return f"{host} is up and healthy — if it fails for you, the problem is likely on your side."
    if cause == "provider_incident":
        return f"{host} is affected by an active incident at {', '.join(providers_down)}."
    if cause == "your_network":
        return f"{host} works from the internet but not from your network."
    if cause == "access":
        return f"{host} is up, but it requires sign-in or blocks automated checks."
    return {
        "dns": f"{host} has a DNS problem — the name does not resolve correctly.",
        "tls": f"{host} has a certificate problem — browsers will block it.",
        "origin": f"{host} is reachable, but its server is returning errors.",
        "unreachable": f"{host} is not accepting connections.",
        "none": f"{host} is up, with warnings worth checking.",
    }.get(cause, f"{host} looks unhealthy, but the cause is unclear — see the findings.")


def build_verdict(target: Target, dns_findings: list[dict], tls_findings: list[dict], http_findings: list[dict],
                  vendors: list[dict], providers: dict[str, list[str]], local_mode: bool) -> dict[str, Any]:
    findings = dns_findings + tls_findings + http_findings
    fails = [f for f in findings if f["status"] == "fail"]
    warns = [f for f in findings if f["status"] == "warn"]
    providers_down = [v["name"] for v in vendors if v["status"] in ("major", "minor")]

    def has(check: str, *words: str) -> bool:
        return any(f["check"] == check and f["status"] == "fail" and all(w.lower() in f["title"].lower() for w in words)
                   for f in findings)

    if not fails:
        status = "degraded" if warns else "ok"
        cause = "none"
        if any(f["check"] == "http" and f["title"].startswith(("HTTP 401", "HTTP 403")) for f in findings):
            cause = "access"
    else:
        status = "down"
        if has("dns", "your computer"):
            cause = "your_network"
        elif has("dns"):
            cause = "dns"
        elif has("tls", "connect") or has("http", "refused") or has("http", "respond"):
            cause = "unreachable"
        elif any(f["check"] == "tls" for f in fails):
            cause = "tls"  # browsers block the site, so it is effectively down for users
        elif any(f["check"] == "http" and f["title"].startswith("HTTP 5") for f in fails):
            cause = "origin"
        else:
            cause = "unknown"
        if providers_down and cause in ("origin", "unreachable", "unknown"):
            cause = "provider_incident"

    vendor_findings = []
    for v in vendors:
        why = "; ".join(providers.get(v["vendor"], []))
        if v["status"] in ("major", "minor"):
            names = ", ".join(i.get("name") or "" for i in v["incidents"][:2])
            vendor_findings.append(finding("provider", "warn" if status == "ok" else "fail",
                                           f"{v['name']} reports an active incident",
                                           f"{names} (detected via {why})", v["page"]))
        elif v["status"] == "operational":
            vendor_findings.append(finding("provider", "pass", f"{v['name']} reports no incidents", f"detected via {why}"))
        else:
            vendor_findings.append(finding("provider", "info", f"{v['name']}: status unknown", v["description"]))

    fixes = [f["fix"] for f in fails + warns if f.get("fix")]
    if status == "ok":
        fixes.append("If users still report problems: clear browser cache/DNS, try another network or disable "
                     "VPN, and check whether only a specific page or API endpoint fails.")
    if cause == "provider_incident":
        fixes.insert(0, "Nothing to fix on your side yet — follow the provider status page and inform users.")

    return {
        "status": status,
        "likely_cause": cause,
        "cause_label": CAUSES[cause],
        "headline": _headline(status, cause, target.host, providers_down),
        "findings": findings + vendor_findings,
        "fixes": list(dict.fromkeys(fixes))[:6],
    }


async def _cloud_view(url: str) -> dict[str, Any] | None:
    base = os.environ.get("PERSONAL_MCP_CLOUD_URL", "").rstrip("/")
    if not base:
        return None
    try:
        async with httpx.AsyncClient(timeout=25, headers={"User-Agent": USER_AGENT}) as c:
            r = await c.get(f"{base}/api/v1/diagnose", params={"url": url})
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"error": f"Cloud check failed: {exc}"}


def _ticket(target: Target, v: dict[str, Any], vantage: str) -> str:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"[{v['status'].upper()}] {target.url} — {v['cause_label']}", f"Checked {now} from {vantage}.", ""]
    for f in v["findings"]:
        if f["status"] in ("fail", "warn"):
            lines.append(f"- {f['title']}" + (f": {f['detail']}" if f.get("detail") else ""))
    if v["fixes"]:
        lines += ["", "Next steps:"] + [f"- {x}" for x in v["fixes"]]
    return "\n".join(lines)


async def diagnose(url: str, policy: NetPolicy, *, local_mode: bool = False,
                   compare_cloud: bool = False) -> dict[str, Any]:
    started = time.perf_counter()
    target = parse_target(url, policy)

    dns_task = asyncio.create_task(resolve_overview(target.host, policy, include_system=local_mode)) \
        if not target.is_ip else None
    cloud_task = asyncio.create_task(_cloud_view(target.url)) if (local_mode and compare_cloud) else None

    ips: list[str] | None = None
    connect_error: str | None = None
    try:
        ips = await resolve_checked(target.host, target.port, policy)
    except TargetError as exc:
        if "private" in str(exc) or "internal" in str(exc):
            raise
        connect_error = str(exc)

    ov = await dns_task if dns_task else {"host": target.host, "resolvers": {}, "cname_chain": [], "zone": None,
                                          "nameservers": []}
    dns_findings = evaluate_overview(ov) if dns_task else []

    tls_info: dict[str, Any] = {}
    http_info: dict[str, Any] = {"hops": []}
    if ips:
        jobs = [probe_http(target, policy)]
        if target.scheme == "https":
            jobs.append(inspect_tls(target, policy, ips))
        res = await asyncio.gather(*jobs)
        http_info = res[0]
        tls_info = res[1] if len(res) > 1 else {}
    elif not any(f["status"] == "fail" for f in dns_findings):
        dns_findings.append(finding("dns", "fail", f"{target.host} does not resolve", connect_error or ""))

    tls_findings = evaluate_tls(tls_info) if tls_info else []
    # Avoid double-reporting the same connection failure from TLS and HTTP.
    if any(f["title"].startswith("Cannot connect") for f in tls_findings):
        http_findings = []
    else:
        http_findings = evaluate_http(http_info) if ips else []

    headers = (http_info.get("final") or {}).get("headers", {})
    providers = detect_providers(target.host, ov.get("cname_chain", []), ov.get("nameservers", []), headers)
    vendors = await vendor_status(list(providers)[:4], policy) if providers else []

    verdict = build_verdict(target, dns_findings, tls_findings, http_findings, vendors, providers, local_mode)
    vantage = "this computer (local mode)" if local_mode else "the IsItMe cloud checker"
    result: dict[str, Any] = {
        "target": target.url,
        "host": target.host,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "vantage": vantage,
        **verdict,
        "providers": [{"vendor": k, "evidence": v} for k, v in providers.items()],
        "details": {
            "dns": ov,
            "tls": {k: v for k, v in tls_info.items() if k != "findings"},
            "http": {k: v for k, v in http_info.items() if k != "findings"},
            "vendor_status": vendors,
        },
    }

    if cloud_task:
        cloud = await cloud_task
        if cloud and "error" not in cloud:
            result["cloud_view"] = {k: cloud.get(k) for k in ("status", "likely_cause", "headline", "checked_at")}
            if verdict["status"] == "down" and cloud.get("status") in ("ok", "degraded"):
                result["status"] = "down"
                result["likely_cause"] = "your_network"
                result["cause_label"] = CAUSES["your_network"]
                result["headline"] = f"{target.host} works from the internet but fails from your network."
                result["fixes"] = ["Check VPN, proxy, firewall and local DNS on this machine/network."] + result["fixes"]
            elif verdict["status"] in ("ok", "degraded") and cloud.get("status") == "down":
                result["headline"] += " (Note: it fails from the internet — it may only work inside your network.)"
        elif cloud:
            result["cloud_view"] = cloud
    elif local_mode and compare_cloud:
        result["cloud_view"] = {"error": "Set PERSONAL_MCP_CLOUD_URL to your hosted IsItMe URL to compare views."}

    result["ticket_summary"] = _ticket(target, result, vantage)
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    return result


def diagnose_text(r: dict[str, Any]) -> str:
    icon = {"ok": "🟢", "degraded": "🟡", "down": "🔴"}[r["status"]]
    lines = [f"{icon} {r['headline']}", f"Likely cause: {r['cause_label']}", ""]
    mark = {"pass": "✅", "warn": "⚠️", "fail": "❌", "info": "ℹ️"}
    for f in r["findings"]:
        lines.append(f"{mark[f['status']]} [{f['check'].upper()}] {f['title']}" + (f" — {f['detail']}" if f.get("detail") else ""))
    if r.get("fixes"):
        lines += ["", "Suggested next steps:"] + [f"• {x}" for x in r["fixes"]]
    if r.get("cloud_view") and "status" in r["cloud_view"]:
        lines += ["", f"Cloud view: {r['cloud_view']['status']} — {r['cloud_view'].get('headline')}"]
    lines += ["", f"Checked from {r['vantage']} in {r['elapsed_ms']} ms."]
    return "\n".join(lines)
