"""Public status pages of common cloud / SaaS vendors, plus hosting-provider detection."""

from __future__ import annotations

import asyncio
import json
import time
import xml.etree.ElementTree as ET
from typing import Any

import httpx

from ..netguard import NetPolicy
from .common import api_client

# kind: statuspage = Atlassian Statuspage /api/v2/summary.json
VENDORS: dict[str, dict[str, Any]] = {
    "aws": {"name": "Amazon Web Services", "kind": "aws", "api": "https://health.aws.amazon.com/public/currentevents",
            "page": "https://health.aws.amazon.com/health/status"},
    "azure": {"name": "Microsoft Azure", "kind": "rss", "api": "https://azure.status.microsoft/en-us/status/feed/",
              "page": "https://azure.status.microsoft/en-us/status"},
    "gcp": {"name": "Google Cloud", "kind": "gcp", "api": "https://status.cloud.google.com/incidents.json",
            "page": "https://status.cloud.google.com/"},
    "microsoft365": {"name": "Microsoft 365", "kind": "manual", "page": "https://status.cloud.microsoft/",
                     "note": "Microsoft 365 has no public status API. Tenant-specific health is in the "
                             "Microsoft 365 admin center → Health → Service health."},
    "github": {"name": "GitHub", "kind": "statuspage", "api": "https://www.githubstatus.com/api/v2/summary.json",
               "page": "https://www.githubstatus.com/"},
    "cloudflare": {"name": "Cloudflare", "kind": "statuspage",
                   "api": "https://www.cloudflarestatus.com/api/v2/summary.json",
                   "page": "https://www.cloudflarestatus.com/"},
    "slack": {"name": "Slack", "kind": "slack", "api": "https://slack-status.com/api/v2.0.0/current",
              "page": "https://slack-status.com/"},
    "jira": {"name": "Jira", "kind": "statuspage", "api": "https://jira-software.status.atlassian.com/api/v2/summary.json",
             "page": "https://jira-software.status.atlassian.com/"},
    "confluence": {"name": "Confluence", "kind": "statuspage",
                   "api": "https://confluence.status.atlassian.com/api/v2/summary.json",
                   "page": "https://confluence.status.atlassian.com/"},
    "bitbucket": {"name": "Bitbucket", "kind": "statuspage",
                  "api": "https://bitbucket.status.atlassian.com/api/v2/summary.json",
                  "page": "https://bitbucket.status.atlassian.com/"},
    "zoom": {"name": "Zoom", "kind": "statuspage", "api": "https://status.zoom.us/api/v2/summary.json",
             "page": "https://status.zoom.us/"},
    "digitalocean": {"name": "DigitalOcean", "kind": "statuspage",
                     "api": "https://status.digitalocean.com/api/v2/summary.json",
                     "page": "https://status.digitalocean.com/"},
    "vercel": {"name": "Vercel", "kind": "statuspage", "api": "https://www.vercel-status.com/api/v2/summary.json",
               "page": "https://www.vercel-status.com/"},
    "netlify": {"name": "Netlify", "kind": "statuspage", "api": "https://www.netlifystatus.com/api/v2/summary.json",
                "page": "https://www.netlifystatus.com/"},
    "npm": {"name": "npm", "kind": "statuspage", "api": "https://status.npmjs.org/api/v2/summary.json",
            "page": "https://status.npmjs.org/"},
    "discord": {"name": "Discord", "kind": "statuspage", "api": "https://discordstatus.com/api/v2/summary.json",
                "page": "https://discordstatus.com/"},
    "dropbox": {"name": "Dropbox", "kind": "statuspage", "api": "https://status.dropbox.com/api/v2/summary.json",
                "page": "https://status.dropbox.com/"},
    "twilio": {"name": "Twilio", "kind": "statuspage", "api": "https://status.twilio.com/api/v2/summary.json",
               "page": "https://status.twilio.com/"},
    "datadog": {"name": "Datadog", "kind": "statuspage", "api": "https://status.datadoghq.com/api/v2/summary.json",
                "page": "https://status.datadoghq.com/"},
    "openai": {"name": "OpenAI", "kind": "statuspage", "api": "https://status.openai.com/api/v2/summary.json",
               "page": "https://status.openai.com/"},
}

ALIASES = {
    "amazon": "aws", "amazon web services": "aws", "cloudfront": "aws", "s3": "aws", "ec2": "aws",
    "microsoft azure": "azure", "google cloud": "gcp", "google cloud platform": "gcp", "firebase": "gcp",
    "m365": "microsoft365", "office365": "microsoft365", "office 365": "microsoft365", "outlook": "microsoft365",
    "teams": "microsoft365", "microsoft teams": "microsoft365", "atlassian": "jira", "gh": "github",
    "do": "digitalocean",
}

# Hosting/CDN fingerprints: suffixes found in CNAME targets, NS records or the hostname itself.
CNAME_HINTS: list[tuple[str, str]] = [
    (".cloudfront.net", "aws"), (".amazonaws.com", "aws"), (".awsglobalaccelerator.com", "aws"),
    (".elasticbeanstalk.com", "aws"), (".amplifyapp.com", "aws"),
    (".azurewebsites.net", "azure"), (".azureedge.net", "azure"), (".azurefd.net", "azure"),
    (".trafficmanager.net", "azure"), (".cloudapp.azure.com", "azure"), (".azurestaticapps.net", "azure"),
    (".core.windows.net", "azure"), (".azure-api.net", "azure"),
    (".googlehosted.com", "gcp"), (".appspot.com", "gcp"), (".run.app", "gcp"), (".web.app", "gcp"),
    (".firebaseapp.com", "gcp"), (".googleusercontent.com", "gcp"),
    (".github.io", "github"), (".githubusercontent.com", "github"),
    (".vercel-dns.com", "vercel"), (".vercel.app", "vercel"),
    (".netlify.app", "netlify"), (".netlify.com", "netlify"), (".netlifyglobalcdn.com", "netlify"),
    (".cdn.cloudflare.net", "cloudflare"), (".pages.dev", "cloudflare"), (".workers.dev", "cloudflare"),
    (".ondigitalocean.app", "digitalocean"), (".digitaloceanspaces.com", "digitalocean"),
    (".atlassian.net", "jira"), (".zoom.us", "zoom"), (".slack.com", "slack"),
    (".outlook.com", "microsoft365"), (".sharepoint.com", "microsoft365"), (".office.com", "microsoft365"),
]
NS_HINTS: list[tuple[str, str]] = [
    (".ns.cloudflare.com", "cloudflare"), ("awsdns-", "aws"), (".azure-dns.", "azure"),
    (".googledomains.com", "gcp"), ("ns-cloud-", "gcp"), (".digitalocean.com", "digitalocean"),
    (".vercel-dns.com", "vercel"),
]
HEADER_HINTS: list[tuple[str, str | None, str]] = [
    # (header, substring in value or None for presence, vendor)
    ("cf-ray", None, "cloudflare"), ("server", "cloudflare", "cloudflare"),
    ("x-amz-cf-id", None, "aws"), ("server", "amazons3", "aws"), ("server", "awselb", "aws"),
    ("x-amzn-requestid", None, "aws"),
    ("x-azure-ref", None, "azure"), ("x-msedge-ref", None, "azure"),
    ("x-vercel-id", None, "vercel"), ("server", "vercel", "vercel"),
    ("x-nf-request-id", None, "netlify"), ("server", "netlify", "netlify"),
    ("x-github-request-id", None, "github"), ("server", "github.com", "github"),
    ("server", "google frontend", "gcp"), ("x-cloud-trace-context", None, "gcp"), ("via", "google", "gcp"),
]


def resolve_vendor(name: str) -> str | None:
    key = (name or "").strip().lower()
    if key in VENDORS:
        return key
    return ALIASES.get(key)


def detect_providers(host: str, cname_chain: list[str], nameservers: list[str],
                     headers: dict[str, str] | None) -> dict[str, list[str]]:
    """Map hosting/CDN/DNS providers to evidence. Pass nameservers only when DNS itself is suspect:
    a DNS provider's incident is irrelevant to a site whose DNS resolves fine."""
    found: dict[str, list[str]] = {}

    def add(vendor: str, why: str) -> None:
        found.setdefault(vendor, [])
        if why not in found[vendor] and len(found[vendor]) < 2:
            found[vendor].append(why)

    for name in [host, *cname_chain]:
        n = "." + name.lower().rstrip(".")
        for suffix, vendor in CNAME_HINTS:
            if n.endswith(suffix):
                add(vendor, f"{'hostname' if name == host else 'CNAME'} {name}")
    for ns in nameservers:
        for marker, vendor in NS_HINTS:
            if marker in ns.lower():
                add(vendor, f"DNS hosted by {VENDORS[vendor]['name']} ({ns})")
                break
    for header, needle, vendor in HEADER_HINTS:
        value = (headers or {}).get(header)
        if value is not None and (needle is None or needle in value.lower()):
            add(vendor, f"header {header}: {value[:60]}")
    return found


# ── status fetching ──────────────────────────────────────────────────────────

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 60.0
_MAX_BYTES = 2_000_000


def _sp_level(indicator: str | None) -> str:
    return {"none": "operational", "minor": "minor", "major": "major", "critical": "major",
            "maintenance": "maintenance"}.get(indicator or "", "unknown")


def _parse_statuspage(data: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    st = data.get("status") or {}
    incidents = [
        {"name": i.get("name"), "status": i.get("status"), "impact": i.get("impact"),
         "started": i.get("created_at"), "url": i.get("shortlink")}
        for i in (data.get("incidents") or []) if i.get("status") not in ("resolved", "postmortem")
    ]
    for m in data.get("scheduled_maintenances") or []:
        if m.get("status") == "in_progress":
            incidents.append({"name": m.get("name"), "status": "maintenance in progress", "impact": "maintenance",
                              "started": m.get("scheduled_for"), "url": m.get("shortlink")})
    degraded = [c.get("name") for c in (data.get("components") or [])
                if c.get("status") not in (None, "operational") and not c.get("group")]
    desc = st.get("description") or ""
    if degraded:
        desc += f" (affected: {', '.join(degraded[:6])})"
    return _sp_level(st.get("indicator")), desc, incidents


def _parse_slack(data: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    inc = [{"name": i.get("title"), "status": i.get("status"), "impact": i.get("type"),
            "started": i.get("date_created"), "url": i.get("url")} for i in data.get("active_incidents") or []]
    if not inc and data.get("status") == "ok":
        return "operational", "All systems operational", []
    level = "major" if any((i.get("impact") or "") == "outage" for i in inc) else "minor"
    return level, f"{len(inc)} active incident(s)", inc


def _parse_gcp(data: list[dict[str, Any]]) -> tuple[str, str, list[dict[str, Any]]]:
    active = [i for i in data if not i.get("end")]
    inc = [{"name": (i.get("external_desc") or "")[:200], "status": i.get("status_impact") or "active",
            "impact": i.get("severity"),
            "started": i.get("begin"), "url": "https://status.cloud.google.com/" + (i.get("uri") or ""),
            "products": [p.get("title") for p in i.get("affected_products") or []][:5]} for i in active]
    if not inc:
        return "operational", "No active incidents", []
    level = "major" if any(i.get("impact") == "high" for i in inc) else "minor"
    return level, f"{len(inc)} active incident(s)", inc


def _parse_aws(raw: bytes) -> tuple[str, str, list[dict[str, Any]]]:
    text = None
    for enc in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(enc)
            data = json.loads(text)
            break
        except (UnicodeDecodeError, ValueError):
            data = None
    if data is None:
        raise ValueError("Unrecognised AWS health feed format")
    events = data if isinstance(data, list) else data.get("events", []) if isinstance(data, dict) else []
    inc = []
    for e in events:
        if not isinstance(e, dict):
            continue
        name = e.get("summary") or ""
        log = e.get("event_log")
        if isinstance(log, list) and log and isinstance(log[-1], dict) and log[-1].get("summary"):
            name = log[-1]["summary"]
        region = e.get("region_name") or e.get("region")
        if region:
            name = f"{region}: {name}"
        inc.append({"name": name,
                    "status": str(e.get("status", "active")),
                    "impact": e.get("service_name") or e.get("service"),
                    "region": e.get("region_name") or e.get("region"),
                    "started": e.get("date"), "url": "https://health.aws.amazon.com/health/status"})
    if not inc:
        return "operational", "No active events", []
    regions = sorted({i["region"] for i in inc if i.get("region")})
    where = f" in {', '.join(regions[:4])}" if regions else ""
    return "minor", f"{len(inc)} regional event(s){where}", inc


def _parse_rss(raw: bytes) -> tuple[str, str, list[dict[str, Any]]]:
    root = ET.fromstring(raw)
    items = root.findall(".//item")
    inc = [{"name": (it.findtext("title") or "").strip(), "status": "active", "impact": None,
            "started": it.findtext("pubDate"), "url": it.findtext("link")} for it in items[:10]]
    if not inc:
        return "operational", "No active incidents in the status feed", []
    return "minor", f"{len(inc)} active item(s) in the status feed", inc


async def fetch_status(client: httpx.AsyncClient, key: str) -> dict[str, Any]:
    v = VENDORS[key]
    base = {"vendor": key, "name": v["name"], "page": v["page"]}
    if v["kind"] == "manual":
        return {**base, "status": "unknown", "description": v["note"], "incidents": []}
    cached = _CACHE.get(key)
    if cached and time.monotonic() - cached[0] < _CACHE_TTL:
        return cached[1]
    try:
        resp = await client.get(v["api"])
        resp.raise_for_status()
        raw = resp.content[:_MAX_BYTES]
        if v["kind"] == "statuspage":
            level, desc, inc = _parse_statuspage(json.loads(raw))
        elif v["kind"] == "slack":
            level, desc, inc = _parse_slack(json.loads(raw))
        elif v["kind"] == "gcp":
            level, desc, inc = _parse_gcp(json.loads(raw))
        elif v["kind"] == "aws":
            level, desc, inc = _parse_aws(raw)
        else:
            level, desc, inc = _parse_rss(raw)
        result = {**base, "status": level, "description": desc, "incidents": inc[:10]}
    except Exception as exc:  # network errors, format changes - never fail the whole diagnosis
        result = {**base, "status": "unknown", "description": f"Could not read status page ({exc.__class__.__name__})",
                  "incidents": []}
        return result
    _CACHE[key] = (time.monotonic(), result)
    return result


async def vendor_status(names: list[str], policy: NetPolicy) -> list[dict[str, Any]]:
    keys: list[str] = []
    for n in names:
        k = resolve_vendor(n)
        if k is None:
            raise ValueError(f"Unknown vendor '{n}'. Known: {', '.join(sorted(VENDORS))}")
        if k not in keys:
            keys.append(k)
    async with api_client(policy, timeout=8) as client:
        return list(await asyncio.gather(*(fetch_status(client, k) for k in keys)))


STATUS_ICON = {"operational": "🟢", "minor": "🟡", "maintenance": "🔧", "major": "🔴", "unknown": "⚪"}


def vendor_text(rows: list[dict[str, Any]]) -> str:
    lines = []
    for r in rows:
        lines.append(f"{STATUS_ICON.get(r['status'], '⚪')} {r['name']}: {r['status']} — {r['description']} ({r['page']})")
        for i in r["incidents"][:3]:
            lines.append(f"    • {i.get('name')} [{i.get('status')}]")
    return "\n".join(lines)
