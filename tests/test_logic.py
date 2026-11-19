"""DNS evaluation, e-mail auth, vendor parsers and the diagnose verdict engine (network mocked)."""

import json

import pytest

from personal_mcp.netguard import HOSTED_POLICY
from personal_mcp.triage import diagnose as diag_mod
from personal_mcp.triage import email_auth as email_mod
from personal_mcp.triage.dns import evaluate_overview, txt_value
from personal_mcp.triage.vendors import (_parse_aws, _parse_gcp, _parse_rss, _parse_slack, _parse_statuspage,
                                         detect_providers, resolve_vendor)


def ov(resolvers, cname=None, ns=None, host="example.com"):
    return {"host": host, "resolvers": resolvers, "cname_chain": cname or [], "zone": "example.com",
            "nameservers": ns or []}


def test_txt_join():
    assert txt_value('"v=spf1 include:_spf.google.com" " -all"') == "v=spf1 include:_spf.google.com -all"
    assert txt_value("plain") == "plain"


def test_dns_consistent():
    f = evaluate_overview(ov({"google": {"rcode": "NOERROR", "addresses": ["1.2.3.4"]},
                              "cloudflare": {"rcode": "NOERROR", "addresses": ["1.2.3.4"]}}))
    assert f[0]["status"] == "pass"


def test_dns_nxdomain():
    f = evaluate_overview(ov({"google": {"rcode": "NXDOMAIN", "addresses": []},
                              "cloudflare": {"rcode": "NXDOMAIN", "addresses": []}}))
    assert f[0]["status"] == "fail" and "NXDOMAIN" in f[0]["title"]


def test_dns_inconsistent():
    f = evaluate_overview(ov({"google": {"rcode": "NOERROR", "addresses": ["1.2.3.4"]},
                              "cloudflare": {"rcode": "NOERROR", "addresses": ["5.6.7.8"]}}))
    assert f[0]["status"] == "warn" and "different" in f[0]["title"]


def test_dns_local_resolver_broken():
    f = evaluate_overview(ov({"google": {"rcode": "NOERROR", "addresses": ["1.2.3.4"]},
                              "cloudflare": {"rcode": "NOERROR", "addresses": ["1.2.3.4"]},
                              "system": {"rcode": "ERROR", "addresses": [], "error": "Temporary failure"}}))
    assert any(x["status"] == "fail" and "Your computer" in x["title"] for x in f)


# ── e-mail ───────────────────────────────────────────────────────────

def fake_dns(records):
    async def lookup(_client, name, rtype):
        rows = records.get((name, rtype))
        if rows == "NX":
            return {"rcode": "NXDOMAIN", "answers": []}
        return {"rcode": "NOERROR", "answers": [{"name": name, "type": rtype, "ttl": 300, "data": d} for d in rows or []]}
    return lookup


async def test_email_good_google(monkeypatch):
    monkeypatch.setattr(email_mod, "doh_lookup", fake_dns({
        ("acme.io", "MX"): ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."],
        ("acme.io", "TXT"): ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"],
        ("_dmarc.acme.io", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@acme.io"],
        ("google._domainkey.acme.io", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBgkq"],
    }))
    r = await email_mod.check_email_auth("acme.io", HOSTED_POLICY)
    assert r["mail_provider"] == "Google Workspace"
    assert r["status"] == "pass", r["findings"]
    assert r["dkim"]["found"][0]["selector"] == "google"


async def test_email_broken(monkeypatch):
    monkeypatch.setattr(email_mod, "doh_lookup", fake_dns({
        ("bad.io", "MX"): ["10 bad-io.mail.protection.outlook.com."],
        ("bad.io", "TXT"): ["v=spf1 include:a.com +all", "v=spf1 -all"],
        ("_dmarc.bad.io", "TXT"): ["v=DMARC1; p=none"],
    }))
    r = await email_mod.check_email_auth("bad.io", HOSTED_POLICY)
    titles = [f["title"] for f in r["findings"]]
    assert r["status"] == "fail"
    assert any("2 SPF records" in t for t in titles)
    assert any("p=none" in t for t in titles)
    assert any("selector1" in (f.get("detail") or "") for f in r["findings"])  # Microsoft 365 hint


async def test_email_plus_all_and_lookups(monkeypatch):
    spf = "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(11)) + " +all"
    monkeypatch.setattr(email_mod, "doh_lookup", fake_dns({
        ("x.io", "MX"): ["10 mx.x.io."], ("x.io", "TXT"): [spf]}))
    r = await email_mod.check_email_auth("x.io", HOSTED_POLICY)
    titles = " | ".join(f["title"] for f in r["findings"])
    assert "+all" in titles and "more than 10 DNS lookups" in titles and "No DMARC" in titles


# ── vendors ──────────────────────────────────────────────────────────

def test_statuspage_parser():
    level, desc, inc = _parse_statuspage({
        "status": {"indicator": "major", "description": "Partial System Outage"},
        "components": [{"name": "Actions", "status": "major_outage"}, {"name": "API", "status": "operational"}],
        "incidents": [{"name": "Actions delayed", "status": "investigating", "impact": "major",
                       "created_at": "2026-11-19T10:00:00Z", "shortlink": "https://stspg.io/x"},
                      {"name": "old", "status": "resolved"}],
        "scheduled_maintenances": [],
    })
    assert level == "major" and "Actions" in desc and len(inc) == 1


def test_slack_parser():
    assert _parse_slack({"status": "ok", "active_incidents": []})[0] == "operational"
    lvl, _, inc = _parse_slack({"status": "active", "active_incidents": [
        {"title": "Messages delayed", "type": "outage", "status": "active", "url": "u", "date_created": "d"}]})
    assert lvl == "major" and inc[0]["name"] == "Messages delayed"


def test_gcp_parser():
    lvl, _, inc = _parse_gcp([{"external_desc": "Cloud Run errors", "severity": "high", "begin": "b", "uri": "i/1",
                               "affected_products": [{"title": "Cloud Run"}]}, {"external_desc": "old", "end": "e"}])
    assert lvl == "major" and inc[0]["products"] == ["Cloud Run"]


def test_aws_parser_utf16_and_empty():
    assert _parse_aws("[]".encode("utf-16"))[0] == "operational"
    raw = json.dumps([{"summary": "[RESOLVED] EC2 API errors", "service_name": "EC2", "region_name": "us-east-1",
                       "date": "1700000000", "status": "1"}]).encode("utf-16")
    lvl, _, inc = _parse_aws(raw)
    assert lvl == "minor" and inc[0]["region"] == "us-east-1"


def test_rss_parser():
    raw = b"<rss><channel><title>Azure</title><item><title>Storage issue</title><link>https://x</link></item></channel></rss>"
    assert _parse_rss(raw)[2][0]["name"] == "Storage issue"
    assert _parse_rss(b"<rss><channel></channel></rss>")[0] == "operational"


def test_provider_detection():
    p = detect_providers("www.acme.io", ["acme.netlify.app"], ["dana.ns.cloudflare.com"],
                         {"server": "Netlify", "x-nf-request-id": "1"})
    assert set(p) == {"netlify", "cloudflare"}
    assert resolve_vendor("Office365") == "microsoft365" and resolve_vendor("nope") is None


# ── diagnose end-to-end against local servers (DoH + vendor pages mocked) ─────

@pytest.fixture
def mock_world(monkeypatch):
    state = {"vendors": []}

    async def fake_overview(host, policy, include_system):
        return ov({"google": {"rcode": "NOERROR", "addresses": ["127.0.0.1"]},
                   "cloudflare": {"rcode": "NOERROR", "addresses": ["127.0.0.1"]}},
                  cname=["acme.cdn.cloudflare.net"], host=host)

    async def fake_vendor_status(names, policy):
        return [v for v in state["vendors"] if v["vendor"] in names]

    monkeypatch.setattr(diag_mod, "resolve_overview", fake_overview)
    monkeypatch.setattr(diag_mod, "vendor_status", fake_vendor_status)
    return state


CF_OK = {"vendor": "cloudflare", "name": "Cloudflare", "status": "operational", "description": "All good",
         "incidents": [], "page": "https://www.cloudflarestatus.com/"}
CF_DOWN = {**CF_OK, "status": "major", "description": "Major outage",
           "incidents": [{"name": "Elevated 5xx in BOM", "status": "investigating"}]}


async def test_diagnose_healthy(serve, policy, mock_world):
    mock_world["vendors"] = [CF_OK]
    port = await serve("valid")
    r = await diag_mod.diagnose(f"https://localhost:{port}/", policy)
    assert r["status"] == "ok", r["findings"]
    assert r["likely_cause"] == "none"
    assert any(f["check"] == "provider" and f["status"] == "pass" for f in r["findings"])
    assert "[OK]" in r["ticket_summary"]


async def test_diagnose_expired_cert(serve, policy, mock_world):
    port = await serve("expired")
    r = await diag_mod.diagnose(f"https://localhost:{port}/", policy)
    assert (r["status"], r["likely_cause"]) == ("down", "tls")
    assert "EXPIRED" in r["ticket_summary"]
    assert any("Renew" in x for x in r["fixes"])


async def test_diagnose_origin_error(serve, policy, mock_world):
    port = await serve(None)
    r = await diag_mod.diagnose(f"http://127.0.0.1:{port}/503", policy)
    assert (r["status"], r["likely_cause"]) == ("down", "origin")


async def test_diagnose_provider_incident(serve, policy, mock_world):
    mock_world["vendors"] = [CF_DOWN]
    port = await serve(None)
    r = await diag_mod.diagnose(f"http://localhost:{port}/503", policy)
    assert r["likely_cause"] == "provider_incident"
    assert "Cloudflare" in r["headline"]
    assert r["fixes"][0].startswith("Nothing to fix")


async def test_diagnose_unreachable(policy, mock_world):
    r = await diag_mod.diagnose("https://127.0.0.1:1/", policy)
    assert (r["status"], r["likely_cause"]) == ("down", "unreachable")


async def test_diagnose_hosted_blocks_private():
    from personal_mcp.netguard import TargetError
    with pytest.raises(TargetError):
        await diag_mod.diagnose("http://127.1/", HOSTED_POLICY)
