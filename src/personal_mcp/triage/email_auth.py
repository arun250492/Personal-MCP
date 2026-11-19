"""E-mail deliverability check: MX, SPF, DKIM (common selectors) and DMARC."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from ..netguard import NetPolicy, normalize_domain
from .common import api_client, finding, text_report, worst
from .dns import doh_lookup, values

COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "k1", "s1", "s2", "dkim", "mail", "smtp",
    "zoho", "protonmail", "mandrill", "everlytickey1", "mxvault",
]

MAIL_PROVIDERS = [
    ("google.com", "Google Workspace", "include:_spf.google.com", "google"),
    ("googlemail.com", "Google Workspace", "include:_spf.google.com", "google"),
    ("protection.outlook.com", "Microsoft 365", "include:spf.protection.outlook.com", "selector1"),
    ("zoho.", "Zoho Mail", "include:zoho.com", "zoho"),
    ("protonmail.ch", "Proton Mail", "include:_spf.protonmail.ch", "protonmail"),
    ("mimecast.com", "Mimecast", "include:<region>._netblocks.mimecast.com", None),
    ("pphosted.com", "Proofpoint", "include:<id>.spf.pphosted.com", None),
    ("amazonaws.com", "Amazon SES/WorkMail", "include:amazonses.com", None),
]

_SPF_LOOKUP_TERMS = re.compile(r"(?:^|\s)[+?~-]?(include:|a\b|a:|mx\b|mx:|ptr\b|ptr:|exists:|redirect=)", re.I)


def _mail_provider(mx_hosts: list[str]) -> tuple[str, str, str | None] | None:
    for host in mx_hosts:
        for needle, name, spf, selector in MAIL_PROVIDERS:
            if needle in host:
                return name, spf, selector
    return None


async def check_email_auth(domain: str, policy: NetPolicy, dkim_selectors: list[str] | None = None) -> dict[str, Any]:
    domain = normalize_domain(domain, policy)
    selectors = [s.strip().lower() for s in (dkim_selectors or []) if s.strip()][:5]
    for s in COMMON_DKIM_SELECTORS:
        if s not in selectors:
            selectors.append(s)
    selectors = selectors[:15]

    async with api_client(policy) as client:
        mx_res, txt_res, dmarc_res, *dkim_res = await asyncio.gather(
            doh_lookup(client, domain, "MX"),
            doh_lookup(client, domain, "TXT"),
            doh_lookup(client, f"_dmarc.{domain}", "TXT"),
            *(doh_lookup(client, f"{s}._domainkey.{domain}", "TXT") for s in selectors),
        )
        # A selector may be a CNAME to the provider (e.g. Microsoft 365); DoH resolves it for us.

    findings: list[dict[str, Any]] = []
    if mx_res["rcode"] == "NXDOMAIN":
        findings.append(finding("email", "fail", f"{domain} does not exist in DNS", "",
                                "Check the domain spelling and that the registration is active."))
        result = {"domain": domain, "findings": findings, "status": "fail"}
        result["summary"] = text_report(f"E-mail authentication report for {domain}", findings)
        return result

    # MX
    mx = []
    for v in values(mx_res, "MX"):
        parts = v.split()
        if len(parts) == 2:
            mx.append({"priority": int(parts[0]) if parts[0].isdigit() else parts[0], "host": parts[1].rstrip(".").lower()})
    mx.sort(key=lambda r: r["priority"] if isinstance(r["priority"], int) else 99999)
    mx_hosts = [r["host"] for r in mx]
    provider = _mail_provider(mx_hosts)
    if not mx:
        findings.append(finding("email", "warn", "No MX records", "This domain cannot receive e-mail.",
                                "If it should receive mail, add MX records from your mail provider."))
    elif mx_hosts == [""] or mx_hosts == ["."]:
        findings.append(finding("email", "info", "Null MX: domain explicitly does not accept mail"))
    else:
        label = f" ({provider[0]})" if provider else ""
        findings.append(finding("email", "pass", f"MX records found{label}", ", ".join(mx_hosts[:4])))

    # SPF
    spf_records = [t for t in values(txt_res, "TXT") if t.lower().startswith("v=spf1")]
    spf_fix = f"Publish one TXT record like: v=spf1 {provider[1] if provider else 'include:<your-provider>'} -all"
    spf: dict[str, Any] = {"records": spf_records}
    if not spf_records:
        findings.append(finding("email", "fail", "No SPF record", "Receivers cannot verify who may send for this domain.",
                                spf_fix))
    elif len(spf_records) > 1:
        findings.append(finding("email", "fail", f"{len(spf_records)} SPF records (only one is allowed)",
                                " | ".join(spf_records)[:300], "Merge them into a single v=spf1 record."))
    else:
        rec = spf_records[0]
        lookups = len(_SPF_LOOKUP_TERMS.findall(rec))
        spf["dns_lookups_top_level"] = lookups
        all_m = re.search(r"([+?~-]?)all\b", rec)
        qual = all_m.group(1) if all_m else None
        if qual in ("", "+"):
            findings.append(finding("email", "fail", "SPF ends with +all (anyone may send as you)", rec,
                                    "Change '+all' to '-all' or '~all'."))
        elif qual == "?":
            findings.append(finding("email", "warn", "SPF ends with ?all (neutral, gives no protection)", rec,
                                    "Change '?all' to '~all' or '-all'."))
        elif qual is None and "redirect=" not in rec:
            findings.append(finding("email", "warn", "SPF has no 'all' mechanism", rec, "End the record with '-all' or '~all'."))
        else:
            findings.append(finding("email", "pass", f"SPF record OK ({'hard fail -all' if qual == '-' else 'soft fail ~all' if qual == '~' else 'redirect'})", rec))
        if lookups > 10:
            findings.append(finding("email", "fail", f"SPF needs more than 10 DNS lookups ({lookups} at top level)", "",
                                    "SPF fails with permerror past 10 lookups. Remove unused includes or flatten the record."))
        elif lookups >= 8:
            findings.append(finding("email", "warn", f"SPF is close to the 10-lookup limit ({lookups} at top level, "
                                    "nested includes add more)"))

    # DMARC
    dmarc_records = [t for t in values(dmarc_res, "TXT") if t.lower().startswith("v=dmarc1")]
    dmarc: dict[str, Any] = {"records": dmarc_records}
    if not dmarc_records:
        findings.append(finding("email", "warn", "No DMARC record",
                                "Gmail and Yahoo require DMARC for bulk senders; spoofing of this domain is not blocked.",
                                f"Start with: _dmarc.{domain} TXT \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}\" "
                                "then move to p=quarantine / p=reject after reviewing reports."))
    else:
        rec = dmarc_records[0]
        tags = {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in rec.split(";")) if k.strip()}
        dmarc["policy"] = tags.get("p")
        p = (tags.get("p") or "").lower()
        if len(dmarc_records) > 1:
            findings.append(finding("email", "fail", "Multiple DMARC records", "", "Keep exactly one _dmarc TXT record."))
        if p == "none":
            findings.append(finding("email", "warn", "DMARC is monitor-only (p=none)", rec,
                                    "Once reports look clean, move to p=quarantine and then p=reject."))
        elif p in ("quarantine", "reject"):
            findings.append(finding("email", "pass", f"DMARC enforced (p={p})", rec))
        else:
            findings.append(finding("email", "fail", "DMARC record has no valid p= policy", rec,
                                    "Add p=none, p=quarantine or p=reject."))
        if "rua" not in tags:
            findings.append(finding("email", "info", "DMARC has no rua= reporting address",
                                    "You will not receive aggregate reports."))

    # DKIM
    found = []
    for sel, res in zip(selectors, dkim_res):
        recs = [t for t in values(res, "TXT") if "p=" in t]
        if recs:
            found.append({"selector": sel, "revoked": bool(re.search(r"\bp=\s*(;|$)", recs[0]))})
    if found:
        active = [d["selector"] for d in found if not d["revoked"]]
        findings.append(finding("email", "pass" if active else "warn",
                                f"DKIM key found for selector(s): {', '.join(d['selector'] for d in found)}",
                                "" if active else "All found keys are revoked (empty p=)."))
    else:
        hint = f" For {provider[0]} the usual selector is '{provider[2]}'." if provider and provider[2] else ""
        findings.append(finding("email", "info", "No DKIM key found under common selectors",
                                f"DKIM selectors are provider-specific, so this is not proof DKIM is missing.{hint}",
                                "Find the selector in a received e-mail's DKIM-Signature header (s=...) and re-run with it."))

    result = {
        "domain": domain,
        "mail_provider": provider[0] if provider else None,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": {"checked_selectors": selectors, "found": found},
        "findings": findings,
        "status": worst(findings),
    }
    result["summary"] = text_report(f"E-mail authentication report for {domain}", findings)
    return result
