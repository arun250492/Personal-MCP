"""DNS checks using public DNS-over-HTTPS resolvers (and the local resolver in local mode)."""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

import httpx

from ..netguard import NetPolicy, normalize_domain
from .common import api_client, finding, text_report, worst

DOH_RESOLVERS: dict[str, str] = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}

RR_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
RR_NAMES = {v: k for k, v in RR_TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

_TXT_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


def txt_value(data: str) -> str:
    """Join the quoted chunks of a TXT answer returned by DoH JSON APIs."""
    chunks = _TXT_CHUNK.findall(data)
    if not chunks:
        return data.strip()
    return "".join(c.replace('\\"', '"') for c in chunks)


async def doh_query(client: httpx.AsyncClient, resolver: str, name: str, rtype: str) -> dict[str, Any]:
    url = DOH_RESOLVERS[resolver]
    out: dict[str, Any] = {"resolver": resolver, "name": name, "type": rtype}
    try:
        resp = await client.get(
            url,
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        out.update(rcode="ERROR", answers=[], error=str(exc) or exc.__class__.__name__)
        return out
    out["rcode"] = RCODES.get(data.get("Status"), str(data.get("Status")))
    answers = []
    for a in data.get("Answer") or []:
        t = RR_NAMES.get(a.get("type"), str(a.get("type")))
        value = a.get("data", "")
        if t == "TXT":
            value = txt_value(value)
        answers.append({"name": a.get("name", "").rstrip("."), "type": t, "ttl": a.get("TTL"), "data": value})
    out["answers"] = answers
    return out


async def doh_lookup(client: httpx.AsyncClient, name: str, rtype: str) -> dict[str, Any]:
    """Query Google first, fall back to Cloudflare."""
    res = await doh_query(client, "google", name, rtype)
    if res["rcode"] == "ERROR":
        res = await doh_query(client, "cloudflare", name, rtype)
    return res


def values(res: dict[str, Any], rtype: str) -> list[str]:
    return [a["data"] for a in res.get("answers", []) if a["type"] == rtype]


async def system_lookup(name: str, timeout: float) -> dict[str, Any]:
    """A/AAAA through the operating-system resolver - i.e. what *this machine* sees."""
    loop = asyncio.get_running_loop()
    out: dict[str, Any] = {"resolver": "system", "name": name}
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(name, 443, type=socket.SOCK_STREAM), timeout)
    except socket.gaierror as exc:
        out.update(rcode="NXDOMAIN" if exc.errno in (socket.EAI_NONAME,) else "ERROR", addresses=[], error=str(exc))
        return out
    except (asyncio.TimeoutError, TimeoutError):
        out.update(rcode="ERROR", addresses=[], error="timeout")
        return out
    addrs: list[str] = []
    for *_x, sockaddr in infos:
        a = sockaddr[0].split("%", 1)[0]
        if a not in addrs:
            addrs.append(a)
    out.update(rcode="NOERROR", addresses=sorted(addrs))
    return out


async def find_zone_ns(client: httpx.AsyncClient, host: str) -> tuple[str | None, list[str]]:
    """Walk up from ``host`` to find the zone that has NS records."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        res = await doh_lookup(client, zone, "NS")
        ns = [v.rstrip(".").lower() for v in values(res, "NS")]
        if ns and all(a["name"].lower() == zone for a in res["answers"] if a["type"] == "NS"):
            return zone, sorted(ns)
    return None, []


async def resolve_overview(host: str, policy: NetPolicy, include_system: bool) -> dict[str, Any]:
    """A/AAAA/CNAME from every public resolver (+ system), with a consistency verdict."""
    async with api_client(policy) as client:
        jobs = {
            (r, t): doh_query(client, r, host, t) for r in DOH_RESOLVERS for t in ("A", "AAAA")
        }
        results = dict(zip(jobs, await asyncio.gather(*jobs.values())))
        zone, ns = await find_zone_ns(client, host)
    system = await system_lookup(host, policy.connect_timeout) if include_system else None

    per_resolver: dict[str, dict[str, Any]] = {}
    cname_chain: list[str] = []
    for r in DOH_RESOLVERS:
        a, aaaa = results[(r, "A")], results[(r, "AAAA")]
        rcode = a["rcode"] if a["rcode"] != "NOERROR" else aaaa["rcode"]
        if a["rcode"] == "NOERROR" or aaaa["rcode"] == "NOERROR":
            rcode = "NOERROR"
        addrs = sorted(set(values(a, "A") + values(aaaa, "AAAA")))
        per_resolver[r] = {"rcode": rcode, "addresses": addrs}
        if a.get("error") and aaaa.get("error"):
            per_resolver[r]["error"] = a["error"]
        for ans in a["answers"]:
            if ans["type"] == "CNAME":
                target = ans["data"].rstrip(".").lower()
                if target not in cname_chain:
                    cname_chain.append(target)
    if system is not None:
        per_resolver["system"] = {k: system[k] for k in ("rcode", "addresses", "error") if k in system}

    return {
        "host": host,
        "resolvers": per_resolver,
        "cname_chain": cname_chain,
        "zone": zone,
        "nameservers": ns,
    }


def evaluate_overview(ov: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    public = {k: v for k, v in ov["resolvers"].items() if k != "system"}
    working = {k: v for k, v in public.items() if v["rcode"] != "ERROR"}
    host = ov["host"]

    if not working:
        findings.append(finding("dns", "warn", "Public DNS resolvers could not be reached",
                                "The checker itself could not query Google/Cloudflare DNS."))
    elif all(v["rcode"] == "NXDOMAIN" for v in working.values()):
        findings.append(finding(
            "dns", "fail", f"{host} does not exist in DNS (NXDOMAIN)",
            "Every public resolver says this name does not exist.",
            "Check the spelling, that the domain registration has not expired, and that the record exists at your DNS provider.",
        ))
    elif all(not v["addresses"] for v in working.values()):
        findings.append(finding(
            "dns", "fail", f"{host} has no A/AAAA records",
            "The name exists but points to no IP address.",
            "Add an A, AAAA or CNAME record at your DNS provider.",
        ))
    else:
        sets = {k: tuple(v["addresses"]) for k, v in working.items()}
        if len(set(sets.values())) == 1:
            addrs = next(iter(sets.values()))
            findings.append(finding("dns", "pass", f"DNS resolves consistently ({', '.join(addrs[:4])}"
                                    f"{'…' if len(addrs) > 4 else ''})"))
        else:
            detail = "; ".join(f"{k}: {', '.join(v) or 'none'}" for k, v in sets.items())
            findings.append(finding(
                "dns", "warn", "Public resolvers return different answers", detail,
                "If you changed DNS recently this is propagation and settles within the record's TTL. "
                "Otherwise check for geo/load-balanced DNS or an inconsistent nameserver.",
            ))

    system = ov["resolvers"].get("system")
    if system is not None and working:
        pub_addrs = set().union(*(set(v["addresses"]) for v in working.values()))
        if system["rcode"] != "NOERROR" and pub_addrs:
            findings.append(finding(
                "dns", "fail", "Your computer cannot resolve this name, but the internet can",
                system.get("error", ""),
                "Your local DNS (router, VPN or corporate resolver) is the problem. Try flushing the DNS cache, "
                "disconnecting the VPN, or switching to 1.1.1.1 / 8.8.8.8 to confirm.",
            ))
        elif system["addresses"] and pub_addrs and not set(system["addresses"]) & pub_addrs:
            findings.append(finding(
                "dns", "warn", "Your computer resolves this name to a different address than the internet",
                f"local: {', '.join(system['addresses'])}; public: {', '.join(sorted(pub_addrs)[:4])}",
                "This is normal for split-horizon / VPN DNS. If it is unexpected, check your hosts file and local DNS.",
            ))
    if ov.get("cname_chain"):
        findings.append(finding("dns", "info", "CNAME chain", " → ".join([host] + ov["cname_chain"])))
    return findings


async def check_dns(name: str, policy: NetPolicy, record_types: list[str] | None = None,
                    include_system: bool = False) -> dict[str, Any]:
    """Full DNS report for the ``check_dns`` tool."""
    host = normalize_domain(name, policy)
    wanted = [t.upper() for t in (record_types or ["A", "AAAA", "CNAME"])]
    bad = [t for t in wanted if t not in RR_TYPES]
    if bad:
        raise ValueError(f"Unsupported record type(s): {', '.join(bad)}. Supported: {', '.join(RR_TYPES)}")
    ov = await resolve_overview(host, policy, include_system)
    findings = evaluate_overview(ov)
    records: dict[str, list[dict[str, Any]]] = {}
    extra = [t for t in wanted if t not in ("A", "AAAA")]
    if extra:
        async with api_client(policy) as client:
            res = await asyncio.gather(*(doh_lookup(client, host, t) for t in extra))
        for t, r in zip(extra, res):
            records[t] = [{"data": a["data"], "ttl": a["ttl"]} for a in r["answers"] if a["type"] == t]
    result = {**ov, "records": records, "findings": findings, "status": worst(findings)}
    extra_lines = []
    if ov["nameservers"]:
        extra_lines.append(f"Nameservers ({ov['zone']}): {', '.join(ov['nameservers'])}")
    for t, rows in records.items():
        extra_lines.append(f"{t}: " + (", ".join(r["data"] for r in rows) or "none"))
    result["summary"] = text_report(f"DNS report for {host}", findings, extra_lines)
    return result
