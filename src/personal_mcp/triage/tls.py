"""TLS certificate checks (expiry, hostname match, trust chain, protocol)."""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
from typing import Any

from ..netguard import NetPolicy, Target, TargetError, parse_target, resolve_checked
from .common import finding, ssl_context, text_report, worst


def _parse_der(der: bytes) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:  # pragma: no cover - cryptography is a hard dependency
        return {}
    cert = x509.load_der_x509_certificate(der)

    def _name(n: x509.Name) -> str:
        for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
            attrs = n.get_attributes_for_oid(oid)
            if attrs:
                return str(attrs[0].value)
        return n.rfc4514_string()

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "self_signed": cert.issuer == cert.subject,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - now).days if not_after > now else -((now - not_after).days + 1),
        "sans": sans[:50],
        "serial": format(cert.serial_number, "x"),
    }


async def _handshake(ip: str, port: int, server_hostname: str | None, ctx: ssl.SSLContext,
                     timeout: float) -> tuple[bytes, str | None, str | None]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_hostname,
                                ssl_handshake_timeout=timeout),
        timeout=timeout + 1,
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) or b""
        cipher = sslobj.cipher()
        return der, sslobj.version(), cipher[0] if cipher else None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:
            pass


async def inspect_tls(target: Target, policy: NetPolicy, ips: list[str] | None = None) -> dict[str, Any]:
    port = target.port if target.scheme == "https" else 443
    if ips is None:
        ips = await resolve_checked(target.host, port, policy)
    ip = ips[0]
    sni = target.host  # for IP targets Python skips SNI but still matches IP SANs
    out: dict[str, Any] = {"host": target.host, "port": port, "ip": ip}
    try:
        der, version, cipher = await _handshake(ip, port, sni, ssl_context(policy), policy.connect_timeout)
        out.update(verified=True, protocol=version, cipher=cipher)
    except ssl.SSLCertVerificationError as exc:
        out.update(verified=False, verify_error=exc.verify_message or str(exc))
        try:
            der, version, cipher = await _handshake(ip, port, sni, ssl_context(policy, verify=False),
                                                    policy.connect_timeout)
            out.update(protocol=version, cipher=cipher)
        except Exception:
            der = b""
    except ssl.SSLError as exc:
        out.update(verified=False, handshake_error=exc.reason or str(exc))
        return out
    except (asyncio.TimeoutError, TimeoutError):
        out.update(verified=False, connect_error=f"Timed out connecting to {ip}:{port}")
        return out
    except OSError as exc:
        out.update(verified=False, connect_error=f"{exc.strerror or exc} ({ip}:{port})")
        return out
    if der:
        out["certificate"] = _parse_der(der)
    return out


def evaluate_tls(info: dict[str, Any]) -> list[dict[str, Any]]:
    f: list[dict[str, Any]] = []
    host = info["host"]
    if "connect_error" in info:
        f.append(finding("tls", "fail", f"Cannot connect to port {info['port']}", info["connect_error"],
                         "The server is down, the port is closed, or a firewall is blocking it."))
        return f
    if "handshake_error" in info:
        f.append(finding("tls", "fail", "TLS handshake failed", info["handshake_error"],
                         "The server is not speaking TLS on this port or has a broken TLS configuration."))
        return f
    cert = info.get("certificate", {})
    days = cert.get("days_left")
    err = (info.get("verify_error") or "").lower()
    if days is not None and days < 0:
        f.append(finding("tls", "fail", f"Certificate EXPIRED {-days} day(s) ago",
                         f"Expired {cert.get('not_after', '')[:10]} (issuer: {cert.get('issuer', '?')})",
                         "Renew the certificate now (e.g. `certbot renew`, or renew in your CDN/load balancer) "
                         "and make sure auto-renewal is running."))
    elif "hostname mismatch" in err or "doesn't match" in err or "not valid for" in err:
        sans = ", ".join(cert.get("sans", [])[:6]) or cert.get("subject", "?")
        f.append(finding("tls", "fail", f"Certificate is not valid for {host}", f"It covers: {sans}",
                         f"Issue a certificate that includes {host}, or point DNS at the server that has one."))
    elif cert.get("self_signed") or "self-signed" in err or "self signed" in err:
        f.append(finding("tls", "fail", "Certificate is self-signed", info.get("verify_error", ""),
                         "Browsers will block this site. Use a certificate from a public CA such as Let's Encrypt."))
    elif not info.get("verified"):
        f.append(finding("tls", "fail", "Certificate is not trusted", info.get("verify_error", ""),
                         "The chain is incomplete or from an unknown CA. Install the full chain (leaf + intermediates)."))
    elif days is not None and days <= 14:
        f.append(finding("tls", "warn", f"Certificate expires in {days} day(s)", cert.get("not_after", "")[:10],
                         "Renew soon and check that auto-renewal works."))
    else:
        exp = f", expires in {days} days" if days is not None else ""
        f.append(finding("tls", "pass", f"Certificate valid{exp}", f"Issuer: {cert.get('issuer', '?')}"))
    proto = info.get("protocol")
    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        f.append(finding("tls", "warn", f"Outdated protocol {proto}", "", "Enable TLS 1.2 and 1.3 on the server."))
    return f


async def check_tls(url: str, policy: NetPolicy) -> dict[str, Any]:
    target = parse_target(url, policy)
    if target.scheme == "http":
        target = Target("https", target.host, 443, target.path, target.is_ip)
        if policy.allowed_ports is not None and 443 not in policy.allowed_ports:  # pragma: no cover
            raise TargetError("Port 443 is not allowed.")
    info = await inspect_tls(target, policy)
    findings = evaluate_tls(info)
    info.update(findings=findings, status=worst(findings))
    cert = info.get("certificate") or {}
    extra = []
    if cert:
        extra.append(f"Subject: {cert.get('subject')} | Issuer: {cert.get('issuer')} | "
                     f"Valid until: {cert.get('not_after', '')[:10]}")
        if cert.get("sans"):
            extra.append("Names: " + ", ".join(cert["sans"][:10]))
    if info.get("protocol"):
        extra.append(f"Protocol: {info['protocol']} ({info.get('cipher')})")
    info["summary"] = text_report(f"TLS report for {target.host}:{info['port']}", findings, extra)
    return info
