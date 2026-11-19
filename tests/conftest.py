"""Test fixtures: a private CA and tiny local HTTPS/HTTP servers with good and broken certificates."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from personal_mcp.netguard import NetPolicy

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn: str, sans: list[str], issuer_key, issuer_name, key, *, not_before, not_after, ca=False):
    alt = []
    for s in sans:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            alt.append(x509.DNSName(s))
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn)).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after))
    if alt:
        b = b.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    else:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _pem(obj) -> bytes:
    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM)
    return obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("pki")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Test Root CA", [], ca_key, _name("Test Root CA"), ca_key,
               not_before=NOW - dt.timedelta(days=30), not_after=NOW + dt.timedelta(days=3650), ca=True)
    (d / "ca.pem").write_bytes(_pem(ca))
    files = {"ca": d / "ca.pem"}

    def leaf(kind: str, cn: str, sans: list[str], nb, na, self_signed=False):
        key = ec.generate_private_key(ec.SECP256R1())
        if self_signed:
            cert = _cert(cn, sans, key, _name(cn), key, not_before=nb, not_after=na)
        else:
            cert = _cert(cn, sans, ca_key, ca.subject, key, not_before=nb, not_after=na)
        (d / f"{kind}.crt").write_bytes(_pem(cert))
        (d / f"{kind}.key").write_bytes(_pem(key))
        files[kind] = d / kind

    leaf("valid", "localhost", ["localhost", "127.0.0.1"], NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=90))
    leaf("expiring", "localhost", ["localhost", "127.0.0.1"], NOW - dt.timedelta(days=80), NOW + dt.timedelta(days=5))
    leaf("expired", "localhost", ["localhost", "127.0.0.1"], NOW - dt.timedelta(days=100), NOW - dt.timedelta(days=3))
    leaf("wronghost", "other.example", ["other.example"], NOW - dt.timedelta(days=1), NOW + dt.timedelta(days=90))
    leaf("selfsigned", "localhost", ["localhost", "127.0.0.1"], NOW - dt.timedelta(days=1),
         NOW + dt.timedelta(days=90), self_signed=True)
    return files


@pytest.fixture
def policy(pki) -> NetPolicy:
    return NetPolicy(allow_private=True, allowed_ports=None, connect_timeout=3, total_timeout=5,
                     ca_file=str(pki["ca"]))


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
    except Exception:
        writer.close()
        return
    path = head.split(b" ", 2)[1].decode()
    routes = {
        "/": (200, "OK", {}),
        "/503": (503, "Service Unavailable", {}),
        "/redir": (302, "Found", {"Location": "/"}),
        "/loop": (302, "Found", {"Location": "/loop"}),
        "/meta": (302, "Found", {"Location": "http://169.254.169.254/latest/meta-data/"}),
        "/cf": (200, "OK", {"Server": "cloudflare", "CF-RAY": "abc123-BOM"}),
    }
    code, reason, extra = routes.get(path, (404, "Not Found", {}))
    body = b"hello"
    hdrs = {"Content-Length": str(len(body)), "Connection": "close", **extra}
    resp = f"HTTP/1.1 {code} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    writer.write(resp.encode() + body)
    try:
        await writer.drain()
    finally:
        writer.close()


@pytest.fixture
async def serve(pki):
    servers = []

    async def start(kind: str | None) -> int:
        ctx = None
        if kind:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(f"{pki[kind]}.crt", f"{pki[kind]}.key")
        srv = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=ctx)
        servers.append(srv)
        return srv.sockets[0].getsockname()[1]

    yield start
    for s in servers:
        s.close()
        await s.wait_closed()
