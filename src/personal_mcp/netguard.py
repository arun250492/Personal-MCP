"""Target parsing and SSRF protection for the network triage tools.

Two policies exist:

* ``LOCAL_POLICY`` - used when the server runs on the user's own machine.
  Internal hosts (192.168.x.x, intranet names, any port) are allowed because
  checking them is the point of a local troubleshooting tool.
* ``HOSTED_POLICY`` - used by the public ChatGPT deployment. Only public
  internet addresses on web ports are reachable, so the server cannot be used
  to probe the hosting provider's private network or cloud metadata endpoints.

Every connection made by the triage tools is *pinned* to an IP address that
was checked here, so a DNS answer that changes between the check and the
connection (DNS rebinding) cannot redirect a request to an internal address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "HOSTED_POLICY",
    "LOCAL_POLICY",
    "NetPolicy",
    "Target",
    "TargetError",
    "format_host_for_url",
    "ip_is_public",
    "normalize_domain",
    "parse_target",
    "resolve_checked",
]


class TargetError(ValueError):
    """The requested target is malformed or not allowed by the active policy."""


@dataclass(frozen=True)
class NetPolicy:
    allow_private: bool = False
    allowed_ports: frozenset[int] | None = frozenset({80, 443, 8080, 8443})
    connect_timeout: float = 5.0
    total_timeout: float = 10.0
    # Extra CA bundle (PEM path) trusted in addition to the system store. Used by tests.
    ca_file: str | None = None
    # Honour HTTP(S)_PROXY env vars. Hosted mode must not, or IP pinning is bypassed.
    trust_env: bool = False


LOCAL_POLICY = NetPolicy(allow_private=True, allowed_ports=None, trust_env=True)
HOSTED_POLICY = NetPolicy()

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")

_BLOCKED_NAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "kubernetes",
    "kubernetes.default",
}
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".home.arpa",
    ".cluster.local",
    ".svc",
)


@dataclass(frozen=True)
class Target:
    scheme: str  # "http" | "https"
    host: str  # ASCII, lower-case, no trailing dot, no brackets for IPv6
    port: int
    path: str  # path + query, always starts with "/"
    is_ip: bool

    @property
    def default_port(self) -> bool:
        return (self.scheme, self.port) in (("http", 80), ("https", 443))

    @property
    def host_header(self) -> str:
        h = format_host_for_url(self.host)
        return h if self.default_port else f"{h}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host_header}{self.path}"


def ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip_is_public(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return ip_is_public(ip.sixtofour)
        if ip.teredo is not None:
            return False
    return bool(ip.is_global) and not ip.is_multicast


def format_host_for_url(host: str) -> str:
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _check_hostname(host: str, policy: NetPolicy) -> str:
    host = host.rstrip(".").lower()
    if not host:
        raise TargetError("Empty hostname.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"Invalid internationalised hostname: {exc}") from None
    if not _HOSTNAME_RE.match(host):
        raise TargetError(f"'{host}' is not a valid hostname.")
    if not policy.allow_private:
        if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
            raise TargetError(f"'{host}' is an internal name. The hosted checker only tests public internet services.")
        if "." not in host:
            raise TargetError("Use a fully qualified public domain name (for example example.com); "
                              "single-label internal names are not checked.")
    return host


def normalize_domain(raw: str, policy: NetPolicy) -> str:
    """Normalise a bare domain (used for DNS and e-mail checks)."""
    raw = (raw or "").strip()
    if "://" in raw or "/" in raw or "@" in raw:
        # Accept a URL or an e-mail address and keep only the domain part.
        if "@" in raw and "://" not in raw:
            raw = raw.rsplit("@", 1)[1]
        else:
            return parse_target(raw, policy).host
    if ":" in raw and raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(raw.strip("[]"))
    except ValueError:
        return _check_hostname(raw, policy)
    raise TargetError(f"'{ip}' is an IP address; a domain name is needed for this check.")


def parse_target(raw: str, policy: NetPolicy) -> Target:
    """Parse ``example.com``, ``https://example.com/x`` or ``example.com:8443``."""
    raw = (raw or "").strip()
    if not raw:
        raise TargetError("No URL or hostname given.")
    if len(raw) > 2048:
        raise TargetError("URL is too long.")
    if any(c.isspace() for c in raw):
        raise TargetError("URL must not contain spaces.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetError(f"Only http and https URLs can be checked (got '{scheme}').")
    if parts.username or parts.password:
        raise TargetError("URLs with embedded usernames or passwords are not accepted.")
    host = parts.hostname
    if not host:
        raise TargetError("Could not find a hostname in that URL.")
    try:
        port = parts.port
    except ValueError:
        raise TargetError("Invalid port number.") from None
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise TargetError("Invalid port number.")

    is_ip = False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        host = _check_hostname(host, policy)
    else:
        is_ip = True
        host = str(ip)
        if not policy.allow_private and not ip_is_public(ip):
            raise TargetError(f"{ip} is a private or reserved address. The hosted checker only tests public internet services.")

    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(policy.allowed_ports))
        raise TargetError(f"Port {port} is not allowed here. Allowed ports: {allowed}.")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme=scheme, host=host, port=port, path=path, is_ip=is_ip)


async def resolve_checked(host: str, port: int, policy: NetPolicy) -> list[str]:
    """Resolve ``host`` with the system resolver and enforce the policy.

    Returns IP strings, IPv4 first. Raises :class:`TargetError` if the name does
    not resolve, or (hosted policy) if *any* answer is a non-public address.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not policy.allow_private and not ip_is_public(ip):
            raise TargetError(f"{ip} is a private or reserved address.")
        return [str(ip)]

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=policy.connect_timeout,
        )
    except (socket.gaierror, UnicodeError) as exc:
        raise TargetError(f"'{host}' does not resolve ({exc.args[-1] if exc.args else exc}).") from None
    except (asyncio.TimeoutError, TimeoutError):
        raise TargetError(f"DNS lookup for '{host}' timed out.") from None

    seen: list[str] = []
    for family, *_rest, sockaddr in infos:
        addr = sockaddr[0].split("%", 1)[0]
        if addr not in seen:
            seen.append(addr)
    if not seen:
        raise TargetError(f"'{host}' has no addresses.")
    if not policy.allow_private:
        bad = [a for a in seen if not ip_is_public(ipaddress.ip_address(a))]
        if bad:
            raise TargetError(
                f"'{host}' resolves to a private or reserved address ({bad[0]}). "
                "The hosted checker only tests public internet services."
            )
    seen.sort(key=lambda a: ":" in a)  # IPv4 first
    return seen
