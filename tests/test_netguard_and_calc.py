import pytest

from personal_mcp.netguard import (HOSTED_POLICY, LOCAL_POLICY, TargetError, normalize_domain, parse_target,
                                   resolve_checked)
from personal_mcp.safe_eval import CalcError, safe_eval


@pytest.mark.parametrize("raw", [
    "http://127.0.0.1/", "https://10.0.0.5", "192.168.1.1", "http://169.254.169.254/latest/meta-data/",
    "https://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fd00::1]/", "100.64.0.1", "0.0.0.0",
    "localhost", "http://localhost:8000", "metadata.google.internal", "printer.local", "db.internal",
    "intranet", "2130706433", "0x7f000001", "ftp://example.com", "file:///etc/passwd",
    "https://user:pass@example.com", "example.com:22", "example.com:6379", "gopher://example.com",
    "http://224.0.0.1/",
])
def test_hosted_policy_rejects(raw):
    with pytest.raises(TargetError):
        parse_target(raw, HOSTED_POLICY)


@pytest.mark.parametrize("raw,host,port,scheme,path", [
    ("example.com", "example.com", 443, "https", "/"),
    ("http://Example.COM./a?b=1", "example.com", 80, "http", "/a?b=1"),
    ("https://example.com:8443/x", "example.com", 8443, "https", "/x"),
    ("bücher.de", "xn--bcher-kva.de", 443, "https", "/"),
    ("8.8.8.8", "8.8.8.8", 443, "https", "/"),
])
def test_hosted_policy_accepts(raw, host, port, scheme, path):
    t = parse_target(raw, HOSTED_POLICY)
    assert (t.host, t.port, t.scheme, t.path) == (host, port, scheme, path)


def test_local_policy_allows_internal():
    assert parse_target("http://192.168.1.10:5000", LOCAL_POLICY).port == 5000
    assert parse_target("nas", LOCAL_POLICY).host == "nas"


def test_normalize_domain():
    assert normalize_domain("ops@Example.com", HOSTED_POLICY) == "example.com"
    assert normalize_domain("https://mail.example.com/x", HOSTED_POLICY) == "mail.example.com"
    assert normalize_domain("_dmarc.example.com", HOSTED_POLICY) == "_dmarc.example.com"
    with pytest.raises(TargetError):
        normalize_domain("1.2.3.4", HOSTED_POLICY)


async def test_resolution_to_private_ip_is_blocked():
    # "127.1" passes syntax checks but resolves to 127.0.0.1 - the resolver check must stop it.
    t = parse_target("http://127.1/", HOSTED_POLICY)
    with pytest.raises(TargetError, match="private"):
        await resolve_checked(t.host, t.port, HOSTED_POLICY)


async def test_resolution_allowed_locally():
    assert await resolve_checked("localhost", 80, LOCAL_POLICY)


@pytest.mark.parametrize("expr,expected", [
    ("2**10", 1024), ("sqrt(144)", 12.0), ("45 * 12.5", 562.5), ("2^3", 8), ("-(3+4)*2", -14),
    ("max(1, 5, 3)", 5), ("round(pi, 2)", 3.14), ("log10(1000)", 3.0), ("10 // 3 + 10 % 3", 4),
])
def test_safe_eval_ok(expr, expected):
    assert safe_eval(expr) == pytest.approx(expected)


@pytest.mark.parametrize("expr", [
    "().__class__", "__import__('os').system('id')", "[x for x in ()]", "open('/etc/passwd')",
    "9**9**9", "factorial(100000)", "a", "lambda: 1", "'abc'", "True + 1", "(1).real", "x" * 400,
])
def test_safe_eval_rejects(expr):
    with pytest.raises((CalcError, TypeError)):
        safe_eval(expr)
