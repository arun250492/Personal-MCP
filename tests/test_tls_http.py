from personal_mcp.triage.http_check import check_http
from personal_mcp.triage.tls import check_tls


def _statuses(r):
    return [(f["status"], f["title"]) for f in r["findings"]]


async def test_valid_certificate(serve, policy):
    port = await serve("valid")
    r = await check_tls(f"https://localhost:{port}", policy)
    assert r["verified"] is True
    assert r["status"] == "pass", _statuses(r)
    assert r["certificate"]["issuer"] == "Test Root CA"
    assert 88 <= r["certificate"]["days_left"] <= 90


async def test_ip_target_matches_ip_san(serve, policy):
    port = await serve("valid")
    r = await check_tls(f"https://127.0.0.1:{port}", policy)
    assert r["status"] == "pass", _statuses(r)


async def test_expiring_certificate_warns(serve, policy):
    port = await serve("expiring")
    r = await check_tls(f"https://localhost:{port}", policy)
    assert r["status"] == "warn"
    assert "expires in" in r["findings"][0]["title"]


async def test_expired_certificate(serve, policy):
    port = await serve("expired")
    r = await check_tls(f"https://localhost:{port}", policy)
    assert r["status"] == "fail"
    assert "EXPIRED" in r["findings"][0]["title"]
    assert "renew" in r["findings"][0]["fix"].lower()


async def test_hostname_mismatch(serve, policy):
    port = await serve("wronghost")
    r = await check_tls(f"https://localhost:{port}", policy)
    assert r["status"] == "fail"
    assert "not valid for localhost" in r["findings"][0]["title"]
    assert "other.example" in r["findings"][0]["detail"]


async def test_self_signed(serve, policy):
    port = await serve("selfsigned")
    r = await check_tls(f"https://localhost:{port}", policy)
    assert r["status"] == "fail"
    assert "self-signed" in r["findings"][0]["title"].lower()


async def test_closed_port(policy):
    r = await check_tls("https://127.0.0.1:1", policy)
    assert r["status"] == "fail"
    assert r["findings"][0]["title"].startswith("Cannot connect")


async def test_http_ok_and_redirect(serve, policy):
    port = await serve("valid")
    r = await check_http(f"https://localhost:{port}/redir", policy)
    assert r["status"] == "pass", _statuses(r)
    assert [h["status_code"] for h in r["hops"]] == [302, 200]
    assert "after 1 redirect" in r["findings"][0]["title"]


async def test_http_503(serve, policy):
    port = await serve(None)
    r = await check_http(f"http://127.0.0.1:{port}/503", policy)
    assert r["status"] == "fail"
    assert r["findings"][0]["title"].startswith("HTTP 503")
    assert "unavailable" in r["findings"][0]["fix"].lower()


async def test_http_redirect_loop(serve, policy):
    port = await serve(None)
    r = await check_http(f"http://127.0.0.1:{port}/loop", policy)
    assert r["status"] == "fail"
    assert r["findings"][0]["title"] == "Redirect loop"


async def test_http_expired_cert_still_reports_origin(serve, policy):
    port = await serve("expired")
    r = await check_http(f"https://localhost:{port}/", policy)
    assert r["final"]["status_code"] == 200
    assert r["final"]["insecure"] is True
    assert "tls_error" in r


async def test_redirect_to_metadata_blocked_by_hosted_rules(serve, policy):
    """A public site redirecting to the cloud metadata IP must not be followed in hosted mode."""
    from personal_mcp.netguard import HOSTED_POLICY, TargetError, parse_target
    import pytest
    with pytest.raises(TargetError):
        parse_target("http://169.254.169.254/latest/meta-data/", HOSTED_POLICY)
    # And locally the redirect is followed as a normal hop (internal targets are allowed on your own machine).
    port = await serve(None)
    r = await check_http(f"http://127.0.0.1:{port}/meta", policy)
    assert r["hops"][0]["status_code"] == 302
