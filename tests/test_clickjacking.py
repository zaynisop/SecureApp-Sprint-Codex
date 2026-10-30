"""Clickjacking (CWE-1021): anti-framing headers present on every response."""
from conftest import login


def test_security_headers_on_public_page(client):
    r = client.get("/login")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


def test_security_headers_on_authenticated_page(client):
    login(client, "alice", "alice-password-1")
    r = client.get("/dashboard")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in r.headers.get("Content-Security-Policy", "")
