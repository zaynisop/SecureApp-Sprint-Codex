"""CSRF (CWE-352): state-changing POST without a valid token must be rejected."""
from conftest import login, _extract_csrf


def test_delete_without_csrf_token_is_rejected(client):
    login(client, "alice", "alice-password-1")
    # Forged request: no csrf_token field (as a cross-site attacker would send).
    r = client.post("/file/1/delete", data={})
    assert r.status_code == 400          # CSRFProtect blocks it


def test_delete_with_valid_csrf_token_succeeds(client):
    login(client, "alice", "alice-password-1")
    page = client.get("/dashboard")
    token = _extract_csrf(page.data)
    r = client.post("/file/1/delete", data={"csrf_token": token},
                    follow_redirects=True)
    assert r.status_code == 200          # legitimate same-site request works
