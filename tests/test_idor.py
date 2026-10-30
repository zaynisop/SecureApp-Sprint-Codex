"""IDOR (CWE-639): a non-owner with no share grant must be denied (403)."""
from conftest import login


def test_owner_can_download_own_file(client):
    login(client, "alice", "alice-password-1")
    r = client.get("/file/1/download")
    assert r.status_code == 200
    assert b"alice-secret" in r.data


def test_idor_other_user_is_forbidden(client):
    # mallory does NOT own file id=1 and it was never shared with her.
    login(client, "mallory", "mallory-pass-9")
    r = client.get("/file/1/download")
    assert r.status_code == 403          # object-level authorization enforced


def test_unauthenticated_is_redirected_to_login(client):
    r = client.get("/file/1/download", follow_redirects=False)
    assert r.status_code in (302, 401)
