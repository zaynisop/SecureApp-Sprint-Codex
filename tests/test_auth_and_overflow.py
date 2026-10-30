"""Auth hardening + Buffer-Overflow-safe preview wrapper."""
from conftest import login, _extract_csrf
from app.native import make_preview


def test_password_is_hashed_not_plaintext(app):
    from app.models import User
    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        assert u.password_hash != "alice-password-1"
        assert u.password_hash.startswith("$argon2")   # Argon2id


def test_login_rejects_wrong_password(client):
    r = client.post("/login",
                    data={"username": "alice", "password": "wrong",
                          "csrf_token": _csrf(client)})
    assert r.status_code == 401


def test_make_preview_is_bounds_safe():
    # 4 KB of input must never overflow the 64-byte preview buffer.
    out = make_preview(b"A" * 4096)
    assert isinstance(out, str)
    assert len(out) <= 64


def test_make_preview_sanitises_binary():
    out = make_preview(bytes(range(256)))
    assert len(out) <= 64


def _csrf(client):
    page = client.get("/login")
    return _extract_csrf(page.data)
