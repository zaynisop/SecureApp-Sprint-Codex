"""Shared pytest fixtures: app, client, and seeded users."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app, db          # noqa: E402
from app.config import TestConfig       # noqa: E402
from app.models import User, File       # noqa: E402


@pytest.fixture
def app():
    app = create_app(TestConfig)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    with app.app_context():
        db.create_all()
        alice = User(username="alice"); alice.set_password("alice-password-1")
        mallory = User(username="mallory"); mallory.set_password("mallory-pass-9")
        db.session.add_all([alice, mallory])
        db.session.commit()
        # alice owns one private file
        rec = File(stored_name="alicefile.txt", original_name="secret.txt",
                   owner_id=alice.id, size=12)
        db.session.add(rec)
        db.session.commit()
        with open(os.path.join(app.config["UPLOAD_DIR"], "alicefile.txt"), "w") as fh:
            fh.write("alice-secret")
    yield app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password):
    """Log in through the real form, carrying the CSRF token."""
    page = client.get("/login")
    token = _extract_csrf(page.data)
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": token,
    }, follow_redirects=True)


def _extract_csrf(html_bytes):
    html = html_bytes.decode()
    marker = 'name="csrf_token" value="'
    i = html.find(marker)
    if i == -1:
        return ""
    i += len(marker)
    return html[i:html.find('"', i)]
