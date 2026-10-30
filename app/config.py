"""Application configuration.

Secrets come from the environment (.env in dev). Secure cookie flags are
ON by default and only relaxed for local HTTP development.
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    # SECRET_KEY must be set in production. A random dev key avoids hardcoding.
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'secureshare.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ---- Uploads ----
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB hard cap (availability / DoS)
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "md", "csv", "log"}

    # ---- Session / cookie hardening ----
    SESSION_COOKIE_HTTPONLY = True          # block JS cookie theft (XSS mitigation)
    SESSION_COOKIE_SAMESITE = "Lax"         # CSRF defence-in-depth
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"  # 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # ---- CSRF (Flask-WTF) ----
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = False  # dev over HTTP; set True in production


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = True  # keep CSRF ON so the CSRF tests are meaningful
    SECRET_KEY = "test-secret-key-not-for-production"
    UPLOAD_DIR = os.path.join(BASE_DIR, "instance", "test_uploads")
