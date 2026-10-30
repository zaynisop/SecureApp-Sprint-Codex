"""Application factory.

Wires extensions and registers the security-header hook that defends
against Clickjacking, MIME-sniffing and related UI-layer attacks.
"""
import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)

    os.makedirs(os.path.join(app.config["UPLOAD_DIR"]), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(app.root_path), "instance"), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"
    csrf.init_app(app)           # CSRF protection on ALL state-changing POST routes
    limiter.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from .auth import auth_bp
    from .files import files_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)

    register_security_headers(app)

    with app.app_context():
        db.create_all()

    return app


def register_security_headers(app):
    """Defence-in-depth HTTP response headers applied to every response."""

    @app.after_request
    def set_secure_headers(resp):
        # --- Clickjacking (CWE-1021) ---
        resp.headers["X-Frame-Options"] = "DENY"
        # --- Content Security Policy: no framing + no inline-script injection ---
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        # --- MIME sniffing ---
        resp.headers["X-Content-Type-Options"] = "nosniff"
        # --- Referrer / permissions ---
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # --- HSTS (effective once served over HTTPS) ---
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return resp
