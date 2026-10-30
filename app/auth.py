"""Authentication blueprint: register, login, logout, change-password.

Security notes
--------------
* Passwords hashed with Argon2id (models.User).
* Login is rate-limited (brute-force / availability).
* Change-password is a state-changing POST -> protected by CSRF token
  (Flask-WTF, enabled globally) and re-auth of the current password.
"""
import re

from flask import (Blueprint, render_template, redirect, url_for, request,
                   flash, abort)
from flask_login import login_user, logout_user, login_required, current_user

from . import db, limiter
from .models import User

auth_bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,64}$")


def _valid_password(pw: str) -> bool:
    return isinstance(pw, str) and 8 <= len(pw) <= 128


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not USERNAME_RE.match(username):
            flash("Username must be 3-64 chars: letters, digits, underscore.", "error")
            return render_template("register.html"), 400
        if not _valid_password(password):
            flash("Password must be 8-128 characters.", "error")
            return render_template("register.html"), 400
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("register.html"), 409

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])  # brute-force protection
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        # Generic error message -> no username enumeration.
        if user is None or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        login_user(user)
        return redirect(url_for("files.dashboard"))
    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    if not current_user.check_password(current):
        abort(403)  # re-authentication failed
    if not _valid_password(new):
        flash("New password must be 8-128 characters.", "error")
        return redirect(url_for("files.dashboard"))
    current_user.set_password(new)
    db.session.commit()
    flash("Password updated.", "success")
    return redirect(url_for("files.dashboard"))
