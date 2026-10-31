"""Files blueprint — the SECURE implementation of all file operations.

This module is where four of the five mandatory vulnerability classes are
remediated (the fifth, Clickjacking, is handled by response headers in
app/__init__.py):

  * IDOR (CWE-639)             -> File.is_accessible_by() checked on every access
  * Command Injection (CWE-78)-> export uses subprocess arg-arrays, shell=False,
                                  with an allow-list; no user string ever reaches a shell
  * CSRF (CWE-352)             -> all mutating routes are POST + global CSRF tokens
  * Buffer Overflow (CWE-120)  -> previews go through app/native.py (bounds-checked)
"""
import os
import subprocess
import uuid

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, send_file, current_app, Response)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from . import db, limiter
from .models import File, Share, User
from .native import make_preview

files_bp = Blueprint("files", __name__)


def _allowed(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def _get_owned_file_or_403(file_id: int) -> File:
    """Fetch a file and enforce OWNER-ONLY authorization (mutations)."""
    f = db.session.get(File, file_id)
    if f is None:
        abort(404)
    if f.owner_id != current_user.id and not current_user.is_admin:
        abort(403)  # object-level authorization
    return f


@files_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("files.dashboard"))
    return render_template("index.html")


@files_bp.route("/dashboard")
@login_required
def dashboard():
    owned = File.query.filter_by(owner_id=current_user.id).all()
    shared = (File.query.join(Share, Share.file_id == File.id)
              .filter(Share.grantee_id == current_user.id).all())
    users = User.query.filter(User.id != current_user.id).all()
    return render_template("dashboard.html", owned=owned, shared=shared, users=users)


@files_bp.route("/upload", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("files.dashboard"))

    original = secure_filename(file.filename)  # strips path traversal
    if not original or not _allowed(original):
        flash("File type not allowed.", "error")
        return redirect(url_for("files.dashboard"))

    # Server-generated storage name -> no user-controlled path component.
    ext = original.rsplit(".", 1)[-1].lower()
    stored = f"{uuid.uuid4().hex}.{ext}"
    dest = os.path.join(current_app.config["UPLOAD_DIR"], stored)
    file.save(dest)

    rec = File(stored_name=stored, original_name=original,
               owner_id=current_user.id, size=os.path.getsize(dest))
    db.session.add(rec)
    db.session.commit()
    flash(f"Uploaded {original}.", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/file/<int:file_id>/download")
@login_required
def download(file_id):
    f = db.session.get(File, file_id)
    if f is None:
        abort(404)
    # IDOR FIX: object-level authorization on every read.
    if not f.is_accessible_by(current_user):
        abort(403)
    path = os.path.join(current_app.config["UPLOAD_DIR"], f.stored_name)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f.original_name)


@files_bp.route("/file/<int:file_id>/preview")
@login_required
def preview(file_id):
    f = db.session.get(File, file_id)
    if f is None:
        abort(404)
    if not f.is_accessible_by(current_user):
        abort(403)
    path = os.path.join(current_app.config["UPLOAD_DIR"], f.stored_name)
    with open(path, "rb") as fh:
        data = fh.read(256)
    # Buffer-overflow-safe native preview (bounds-checked wrapper).
    text = make_preview(data)
    return Response(text, mimetype="text/plain")


@files_bp.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete(file_id):
    f = _get_owned_file_or_403(file_id)  # CSRF token enforced by global CSRFProtect
    path = os.path.join(current_app.config["UPLOAD_DIR"], f.stored_name)
    if os.path.exists(path):
        os.remove(path)
    db.session.delete(f)
    db.session.commit()
    flash("File deleted.", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/file/<int:file_id>/share", methods=["POST"])
@login_required
def share(file_id):
    f = _get_owned_file_or_403(file_id)
    grantee_name = (request.form.get("grantee") or "").strip()
    grantee = User.query.filter_by(username=grantee_name).first()
    if grantee is None or grantee.id == current_user.id:
        flash("Invalid share recipient.", "error")
        return redirect(url_for("files.dashboard"))
    if not any(s.grantee_id == grantee.id for s in f.shares):
        db.session.add(Share(file_id=f.id, grantee_id=grantee.id))
        db.session.commit()
    flash(f"Shared with {grantee.username}.", "success")
    return redirect(url_for("files.dashboard"))


# Allow-listed export formats -> the ONLY values that may reach the tool.
_EXPORT_CMDS = {
    "zip": ["python", "-c",
            "import sys,zipfile; "
            "z=zipfile.ZipFile(sys.argv[2],'w'); z.write(sys.argv[1]); z.close()"],
}


@files_bp.route("/file/<int:file_id>/export", methods=["POST"])
@login_required
def export(file_id):
    """Export a file to an archive.

    COMMAND-INJECTION FIX: the user chooses only an allow-listed format key;
    the filename never reaches a shell. subprocess is called with an argument
    ARRAY and shell=False, so metacharacters (; | && `$()`) are inert.
    """
    f = _get_owned_file_or_403(file_id)
    fmt = (request.form.get("format") or "zip").lower()
    if fmt not in _EXPORT_CMDS:
        abort(400)

    src = os.path.join(current_app.config["UPLOAD_DIR"], f.stored_name)
    out = os.path.join(current_app.config["UPLOAD_DIR"], f"{f.stored_name}.{fmt}")

    cmd = _EXPORT_CMDS[fmt] + [src, out]
    try:
        # shell=False (default): argv array, no shell interpretation.
        #
        # SAST triage (Semgrep, p/security-audit + p/owasp-top-ten): the two
        # rules below flag ANY subprocess call that is data-flow-reachable from
        # request data. Here the executable + args are an allow-listed CONSTANT
        # (_EXPORT_CMDS[fmt]; `fmt` is rejected with HTTP 400 above unless it is
        # an allow-list key), the call uses an argv ARRAY with shell=False, and
        # the only request-derived values (src/out) are server-generated UUID
        # paths — never a shell string. Command injection is therefore
        # impossible, as proved by tests/test_command_injection.py. Accepted as
        # a documented false positive; see docs/SECURITY_TEST_REPORT.md §4.1.
        # nosemgrep: python.flask.security.injection.subprocess-injection.subprocess-injection,python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use
        subprocess.run(cmd, check=True, timeout=15, capture_output=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        flash("Export failed.", "error")
        return redirect(url_for("files.dashboard"))

    return send_file(out, as_attachment=True,
                     download_name=f"{f.original_name}.{fmt}")
