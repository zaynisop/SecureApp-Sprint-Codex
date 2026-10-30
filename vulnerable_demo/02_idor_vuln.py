"""LAB-ONLY — IDOR (CWE-639) VULNERABLE reference.

Insecure version of the download route. The running app uses the secure
version in app/files.py::download, which calls File.is_accessible_by().

THE BUG
-------
The handler fetches the file by the `file_id` from the URL and returns it
WITHOUT verifying that the current user owns or has been granted the file.
Any authenticated user can enumerate IDs and read everyone's files:

    GET /file/1/download
    GET /file/2/download   <-- another user's private file
    GET /file/3/download   <-- ...

PROOF OF CONCEPT (against our own localhost app only)
-----------------------------------------------------
    login as alice (owns file id=5)
    as attacker 'mallory', request /file/5/download  ->  200 OK (LEAK)
"""


def download_VULNERABLE(db, send_file, current_user, file_id):
    f = db.session.get(File, file_id)          # noqa: F821 (illustrative)
    if f is None:
        return 404
    # VULNERABLE: no object-level authorization check at all.
    return send_file(f.path)                    # returns ANY user's file


# ---------------------------------------------------------------------------
# SECURE pattern (app/files.py::download):
#
#   f = db.session.get(File, file_id)
#   if f is None: abort(404)
#   if not f.is_accessible_by(current_user):   # owner OR explicit share grant
#       abort(403)
#   return send_file(path, as_attachment=True, download_name=f.original_name)
# ---------------------------------------------------------------------------
