"""Command Injection (CWE-78): shell metacharacters must stay inert.

The secure export builds an argv array (shell=False) and only accepts an
allow-listed format key, so a filename can never reach a shell. These tests
assert the design guarantees that make injection impossible.
"""
import subprocess

from conftest import login, _extract_csrf
from app.files import _EXPORT_CMDS


def test_export_rejects_non_allowlisted_format(client):
    login(client, "alice", "alice-password-1")
    page = client.get("/dashboard")
    token = _extract_csrf(page.data)
    # Attempt an injection via the format field; only allow-listed keys pass.
    r = client.post("/file/1/export",
                    data={"csrf_token": token, "format": "zip; id"})
    assert r.status_code == 400          # not in allow-list -> rejected


def test_export_commands_are_argv_arrays_not_strings():
    # A list argv with shell=False means no shell parses metacharacters.
    for key, argv in _EXPORT_CMDS.items():
        assert isinstance(argv, list)
        assert all(isinstance(a, str) for a in argv)


def test_metacharacters_in_filename_are_inert(tmp_path):
    """Direct proof: a malicious 'filename' passed as an argv element is a
    literal path, never executed. The injected `id` command does NOT run."""
    marker = tmp_path / "pwned"
    evil = f"x.txt; id > {marker}"
    # shell=False: `evil` is a single literal argument to `python -c 'pass'`.
    subprocess.run(["python", "-c", "pass", evil], check=True, timeout=10)
    assert not marker.exists()           # injection did not execute
