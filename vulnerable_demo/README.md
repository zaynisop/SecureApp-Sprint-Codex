# ⚠️ vulnerable_demo/ — LAB-ONLY Proof-of-Concept code

**Do NOT deploy. Do NOT import any of this into the running application.**

This directory holds deliberately insecure reference snippets and exploit
proof-of-concepts used **only** to demonstrate each mandatory vulnerability
class *before* its fix, as required by the CYC386 midterm lab
(Section 6.4). The production application under `app/` is secure; these files
are never loaded by it.

Every demonstration here targets **only this team's own application running on
`127.0.0.1`**, in line with Section 9 (Academic Integrity & Ethical Boundaries).

| # | Class | Vulnerable artefact | Fixed in |
|---|-------|--------------------|----------|
| 1 | Buffer Overflow (CWE-120) | `../native/thumbgen_vuln.c` | `../native/thumbgen_secure.c` |
| 2 | Command Injection (CWE-78) | `01_command_injection_vuln.py` | `app/files.py::export` |
| 3 | IDOR (CWE-639) | `02_idor_vuln.py` | `app/files.py::download` |
| 4 | CSRF (CWE-352) | `03_csrf_attack.html` | global `CSRFProtect` + `SameSite` |
| 5 | Clickjacking (CWE-1021) | `04_clickjacking_frame.html` | `X-Frame-Options` + CSP `frame-ancestors` |

See `docs/SECURITY_IMPLEMENTATION.md` for the full before → PoC → after → verify
write-up with screenshots.
