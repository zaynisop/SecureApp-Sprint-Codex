# Theme Selection / Proposal (Submit within first 24 hours)
### Team Codex · CYC386 Midterm Lab Exam (Fall 2026)

**Team members:** Zain Ali (FA23-BCT-059), Nimra Umar (FA23-BCT-031)
**Team name:** Codex
**Selected theme:** File Sharing / Collaboration (recommended theme, §3.1)
**Application name:** SecureShare
**Repository:** `SecureApp-Sprint-Codex`

## Application domain
A web-based file-sharing and collaboration service. Users register, upload
files, share them with specific users, preview and export files. The service is
session-authenticated with an admin role.

## Planned architecture
- **Backend:** Python Flask (blueprints: auth, files) with SQLAlchemy/SQLite.
- **AuthN/Z:** Flask-Login sessions + Argon2id; explicit owner/share model for
  object-level authorization.
- **Native component:** a C preview helper invoked via `ctypes` (memory-unsafe
  surface for the Buffer Overflow demonstration).
- **Frontend:** Jinja2 templates with a strict Content Security Policy.
- **CI/CD:** GitHub Actions (build, test, Bandit, Semgrep, CodeQL, OWASP ZAP).

## How each mandatory vulnerability class is introduced and fixed
| Class | Realistic attack surface | Fix |
|-------|--------------------------|-----|
| **Buffer Overflow (CWE-120)** | C preview helper copies file header bytes into a fixed stack buffer trusting a caller length | length clamp + `snprintf`, `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, ASAN |
| **Command Injection (CWE-78)** | file "export/convert" shells out with a user-controlled filename | argv array + `shell=False` + format allow-list |
| **IDOR (CWE-639)** | download/preview by numeric `file_id` | object-level authorization on every access |
| **CSRF (CWE-352)** | share / delete / change-password POSTs | Flask-WTF synchronizer tokens + `SameSite` cookies |
| **Clickjacking (CWE-1021)** | dashboard / share console framable | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |

## Why Buffer Overflow is realistic here
The preview helper is genuine native C (`native/thumbgen_*.c`) exercising a real
memory-unsafe copy; the overflow is demonstrated under AddressSanitizer and
remediated with bounds checking and compiler mitigations.

## CIA alignment
Every protection need maps to Confidentiality, Integrity, and/or Availability
(see `PNE_Report.md`). Example: object-level authorization protects
Confidentiality and Integrity of user files; rate limiting and the upload cap
protect Availability.

## Uniqueness
SecureShare is a self-built collaboration service (not a clone of another team's
app). Requesting approval on a first-come uniqueness basis.

> **Instructor approval:** _____________________  **Date:** ___________
