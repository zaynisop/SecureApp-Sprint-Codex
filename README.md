# SecureApp-Sprint-Codex — SecureShare

A hardened file-sharing & collaboration service built for the **CYC386 — Secure
Software Design and Development** Midterm Lab Exam (Fall 2026): a one-week
DevSecOps security-engineering sprint.

> **Team Codex**
> | Name | Roll No | Role |
> |------|---------|------|
> | Zain Ali | FA23-BCT-059 | Backend / Secure implementation / CI-CD |
> | Nimra Umar | FA23-BCT-031 | Threat modeling / Testing / Documentation |

---

## What this is

**SecureShare** lets authenticated users upload files, share them with specific
users, preview and export them. The application is engineered to be
**attack-resistant** and demonstrates — then remediates — the five mandatory
vulnerability classes:

| Class | CWE | Where it lived | How it is fixed |
|-------|-----|----------------|-----------------|
| Buffer Overflow | CWE-120 | native C preview helper | bounds checking + `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, ASAN |
| Command Injection | CWE-78 | file export (shell) | `subprocess` argv array, `shell=False`, allow-list |
| IDOR | CWE-639 | file download/preview | object-level authorization (`File.is_accessible_by`) |
| CSRF | CWE-352 | delete / share / password | Flask-WTF synchronizer tokens + `SameSite` cookies |
| Clickjacking | CWE-1021 | all pages | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |

Every protection need maps to the **CIA triad** — see
[`docs/PNE_Report.md`](docs/PNE_Report.md).

## Architecture (at a glance)

```
Browser ──HTTPS──> Flask app (app/)
                     ├─ auth.py      sessions, Argon2id, rate-limit
                     ├─ files.py     upload/share/download/export (SECURE)
                     ├─ native.py ──ctypes──> native/thumbgen_secure.(so|dll)
                     └─ models.py ──> SQLite (users / files / shares)
```

Full context + Level-1 DFDs, STRIDE, attack trees and CVSS scoring:
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Build & run

### 1. Python app (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py            # http://127.0.0.1:5000
```

### 1. Python app (Linux/macOS)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### 2. Native helper (optional — app has a safe pure-Python fallback)
```powershell
# Windows (needs gcc/MinGW or MSVC)
./native/build.ps1
```
```bash
# Linux/macOS
make -C native secure
```

## Test
```bash
pytest tests -q            # 14 security/unit tests
```

## Security scanning (local)
```bash
bandit -r app -ll          # SAST gate (production code must be clean)
semgrep --config p/owasp-top-ten --config p/security-audit app/
```

The full pipeline (build → test → Bandit → Semgrep → CodeQL → OWASP ZAP) runs in
[`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) and **fails the
build on any high/critical finding**.

## Repository layout
```
app/                Flask application (SECURE)
native/             C preview helper: *_secure.c (used) and *_vuln.c (lab PoC)
vulnerable_demo/    LAB-ONLY insecure PoCs for the before/after demo — never deployed
tests/              pytest security suite
docs/               PNE, threat model, implementation, test report, final report
.github/workflows/  CI/CD pipeline
```

## Documentation index
- [PNE_Report.md](docs/PNE_Report.md) — assets, protection needs, CIA mapping
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) — DFDs, STRIDE, attack trees, CVSS
- [SECURITY_IMPLEMENTATION.md](docs/SECURITY_IMPLEMENTATION.md) — before → PoC → after → verify
- [SECURITY_TEST_REPORT.md](docs/SECURITY_TEST_REPORT.md) — SAST/DAST, before/after
- [FINAL_REPORT.md](docs/FINAL_REPORT.md) — IEEE-style final report
- [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

## Ethics
All exploitation is confined to this team's own application on `127.0.0.1` for
defensive education only (Section 9). Do not point any PoC at systems you do not
own.

## License
MIT — see [LICENSE](LICENSE).
