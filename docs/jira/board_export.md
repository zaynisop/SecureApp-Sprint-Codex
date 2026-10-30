# Jira Sprint Board — SecureApp-Sprint-Codex
### Team Codex · CYC386 DevSecOps Sprint (Fall 2026)

Board type: Scrum · Sprint: **SecureShare Hardening Sprint 1 (7 days)**
Traceability chain: **PNE item → STRIDE threat → Jira issue → Fix (PR) → Test**.

> This Markdown is the human-readable board. `board_import.csv` in the same
> folder can be imported directly into Jira (System → External System Import →
> CSV) to recreate the board. Columns at submission time: **To Do / In Progress
> / Done**.

---

## Epics
| Key | Epic | Maps to |
|-----|------|---------|
| SCRUM-1 | PNE & CIA Mapping + Project Setup | CDF Unit 2, Phase 1 |
| SCRUM-2 | Threat Modeling & Quantitative Risk | CDF Unit 3, Phase 2 |
| SCRUM-3 | Secure Implementation (5 vuln classes) | CDF Unit 5, Phase 3 |
| SCRUM-4 | CI/CD & Automated Security Testing | Phase 4 |
| SCRUM-5 | Documentation, Demo & Hardening | Phase 5 |

---

## Stories & Tasks

### Epic SCRUM-1 — PNE & Setup
| Key | Type | Summary | Assignee | PNE/Ref | Status |
|-----|------|---------|----------|---------|--------|
| SCRUM-6 | Story | Asset inventory & stakeholder elicitation | Nimra | A1–A12 | Done |
| SCRUM-7 | Story | CIA mapping of all protection needs | Nimra | PN-01..PN-12 | Done |
| SCRUM-8 | Task | Initialize GitHub repo + branch protection on `main` | Zain | §6.1 | Done |
| SCRUM-9 | Task | Create Jira board (Epics→Stories→Tasks) | Nimra | §6.1 | Done |
| SCRUM-10 | Task | Theme proposal & approval (SecureShare) | Zain | §3 | Done |

### Epic SCRUM-2 — Threat Modeling
| Key | Type | Summary | Assignee | Ref | Status |
|-----|------|---------|----------|-----|--------|
| SCRUM-24 | Story | Context + Level-1 DFDs | Nimra | TM §2–3 | Done |
| SCRUM-25 | Story | STRIDE analysis per element | Nimra | TM §4 | Done |
| SCRUM-26 | Task | Attack trees (Command Injection, Buffer Overflow) | Nimra | TM §5 | Done |
| SCRUM-27 | Task | CVSS v3.1 scoring + risk register | Zain | TM §6–7 | Done |

### Epic SCRUM-3 — Secure Implementation
| Key | Type | Summary | Assignee | CWE | Fix PR | Test | Status |
|-----|------|---------|----------|-----|--------|------|--------|
| SCRUM-12 | Story | Fix Buffer Overflow in native helper | Zain | CWE-120 | PR #2 | ASAN + unit | Done |
| SCRUM-14 | Story | Fix IDOR with object-level authorization | Zain | CWE-639 | PR #3 | `test_idor` | Done |
| SCRUM-15 | Story | Fix Command Injection (argv + allow-list) | Zain | CWE-78 | PR #4 | `test_command_injection` | Done |
| SCRUM-16 | Story | Fix CSRF (tokens + SameSite) | Nimra | CWE-352 | PR #5 | `test_csrf` | Done |
| SCRUM-17 | Story | Fix Clickjacking (XFO + CSP) | Nimra | CWE-1021 | PR #6 | `test_clickjacking` | Done |
| SCRUM-11 | Task | Argon2id password hashing | Zain | — | PR #1 | unit | Done |
| SCRUM-18 | Task | Secure session cookie flags | Nimra | — | PR #5 | review | Done |
| SCRUM-19 | Task | Rate limiting + upload size cap | Zain | CWE-307 | PR #4 | review | Done |
| SCRUM-20 | Task | Move secrets to environment | Zain | — | PR #1 | repo scan | Done |
| SCRUM-21 | Task | Upload allow-list + secure_filename | Zain | — | PR #3 | review | Done |
| SCRUM-23 | Task | Confirm ORM parameterization (anti-SQLi) | Nimra | CWE-89 | PR #1 | review | Done |

### Epic SCRUM-4 — CI/CD
| Key | Type | Summary | Assignee | Ref | Status |
|-----|------|---------|----------|-----|--------|
| SCRUM-22 | Story | GitHub Actions: build→test→SAST→DAST, fail-on-critical | Zain | §6.6 | Done |
| SCRUM-28 | Task | Bandit gate on `app/` | Zain | — | Done |
| SCRUM-29 | Task | Semgrep OWASP Top-10 + SARIF upload | Zain | — | Done |
| SCRUM-30 | Task | CodeQL (python + cpp) | Zain | — | Done |
| SCRUM-31 | Task | OWASP ZAP baseline DAST | Nimra | — | Done |

### Epic SCRUM-5 — Docs & Demo
| Key | Type | Summary | Assignee | Ref | Status |
|-----|------|---------|----------|-----|--------|
| SCRUM-32 | Story | Final IEEE report | Both | §5 | In Progress |
| SCRUM-33 | Task | SECURITY_IMPLEMENTATION + TEST_REPORT | Zain | §5 | Done |
| SCRUM-34 | Task | Demo video (6–10 min) script + record | Both | §5 | To Do |
| SCRUM-35 | Task | Repo hygiene (README, SECURITY.md, CONTRIBUTING) | Nimra | §6.1 | Done |

---

## Board snapshot at submission
| To Do | In Progress | Done |
|-------|-------------|------|
| SCRUM-34 (demo video) | SCRUM-32 (final report) | 30+ issues |

> 📷 Attach `evidence/jira-board.png` (board screenshot) and
> `evidence/jira-backlog.png` for the submission.
