# Demo Video Script & Storyboard (6–10 minutes)
### SecureShare · Team Codex · CYC386

Record a screen capture with narration. Target 7–8 minutes. Both members should
speak (individual contribution is assessed). Capture the referenced screenshots
into `docs/evidence/` as you go.

| # | Time | On screen | Narration (summary) | Speaker |
|---|------|-----------|---------------------|---------|
| 1 | 0:00–0:45 | Title slide + repo | Introduce team, theme (SecureShare), and the 7-day DevSecOps goal: harden to production-grade, CIA-driven. | Zain |
| 2 | 0:45–1:45 | `THREAT_MODEL.md` DFDs + risk register | Walk the context/Level-1 DFD, trust boundaries, top CVSS risks (CmdInj 8.8, BO 7.0). | Nimra |
| 3 | 1:45–2:45 | App running on localhost | Register two users (alice, mallory), upload a file as alice, show share. | Zain |
| 4 | 2:45–3:45 | **IDOR before→after** | Show vulnerable pattern; as mallory hit `/file/1/download` → 403. Run `pytest tests/test_idor.py`. | Zain |
| 5 | 3:45–4:45 | **Command Injection before→after** | Show `vulnerable_demo/01_…`; show secure `export` argv+allow-list; `format=zip; id` → 400; run cmd-injection tests. | Zain |
| 6 | 4:45–5:30 | **Buffer Overflow** | Show `thumbgen_vuln.c` vs `_secure.c`; play CI ASAN log: overflow before, clean after. | Nimra |
| 7 | 5:30–6:15 | **CSRF + Clickjacking** | Open `03_csrf_attack.html` → 400 "CSRF token missing"; open `04_clickjacking_frame.html` → blank frame + console refusal. | Nimra |
| 8 | 6:15–7:15 | GitHub Actions run | Show pipeline: build→test→Bandit→Semgrep→CodeQL→ZAP; show a failing run (vuln reintroduced) vs green run → fail-on-critical. | Zain |
| 9 | 7:15–8:00 | Jira board + wrap-up | Show board (Epics→Stories→Tasks, traceability), residual-risk statement, lessons learned. | Nimra |

**Checklist before recording**
- [ ] `python run.py` works; two users seeded.
- [ ] `pytest tests -q` shows 14 passed on camera.
- [ ] CI run is green (and have a screenshot of a failing/fail-on-critical run).
- [ ] Jira board visible with Done/In Progress/To Do.
- [ ] Mention ethics: all demos on our own `127.0.0.1`.
