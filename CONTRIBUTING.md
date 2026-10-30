# Contributing — Team Codex workflow

## Branching strategy
- `main` — **protected**. No direct pushes. Requires a PR + 1 approving review +
  green CI.
- `develop` — optional integration branch.
- `feature/<short-name>` — new functionality.
- `fix/<short-name>` — vulnerability remediation / bug fixes.

## Commit messages
Descriptive, imperative mood, referencing the Jira issue and/or CWE:
```
fix(idor): enforce object-level authz on download  [SCRUM-14, CWE-639]
```
Squash/rebase is allowed; history must stay understandable.

## Pull requests
1. Branch from `main` (or `develop`).
2. Keep changes focused; update tests and docs.
3. Open a PR using the template; link the Jira issue and the PNE/STRIDE item.
4. At least **one teammate reviews and approves** before merge.
5. CI (build, tests, SAST, DAST) must pass. The build fails on high/critical.

## Secure coding checklist (must pass before merge)
- [ ] No user input reaches a shell (`shell=False`, argv arrays, allow-lists).
- [ ] Every sensitive object access has an object-level authorization check.
- [ ] All state-changing routes are POST and carry a CSRF token.
- [ ] No fixed-size memory copy trusts a caller-supplied length.
- [ ] Output is escaped (Jinja autoescape) / CSP in place.
- [ ] Secrets come from the environment, never hardcoded.
- [ ] New endpoints are covered by a test.

## Running locally
```bash
pip install -r requirements.txt
pytest tests -q
bandit -r app -ll
```
