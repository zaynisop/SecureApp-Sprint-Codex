# GitHub & Jira Setup Guide (Team Codex)

Everything below is ready to run once the GitHub repo exists. Replace
`<OWNER>` with the repo owner's GitHub username.

## 1. Create the repository
- Name: **`SecureApp-Sprint-Codex`**
- Visibility: **Private** (then invite the instructor as a collaborator), or Public.
- Do **not** initialize with a README (we already have one).

## 2. Push the local repository
```bash
cd "D:/LAB MIDS"
git remote add origin https://github.com/<OWNER>/SecureApp-Sprint-Codex.git
git push -u origin main
git push origin develop
# push all fix/* and feature/* branches for their PRs:
git push origin --all
```
On first push, Git Credential Manager opens a browser to sign in (no token to
paste). Alternatively use a fine-scoped Personal Access Token as the password.

## 3. Protect `main` (Settings → Branches → Add rule)
- Branch name pattern: `main`
- ☑ Require a pull request before merging → ☑ Require **1** approval
- ☑ Require status checks to pass before merging →
  select: `build-and-test`, `sast-bandit`, `sast-semgrep`, `codeql`
- ☑ Do not allow bypassing the above settings
- ☑ Disable direct pushes to `main` (enforced by the PR rule)

## 4. Invite the instructor (if private)
Settings → Collaborators → add the instructor's GitHub account (email:
`m.ahmadnawazz@gmail.com` — ask for their GitHub handle).

## 5. Open the Pull Requests (one per fix branch)
For each `fix/*` and `feature/*` branch, open a PR into `main`, fill the PR
template (links the Jira issue + CWE), and have the **other teammate review and
approve** before merging. This satisfies the "≥1 peer review per PR" rule.

Suggested PRs:
| PR | Branch | Author | Reviewer |
|----|--------|--------|----------|
| #1 | feature/app-core | Zain | Nimra |
| #2 | fix/buffer-overflow | Zain | Nimra |
| #3 | fix/idor | Zain | Nimra |
| #4 | fix/command-injection | Zain | Nimra |
| #5 | fix/csrf | Nimra | Zain |
| #6 | fix/clickjacking | Nimra | Zain |
| #7 | feature/ci-cd | Zain | Nimra |
| #8 | docs/reports | Nimra | Zain |

## 6. Enable CodeQL / Security features
Settings → Code security → enable CodeQL (our workflow already uploads SARIF),
Dependabot alerts, and secret scanning.

## 7. Jira board
Options:
- **Jira:** create a Scrum project, import `docs/jira/board_import.csv`
  (System → External System Import → CSV), map columns, and grant the instructor
  view access; or
- **GitHub Projects** (needs instructor approval): create a board, add the issues
  from `docs/jira/board_export.md`.
Export the finished board as PDF/screenshots into `docs/evidence/`.

## 8. MS Teams submission
Upload `docs/FINAL_REPORT.pdf` and the demo video (or a private link) to the
designated MS Teams assignment, and attach the Jira board export.
