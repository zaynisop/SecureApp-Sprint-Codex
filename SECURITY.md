# Security Policy

## Scope & ethics
SecureShare is a lab project for CYC386. All vulnerability demonstrations are
restricted to the team's own instance running on `127.0.0.1` (exam Section 9).
Never target third-party or university systems.

## Supported versions
The `main` branch is the supported, hardened version. Code under
`vulnerable_demo/` is intentionally insecure, is **never** deployed, and exists
only for the before/after demonstration.

## Reporting a vulnerability
Open a **private** GitHub Security Advisory, or email the maintainers
(team Codex). Do not open a public issue for an unfixed vulnerability.
Please include reproduction steps and affected endpoints.

## Security controls in place
- **AuthN:** Argon2id password hashing; session cookies `HttpOnly`,
  `SameSite=Lax`, `Secure` (HTTPS); strong session protection.
- **AuthZ:** object-level authorization on every file access (anti-IDOR).
- **CSRF:** Flask-WTF synchronizer tokens on all state-changing requests.
- **Clickjacking:** `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`.
- **Injection:** no shell interpretation of user input (`subprocess` argv +
  allow-list); parameterized ORM queries (anti-SQLi).
- **Memory safety:** native helper built with `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`; validated under AddressSanitizer in CI.
- **Headers:** CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  HSTS, `Permissions-Policy`.
- **Abuse:** per-route rate limiting (brute-force / DoS).
- **Uploads:** extension allow-list, 10 MB cap, server-generated storage names.

## CI/CD security gates
Every push/PR runs Bandit + Semgrep + CodeQL (SAST) and OWASP ZAP (DAST).
The build **fails on high/critical findings** in production code.
