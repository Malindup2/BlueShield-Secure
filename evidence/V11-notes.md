# V11 — Secrets committed to Git history

## Classification

- OWASP: A05:2021 — Security Misconfiguration
- CWE: CWE-540 — Inclusion of Sensitive Information in Source Code
- Original affected path: `frontend/src/.env`
- Original affected commits: `d5cbcf6` and `7042633`

## Vulnerability

The original repository included an environment file containing credentials in Git history. Publicly committed credentials must be considered compromised because deleting the latest file does not remove historical copies or revoke the credentials.

## Impact

Exposed credentials could allow unauthorized access to the database, authentication tokens, email account, cloud storage, and third-party APIs.

## Root cause

A real environment file was committed before suitable `.gitignore` rules and secret-scanning controls were established.

## History assessment

The current repository was checked using:

```powershell
git log --all --oneline -- ":(glob)**/.env"
git log --all --oneline -- frontend/src/.env
```

Both commands returned no matching commits.

The `v0-vulnerable` tag was inspected by filename and contained only:

```text
backend/.env.example
```

The current remediation repository therefore contains no tracked real `.env` file.

## Remediation

1. Generate replacement credentials.
2. Test the replacement credentials.
3. Revoke the previously exposed credentials.
4. Ensure the affected file is absent from Git history.
5. Provide placeholder-only `.env.example` files.
6. Exclude real environment files through `.gitignore`.
7. Scan complete Git history with Gitleaks CI.

History cleaning does not invalidate credentials that may already have been copied, so rotation and revocation remain required.

## Preventive controls

- Ignore `.env` and `.env.*` files.
- Track only placeholder `.env.example` files.
- Keep backend secrets outside frontend code.
- Store deployment credentials in platform secret storage.
- Run Gitleaks on every push and pull request.
- Scan full history using `fetch-depth: 0`.
- Review staged files before committing.
- Keep credentials out of logs, screenshots, and evidence.

## Verification

Current history checks found no tracked real `.env` file. Gitleaks CI must pass, and provider-side credential rotation and revocation must be confirmed.

## Acceptance criteria

- [x] Current repository searched across all available references
- [x] Current repository contains no tracked real `.env` file
- [x] `frontend/src/.env` is absent from available history
- [x] Real environment files excluded through complete `.gitignore` rules
- [x] Complete placeholder-only environment examples provided
- [x] Gitleaks workflow added
- [ ] Gitleaks GitHub Actions job passes
- [ ] Replacement credentials confirmed working
- [ ] Previously exposed credentials confirmed revoked