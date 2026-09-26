# BlueShield — Security Remediation

**SE4030 – Secure Software Development · Group Assignment**
Sri Lanka Institute of Information Technology

This repository contains the security assessment and remediation of the **BlueShield** maritime hazard and illegal-fishing reporting platform. Its commit history documents the identification and fixing of each vulnerability individually.

| | |
|---|---|
| **Original project** | https://github.com/Malindup2/BlueShield |
| **Baseline commit** | `5aee302` (11 April 2026) |
| **Baseline tag** | `v0-vulnerable` |
| **Final tag** | `v1-remediated` *(applied when remediation completes)* |

> The original project was developed by members of this group. It is not a deliberately vulnerable training application, and no fixed version of it is publicly available.

---

## Team

| Name | Index No. | Findings owned | Primary files |
|---|---|---|---|
| Thilakumara M.P. | IT23391390 | V1, V7, V13, V14 · **OAuth / OIDC implementation** | `controllers/authController.js`, `models/PendingUser.js`, `utils/generateToken.js`, `controllers/oauthController.js`, `routes/oauthRoutes.js`, `context/AuthContext.jsx`, `services/api.js` |
| Dabarera W.A.S | IT23175648 | V6, V9, V12, V17 | `app.js`, `server.js`, `middlewares/sanitize.js`, `validations/auth.validation.js` |
| Dias K.S.S. | IT23168404 | V3, V4, V5, V11 | `controllers/reportController.js`, `routes/reportRoutes.js`, `models/Report.js`, `utils/reportSerializer.js`, `controllers/hazardController.js`, `controllers/illegalCaseController.js` |
| J.D. Minuli Pabasara | IT23156388 | V2, V8, V10, V15, V16 | `middlewares/authMiddleware.js`, `routes/vesselRoutes.js`, `controllers/vesselController.js`, `package.json` |


### Shared files — coordinate before editing

| File | Editors | Resolution |
|---|---|---|
| `models/User.js` | Minuli (V10), Dabarera (V9), Thilakumara (OAuth) | All fields agreed in a single foundation commit before branching |
| `controllers/authController.js` | Thilakumara, Minuli (V8) | Minuli's two-line change merges first |
| `routes/authRoutes.js` | Dabarera (V9), Thilakumara (V1) | Dabarera's rate limiters merge first |
| `src/app.js` | Dabarera, Thilakumara (3 mount lines) | Dabarera restructures first; mounts added afterwards in one commit |

---

## Getting started

```bash
git clone https://github.com/Malindup2/BlueShield-Secure.git
cd BlueShield-Secure
git checkout security/remediation
```

**Set your own git identity before committing.** Individual contribution is assessed from the commit history — commits authored under another identity will not count toward your contribution.

```bash
git config user.name "Your Name"
git config user.email "your-github-email"
```

### Install

```bash
cd backend  && npm install
cd frontend && npm install
```

Copy `backend/.env.example` to `backend/.env` and fill in your own values. **Never commit a real `.env`.**

---

## Branches and tags

| Ref | Purpose |
|---|---|
| `main` | Untouched baseline import |
| **`v0-vulnerable`** | **Frozen vulnerable state — check this out to reproduce any exploit** |
| `security/remediation` | Integration branch; all fixes merge here |
| `security/vNN-<slug>` | One branch per vulnerability |
| `feat/oauth-google-oidc` | OAuth / OpenID Connect feature |

### Reproducing a vulnerability

`security/remediation` becomes progressively more secure as fixes land, so exploits stop working there. `v0-vulnerable` never changes:

```bash
git checkout v0-vulnerable          # exploit works here — capture "before"
git checkout security/remediation   # fixed — capture "after"
```

---

## Workflow

```bash
git checkout -b security/v03-report-delete-authz security/remediation
# implement the fix
git commit                      # use the template below
git push -u origin security/v03-report-delete-authz
# open a pull request into security/remediation
```

### Commit message template — required for every fix

The assignment brief makes a detailed commit history a condition of a valid submission. Every fix commit must use this format:

```
fix(V03): enforce SYSTEM_ADMIN authorization on report deletion

Vulnerability : Broken Access Control (OWASP A01:2021, CWE-862)
Location      : backend/src/routes/reportRoutes.js:35
Impact        : Any authenticated FISHERMAN could delete any report,
                destroying evidence of illegal fishing activity.
Root cause    : authorize() middleware omitted from the DELETE route.
Fix           : Added authorize("SYSTEM_ADMIN") and converted the
                operation to a soft delete.
Verified      : FISHERMAN token now receives 403; ZAP re-scan clear.
```

---

## Findings register

17 vulnerabilities identified across 8 OWASP Top 10 (2021) categories.

| ID | Vulnerability | OWASP | CWE | Severity | Owner | Status |
|---|---|---|---|---|---|---|
| V1 | Privilege escalation via role mass assignment | A01 | 269/915 | Critical | Thilakumara | ☐ |
| V2 | Unauthenticated vessel API endpoints | A01 | 306 | Critical | Pabasara | ☐ |
| V3 | Missing authorization on report deletion | A01 | 862 | Critical | Dias | ☐ |
| V4 | IDOR and mass assignment on report update | A01 | 639/915 | High | Dias | ☐ |
| V5 | Anonymous reporter de-anonymisation | A01/A02 | 359 | High | Dias | ☐ |
| V6 | NoSQL injection in authentication flows | A03 | 943 | High | Dabarera | ☐ |
| V7 | Predictable OTP generation | A02 | 338/330 | High | Thilakumara | ☐ |
| V8 | OTP disclosed in HTTP response | A04 | 200 | High | Pabasara | ☐ |
| V9 | Missing rate limiting and account lockout | A07 | 307 | High | Dabarera | ☐ |
| V10 | Sensitive fields exposed via `/api/auth/me` | A02 | 200 | High | Pabasara | ☐ |
| V11 | Secrets committed to git history | A05 | 540 | Medium | Dias | ☐ |
| V12 | Security misconfiguration | A05 | 693/16 | Medium | Dabarera | ☐ |
| V13 | Insecure JWT storage and lifecycle | A02/A07 | 522/613 | Medium | Thilakumara | ☐ |
| V14 | User enumeration and verbose error leakage | A01/A09 | 204/209 | Medium | Thilakumara | ☐ |
| V15 | Weak administrator-role validation | A01 | 697 | Medium | Pabasara | ☐ |
| V16 | Vulnerable third-party dependencies | A06 | 1035 | Medium | Pabasara | ☐ |
| V17 | Insufficient transport security | A02 | 319/311 | Medium | Dabarera | ☐ |

**Documented as accepted residual risk:** DOM XSS sinks · LLM prompt injection · over-broad report read access.

---

## Evidence

Every finding requires a before/after pair, captured in one sitting so the comparison is like-for-like.

```
evidence/
  V01-before.png        V01-after.png
  ZAP-before.html       ZAP-after.html
  depcheck-before.html  depcheck-after.html
```

---

## Security testing tools

OWASP ZAP · OWASP Dependency-Check · npm audit · njsscan / Semgrep · gitleaks · NoSQLMap · Artillery · Postman · Jest

*Only tools actually used are retained in the final report.*
