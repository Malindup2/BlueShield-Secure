# V05 — Anonymous reporter de-anonymisation

## Classification

- OWASP: A01:2021 Broken Access Control / A02:2021 Cryptographic Failures
- CWE: CWE-359 — Exposure of Private Personal Information
- Severity: High

## Starting version

- Branch: `security/v05-anonymous-reporter-privacy`
- Base branch: `security/remediation`
- Starting commit: `8fe79d0`

## Vulnerability

Reports marked with `isAnonymous: true` still exposed `reportedBy`.
Some endpoints populated this field with the reporter's name and email.

## Affected read paths

- `GET /api/reports`
- `GET /api/reports/my`
- `GET /api/reports/:reportId`
- Report creation/update responses
- `GET /api/illegal-cases/reports/pending`
- `GET /api/illegal-cases`
- `GET /api/illegal-cases/:caseId`
- `GET /api/hazards/review-reports`
- `GET /api/hazards/review-reports/:reportId`
- `GET /api/hazards/dashboard-summary`
- `PATCH /api/illegal-cases/reports/:reportId/mark-reviewed`
- Hazard responses containing `baseReport`

## Before remediation

### Officer direct report request

- Endpoint: `GET /api/reports/6ab8e7829056eebde0534d57`
- Role: `OFFICER`
- Result: `200 OK`
- `isAnonymous`: `true`
- `reportedBy`: exposed with identity information
- Evidence: `V05-before-officer-direct-report.png`

### Officer report list

- Endpoint: `GET /api/reports`
- Role: `OFFICER`
- Result: anonymous report included populated `reportedBy`
- Evidence: `V05-before-officer-report-list.png`

## Remediation

A centralized response serializer was added.

For reports where `isAnonymous === true`:

- `reportedBy` is omitted for all roles except `SYSTEM_ADMIN`.
- The underlying database record is not modified.
- Authorized system-administrator reveals create a security audit log.
- The log records the actor ID, report ID, event type, and client IP.
- The log does not contain the reporter's name, email, password, or token.

The serializer was applied to report, illegal-case, and hazard response paths.

## After remediation

### Officer direct access

- Expected: `200`, no `reportedBy`
- Actual: `200`, no `reportedBy`
- Evidence: `V05-after-officer-direct-report-hidden.png`

### Officer list access

- Expected: anonymous reports have no `reportedBy`
- Actual: anonymous reports have no `reportedBy`
- Evidence: `V05-after-officer-list-hidden.png`

### System administrator access

- Expected: `200`, `reportedBy` retained, audit event written
- Actual: `200`, `reportedBy` retained, audit event written
- Evidence:
  - `V05-after-admin-authorized-reveal.png`
  - `V05-after-admin-security-log.png`



## Acceptance criteria

- [x] Anonymous direct report hides `reportedBy` from `FISHERMAN`
- [x] Anonymous direct report hides `reportedBy` from `OFFICER`
- [x] Anonymous direct report hides `reportedBy` from `ILLEGAL_ADMIN`
- [x] Anonymous hazard review hides `reportedBy` from `HAZARD_ADMIN`
- [x] Illegal-case responses hide anonymous `baseReport.reportedBy`
- [x] Hazard responses hide anonymous `baseReport.reportedBy`
- [x] Non-anonymous reports retain normal reporter information
- [x] `SYSTEM_ADMIN` can perform an authorized reveal
- [x] Every authorized reveal produces a security log
- [x] Security logs contain no reporter PII or bearer token
- [x] Automated V05 tests pass
- [x] Existing integration tests pass
- [x] Complete security suite passes
