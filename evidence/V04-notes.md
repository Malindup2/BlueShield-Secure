# V04 — IDOR and mass assignment on report update

## Classification

- OWASP: A01:2021 — Broken Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- Severity: High
- Endpoint: PATCH /api/reports/:reportId
- Branch: security/v04-report-update-authz
- Starting commit: a862beb

## Root cause

The report update controller accepted a user-controlled report ID and passed
the complete request body directly to `Report.findByIdAndUpdate()`.

The controller did not confirm that the authenticated user owned the report.
It also did not use an explicit field allow-list.

## Security impact

A fisherman could update another fisherman's report by obtaining its report ID.
The attacker could also overwrite protected properties such as `reportedBy`,
`isAnonymous`, and `status`.

This could change evidence, remove reporter anonymity, transfer ownership, and
manipulate the report-review workflow.

## Before remediation

### Test: Fisherman A updates Fisherman B's report

- Method: PATCH
- Endpoint: /api/reports/6ab8ba9e6ba69ddff18e579f
- Caller role: FISHERMAN
- Caller: Fisherman A
- Original report owner: Fisherman B
- Expected secure result: 403 Forbidden
- Actual vulnerable result: 200 OK
- IDOR confirmed: Yes
- Mass assignment confirmed: Yes
- Changed fields:
  - title
  - description
  - severity
  - status
  - reportedBy
  - isAnonymous
- Evidence: V04-before-idor-mass-assignment.png

## Required remediation

- Fetch the report before updating it.
- Exclude soft-deleted reports.
- Verify ownership for FISHERMAN callers.
- Return 403 when a fisherman attempts to update another user's report.
- Apply role-specific field allow-lists.
- Never pass the complete request body directly to Mongoose.
- Never allow `reportedBy` or `isAnonymous` to be rewritten.

## Field policy

### Report owner

Permitted fields:

- title
- description
- severity

### OFFICER and SYSTEM_ADMIN

Permitted fields:

- status

### Protected fields

- reportedBy
- isAnonymous
- reportType
- location
- vessel
- attachments
- isDeleted
- deletedBy
- deletedAt
- _id
- createdAt
- updatedAt

## After remediation

### Unauthenticated update

- Expected: 401
- Actual: 401 Unauthorized
- Report unchanged: Yes

### Fisherman A updates Fisherman B's report

- Expected: 403
- Actual: 403 Forbidden,You are not authorized to update this report
- Report unchanged: Yes

### Owner updates permitted fields

- Expected: 200
- Actual: 200 OK
- Updated fields:
  - title
  - description
  - severity
- Protected fields unchanged: Yes

### Owner attempts mass assignment

- Expected: 400
- Actual: 400 Bad Request,
- reportedBy unchanged: Yes
- isAnonymous unchanged: Yes
- status unchanged: Yes
- reportType unchanged: Yes
- isDeleted unchanged: Yes

### Officer updates report status

- Expected: 200
- Actual: 200, OK
- Updated field: status
- Report content unchanged: Yes

## Acceptance criteria

- [x] Unauthenticated caller receives 401
- [x] Non-owner fisherman receives 403
- [x] Non-owner request does not change the report
- [x] Owner can update title, description, and severity
- [x] Owner cannot update status
- [x] reportedBy cannot be changed
- [x] isAnonymous cannot be changed
- [x] deletion metadata cannot be changed
- [x] Officer can update status
- [x] Soft-deleted report returns 404
- [x] V04 security regression tests pass
- [x] Existing report integration tests pass
- [x] Complete security regression suite passes
- [x] reportType cannot be changed through the report update endpoint
- [x] location cannot be changed through the report update endpoint
- [x] vessel cannot be changed through the report update endpoint
- [x] attachments cannot be changed through the report update endpoint