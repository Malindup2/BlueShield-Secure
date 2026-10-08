Finding: V3 — Missing authorization on report deletion
Tester: Dias K.S.S.
Branch: security/v03-report-delete-authz
Pre-fix commit: 50e784bed4120c4841b660a56c32b2613dd435f4
Database: blueshield_dias_security
API: http://localhost:5000

This is the pre-V3-fix integration version, not the original baseline tag.

Expected policy:
Only SYSTEM_ADMIN may delete reports.
Deletion must preserve the record through soft deletion.

Actual before results:

Test 1 — Fisherman unauthorized deletion
Owner             : V03 Fisherman A
Caller            : V03 Fisherman B
Caller role       : FISHERMAN
Report ID         : 6ab895db06b87a8749eab5e6
Request           : DELETE /api/reports/6ab895db06b87a8749eab5e6
Expected policy   : 403 Forbidden; report must remain unchanged
Actual status     : 200 OK
Actual response   : {"message":"Report deleted successfully"}
Database result   : No matching document remained in the reports collection
Security impact   : An authenticated fisherman permanently deleted another
                    user's report.
Evidence          : V03-before-caller-role.png
                    V03-before-fisherman-delete.png
                    V03-before-fisherman-record-removed.png



Test 2 — Officer unauthorized deletion
Owner             : V03 Fisherman A
Caller            : V03 Officer
Caller role       : OFFICER
Report ID         : 6ab89a8206b87a8749eab5f1
Request           : DELETE /api/reports/6ab89a8206b87a8749eab5f1
Expected policy   : 403 Forbidden; report must remain unchanged
Actual status     : 200 OK
Actual response   : {"message":"Report deleted successfully"}
Database result   : No matching document remained in the reports collection
Security impact   : An authenticated officer permanently deleted a report
                    despite the SYSTEM_ADMIN-only deletion policy.
Evidence          : V03-before-officer-role.png
                    V03-before-officer-delete.png
                    V03-before-officer-record-removed.png


Vulnerability reproduced: YES

Root cause:
The DELETE route used protect middleware but did not use
authorize("SYSTEM_ADMIN"). The controller used findByIdAndDelete(), causing
permanent removal instead of preserving the report as evidence.



Actual after results:

Test 1 — Unauthenticated deletion
Expected          : 401; report unchanged
Actual            : 401,Not authorized, no token
Report ID         : 6ab89e5bee28a0148b55d701
Evidence          : V03-after-unauthenticated-401.png

Test 2 — Fisherman deletion
Expected          : 403; report unchanged
Actual            : 403,Forbidden: insufficient role
Report ID         : 6ab89e5bee28a0148b55d701
Evidence          : V03-after-fisherman-403.png
                    V03-after-fisherman-record-unchanged.png

Test 3 — Officer deletion
Expected          : 403; report unchanged
Actual            : 403, insufficient role
Report ID         : 6ab89e5bee28a0148b55d701
Evidence          : V03-after-officer-403.png
                    V03-after-officer-record-unchanged.png

Test 4 — SYSTEM_ADMIN deletion
Expected          : 200; report retained with soft-delete metadata
Actual            : 200 OK,Report deleted successfully
Report ID         : 6ab89e5bee28a0148b55d701
Security log      : Report soft-deleted: 6ab89e5bee28a0148b55d701 by   v03.admin@example.test (SYSTEM_ADMIN)
Evidence          : V03-after-admin-200.png
                    V03-after-admin-soft-delete-record.png
                    V03-after-security-log.png

Acceptance criteria:
[x] Unauthenticated caller receives 401
[x] FISHERMAN receives 403
[x] OFFICER receives 403
[x] SYSTEM_ADMIN receives 200
[x] Administrator-deleted record remains in MongoDB
[x] isDeleted is true
[x] deletedBy identifies the administrator
[x] deletedAt contains the deletion time
[x] Security action is logged
[x] Automated security tests pass


Automated verification:

Test file          : backend/tests/security/v03-report-delete-authz.test.js
Command            : npx jest tests/security/v03-report-delete-authz.test.js --runInBand
Result             : PASS
Test suites        : 1 passed, 1 total
Tests              : 5 passed, 5 total
Verified behavior  : Unauthenticated deletion returns 401
                     FISHERMAN deletion returns 403
                     OFFICER deletion returns 403
                     SYSTEM_ADMIN performs soft deletion
                     Missing/already-deleted report returns 404
Evidence           : V03-after-jest-security-pass.png


Existing report regression test

Test file          : backend/tests/integration/reportRoutes.test.js
Result             : PASS
Evidence           : V03-report-integration.txt
                     V03-after-report-integration-pass.png