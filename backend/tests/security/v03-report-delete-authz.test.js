// V3 — Missing authorization on report deletion
// OWASP A01:2021, CWE-862
//
// Previously, the DELETE route required authentication but did not restrict
// the operation to SYSTEM_ADMIN. Any authenticated user could permanently
// delete a report. The secured route enforces SYSTEM_ADMIN authorization and
// the controller preserves the report through soft deletion.

jest.mock("../../src/models/Report", () => ({
  findOneAndUpdate: jest.fn(),
}));

jest.mock("../../src/models/User");

const jwt = require("jsonwebtoken");
const request = require("supertest");
const app = require("../../src/app");
const Report = require("../../src/models/Report");
const User = require("../../src/models/User");

const REPORT_ID = "507f1f77bcf86cd799439011";
const FISHERMAN_ID = "507f1f77bcf86cd799439012";
const OFFICER_ID = "507f1f77bcf86cd799439013";
const ADMIN_ID = "507f1f77bcf86cd799439014";

const tokenFor = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_SECRET);

const authenticateAs = (user) => {
  User.findById.mockReturnValue({
    select: jest.fn().mockResolvedValue(user),
  });
};

describe("V3 — report deletion authorization", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = "v03-test-secret";
  });

  test("rejects an unauthenticated deletion request with 401", async () => {
    const response = await request(app).delete(
      `/api/reports/${REPORT_ID}`
    );

    expect(response.status).toBe(401);
    expect(Report.findOneAndUpdate).not.toHaveBeenCalled();
  });

  test("rejects a FISHERMAN deletion request with 403", async () => {
    authenticateAs({
      _id: FISHERMAN_ID,
      email: "fisherman@example.test",
      role: "FISHERMAN",
    });

    const response = await request(app)
      .delete(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(FISHERMAN_ID)}`);

    expect(response.status).toBe(403);
    expect(response.body.message).toBe(
      "Forbidden: insufficient role"
    );
    expect(Report.findOneAndUpdate).not.toHaveBeenCalled();
  });

  test("rejects an OFFICER deletion request with 403", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    const response = await request(app)
      .delete(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`);

    expect(response.status).toBe(403);
    expect(response.body.message).toBe(
      "Forbidden: insufficient role"
    );
    expect(Report.findOneAndUpdate).not.toHaveBeenCalled();
  });

  test("allows SYSTEM_ADMIN and performs a soft deletion", async () => {
    authenticateAs({
      _id: ADMIN_ID,
      email: "admin@example.test",
      role: "SYSTEM_ADMIN",
    });

    const deletedAt = new Date("2026-09-27T04:30:00.000Z");

    Report.findOneAndUpdate.mockResolvedValue({
      _id: REPORT_ID,
      isDeleted: true,
      deletedBy: ADMIN_ID,
      deletedAt,
    });

    const logSpy = jest
      .spyOn(console, "info")
      .mockImplementation(() => {});

    const response = await request(app)
      .delete(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(ADMIN_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.message).toBe(
      "Report deleted successfully"
    );
    expect(response.body.report).toMatchObject({
      _id: REPORT_ID,
      isDeleted: true,
      deletedBy: ADMIN_ID,
      deletedAt: deletedAt.toISOString(),
    });

    expect(Report.findOneAndUpdate).toHaveBeenCalledTimes(1);

    const [filter, update, options] =
      Report.findOneAndUpdate.mock.calls[0];

    expect(filter).toEqual({
      _id: REPORT_ID,
      isDeleted: { $ne: true },
    });

    expect(update.$set).toMatchObject({
      isDeleted: true,
      deletedBy: ADMIN_ID,
    });

    expect(update.$set.deletedAt).toBeInstanceOf(Date);

    expect(options).toEqual({
      returnDocument: "after",
      runValidators: true,
    });

    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        `[Security] Report soft-deleted: ${REPORT_ID}`
      )
    );

    logSpy.mockRestore();
  });

  test("returns 404 when the report does not exist or is already deleted", async () => {
    authenticateAs({
      _id: ADMIN_ID,
      email: "admin@example.test",
      role: "SYSTEM_ADMIN",
    });

    Report.findOneAndUpdate.mockResolvedValue(null);

    const response = await request(app)
      .delete(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(ADMIN_ID)}`);

    expect(response.status).toBe(404);
    expect(response.body.message).toBe("Report not found");
  });
});