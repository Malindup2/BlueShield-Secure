// V4 — IDOR and mass assignment on report update
// OWASP A01:2021, CWE-639/CWE-915
//
// Previously, an authenticated fisherman could update another user's report,
// and the complete request body was passed directly to Mongoose. The secured
// controller enforces ownership and role-specific field allow-lists.

jest.mock("../../src/models/Report", () => ({
  findOne: jest.fn(),
}));

jest.mock("../../src/models/User");

const jwt = require("jsonwebtoken");
const request = require("supertest");
const app = require("../../src/app");
const Report = require("../../src/models/Report");
const User = require("../../src/models/User");

const REPORT_ID = "507f1f77bcf86cd799439011";
const OWNER_ID = "507f1f77bcf86cd799439012";
const OTHER_FISHERMAN_ID = "507f1f77bcf86cd799439013";
const OFFICER_ID = "507f1f77bcf86cd799439014";
const ADMIN_ID = "507f1f77bcf86cd799439015";

const tokenFor = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_SECRET);

const authenticateAs = (user) => {
  User.findById.mockReturnValue({
    select: jest.fn().mockResolvedValue(user),
  });
};

const createReport = (overrides = {}) => {
  const report = {
    _id: REPORT_ID,
    title: "Original report",
    description: "Original description",
    reportType: "ILLEGAL_FISHING",
    severity: "MEDIUM",
    reportedBy: OWNER_ID,
    status: "PENDING",
    isAnonymous: true,
    isDeleted: false,
    deletedBy: null,
    deletedAt: null,
    attachments: [],
    location: {
      type: "Point",
      coordinates: [79.8612, 6.9271],
    },
    vessel: {
      name: "Original vessel",
      mmsi: "123456789",
    },
    ...overrides,
  };

  report.save = jest.fn().mockImplementation(async () => report);

  return report;
};

describe("V4 — report update authorization", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = "v04-test-secret";
  });

  test("rejects an unauthenticated update request with 401", async () => {
    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .send({ title: "Unauthorized update" });

    expect(response.status).toBe(401);
    expect(Report.findOne).not.toHaveBeenCalled();
  });

  test("rejects Fisherman A updating Fisherman B's report with 403", async () => {
    authenticateAs({
      _id: OTHER_FISHERMAN_ID,
      email: "fisherman-a@example.test",
      role: "FISHERMAN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OTHER_FISHERMAN_ID)}`)
      .send({ title: "Unauthorized update" });

    expect(response.status).toBe(403);
    expect(response.body.message).toBe(
      "You are not authorized to update this report"
    );
    expect(report.title).toBe("Original report");
    expect(report.save).not.toHaveBeenCalled();
  });

  test("allows the owner to update title, description, and severity", async () => {
    authenticateAs({
      _id: OWNER_ID,
      email: "owner@example.test",
      role: "FISHERMAN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OWNER_ID)}`)
      .send({
        title: "Owner updated title",
        description: "Owner updated description",
        severity: "HIGH",
      });

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      title: "Owner updated title",
      description: "Owner updated description",
      severity: "HIGH",
    });
    expect(report.save).toHaveBeenCalledTimes(1);
  });

  test("prevents the owner from changing ownership and anonymity", async () => {
    authenticateAs({
      _id: OWNER_ID,
      email: "owner@example.test",
      role: "FISHERMAN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OWNER_ID)}`)
      .send({
        reportedBy: OTHER_FISHERMAN_ID,
        isAnonymous: false,
      });

    expect(response.status).toBe(400);
    expect(report.reportedBy).toBe(OWNER_ID);
    expect(report.isAnonymous).toBe(true);
    expect(report.save).not.toHaveBeenCalled();
  });

  test("prevents a fisherman from changing status", async () => {
    authenticateAs({
      _id: OWNER_ID,
      email: "owner@example.test",
      role: "FISHERMAN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OWNER_ID)}`)
      .send({ status: "RESOLVED" });

    expect(response.status).toBe(400);
    expect(report.status).toBe("PENDING");
    expect(report.save).not.toHaveBeenCalled();
  });

  test("prevents mass assignment of report workflow and evidence fields", async () => {
    authenticateAs({
      _id: OWNER_ID,
      email: "owner@example.test",
      role: "FISHERMAN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OWNER_ID)}`)
      .send({
        reportType: "HAZARD",
        location: {
          type: "Point",
          coordinates: [80.0, 7.0],
        },
        vessel: {
          name: "Injected vessel",
          mmsi: "999999999",
        },
        attachments: [
          {
            url: "https://attacker.example/evidence.jpg",
            type: "image/jpeg",
          },
        ],
        isDeleted: true,
        deletedBy: OTHER_FISHERMAN_ID,
        deletedAt: "2026-09-27T06:00:00.000Z",
      });

    expect(response.status).toBe(400);
    expect(report.reportType).toBe("ILLEGAL_FISHING");
    expect(report.location.coordinates).toEqual([79.8612, 6.9271]);
    expect(report.vessel.name).toBe("Original vessel");
    expect(report.attachments).toEqual([]);
    expect(report.isDeleted).toBe(false);
    expect(report.deletedBy).toBeNull();
    expect(report.deletedAt).toBeNull();
    expect(report.save).not.toHaveBeenCalled();

  });

  test("allows an officer to update report status", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`)
      .send({ status: "UNDER_REVIEW" });

    expect(response.status).toBe(200);
    expect(response.body.status).toBe("UNDER_REVIEW");
    expect(report.save).toHaveBeenCalledTimes(1);
  });

  test("prevents an officer from modifying report content fields", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`)
      .send({ title: "Officer changed title" });

    expect(response.status).toBe(400);
    expect(report.title).toBe("Original report");
    expect(report.save).not.toHaveBeenCalled();
  });

  test("allows a system administrator to update report status", async () => {
    authenticateAs({
      _id: ADMIN_ID,
      email: "admin@example.test",
      role: "SYSTEM_ADMIN",
    });

    const report = createReport();
    Report.findOne.mockResolvedValue(report);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(ADMIN_ID)}`)
      .send({ status: "VERIFIED" });

    expect(response.status).toBe(200);
    expect(response.body.status).toBe("VERIFIED");
    expect(report.save).toHaveBeenCalledTimes(1);
  });

  test("returns 404 when the report does not exist or is soft-deleted", async () => {
    authenticateAs({
      _id: OWNER_ID,
      email: "owner@example.test",
      role: "FISHERMAN",
    });

    Report.findOne.mockResolvedValue(null);

    const response = await request(app)
      .patch(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OWNER_ID)}`)
      .send({ title: "Missing report" });

    expect(response.status).toBe(404);
    expect(response.body.message).toBe("Report not found");

    expect(Report.findOne).toHaveBeenCalledWith({
        _id: REPORT_ID,
        isDeleted: { $ne: true },
    });
  });
});