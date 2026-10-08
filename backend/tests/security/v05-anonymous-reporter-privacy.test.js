// V5 — Anonymous reporter de-anonymisation
// OWASP A01/A02:2021, CWE-359
//
// Reports marked as anonymous previously exposed `reportedBy` through
// report, illegal-case, and hazard response paths. The secured response
// serializer removes that field for every role except SYSTEM_ADMIN and
// logs each authorized administrator reveal.

jest.mock("../../src/models/Report", () => ({
  findOne: jest.fn(),
  find: jest.fn(),
  countDocuments: jest.fn(),
}));

jest.mock("../../src/models/User");

jest.mock("../../src/services/illegalCaseService", () => ({
  getPendingReports: jest.fn(),
  markAsReviewed: jest.fn(),
  listCases: jest.fn(),
  getCaseById: jest.fn(),
}));

jest.mock("../../src/services/hazardService", () => ({
  listReviewReports: jest.fn(),
  getReviewReportById: jest.fn(),
  updateReviewReportStatus: jest.fn(),
  list: jest.fn(),
  getById: jest.fn(),
  getDashboardSummary: jest.fn(),
}));

const jwt = require("jsonwebtoken");
const request = require("supertest");

const app = require("../../src/app");
const Report = require("../../src/models/Report");
const User = require("../../src/models/User");
const illegalCaseService = require("../../src/services/illegalCaseService");
const hazardService = require("../../src/services/hazardService");

const {
  serializeReport,
} = require("../../src/utils/reportSerializer");

const REPORT_ID = "507f1f77bcf86cd799439011";
const PUBLIC_REPORT_ID = "507f1f77bcf86cd799439012";
const CASE_ID = "507f1f77bcf86cd799439013";
const HAZARD_ID = "507f1f77bcf86cd799439014";

const FISHERMAN_ID = "507f1f77bcf86cd799439021";
const OFFICER_ID = "507f1f77bcf86cd799439022";
const ILLEGAL_ADMIN_ID = "507f1f77bcf86cd799439023";
const HAZARD_ADMIN_ID = "507f1f77bcf86cd799439024";
const SYSTEM_ADMIN_ID = "507f1f77bcf86cd799439025";

const REPORTER_EMAIL = "reporter@example.test";

const tokenFor = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_SECRET);

const authenticateAs = (user) => {
  User.findById.mockReturnValue({
    select: jest.fn().mockResolvedValue(user),
  });
};

const createAnonymousReport = (overrides = {}) => ({
  _id: REPORT_ID,
  title: "Anonymous V05 report",
  description: "Anonymous reporter privacy test",
  reportType: "ILLEGAL_FISHING",
  severity: "HIGH",
  status: "PENDING",
  isAnonymous: true,
  isDeleted: false,
  reportedBy: {
    _id: FISHERMAN_ID,
    name: "Anonymous Reporter",
    email: REPORTER_EMAIL,
  },
  attachments: [],
  location: {
    type: "Point",
    coordinates: [79.8612, 6.9271],
  },
  ...overrides,
});

const createPublicReport = (overrides = {}) => ({
  ...createAnonymousReport({
    _id: PUBLIC_REPORT_ID,
    title: "Public V05 report",
    isAnonymous: false,
  }),
  ...overrides,
});

const mockFindOneWithPopulate = (report) => {
  const query = {
    populate: jest.fn().mockResolvedValue(report),
  };

  Report.findOne.mockReturnValue(query);

  return query;
};

const mockReportListQuery = (reports) => {
  const query = {
    populate: jest.fn(),
    limit: jest.fn(),
    skip: jest.fn(),
    sort: jest.fn(),
  };

  query.populate.mockReturnValue(query);
  query.limit.mockReturnValue(query);
  query.skip.mockReturnValue(query);
  query.sort.mockResolvedValue(reports);

  Report.find.mockReturnValue(query);
  Report.countDocuments.mockResolvedValue(reports.length);

  return query;
};

describe("V5 — anonymous reporter privacy", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = "v05-test-secret";
  });

  test("rejects an unauthenticated report request with 401", async () => {
    const response = await request(app).get(
      `/api/reports/${REPORT_ID}`
    );

    expect(response.status).toBe(401);
    expect(Report.findOne).not.toHaveBeenCalled();
  });

  test("hides reportedBy when an OFFICER reads an anonymous report", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    mockFindOneWithPopulate(createAnonymousReport());

    const response = await request(app)
      .get(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.isAnonymous).toBe(true);
    expect(response.body).not.toHaveProperty("reportedBy");
  });

  test("hides reportedBy when a FISHERMAN reads an anonymous report", async () => {
    authenticateAs({
      _id: FISHERMAN_ID,
      email: REPORTER_EMAIL,
      role: "FISHERMAN",
    });

    mockFindOneWithPopulate(createAnonymousReport());

    const response = await request(app)
      .get(`/api/reports/${REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(FISHERMAN_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.isAnonymous).toBe(true);
    expect(response.body).not.toHaveProperty("reportedBy");
  });

  test("retains reportedBy for a non-anonymous report", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    mockFindOneWithPopulate(createPublicReport());

    const response = await request(app)
      .get(`/api/reports/${PUBLIC_REPORT_ID}`)
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.isAnonymous).toBe(false);
    expect(response.body.reportedBy).toMatchObject({
      _id: FISHERMAN_ID,
      email: REPORTER_EMAIL,
    });
  });

  test("allows SYSTEM_ADMIN to reveal the reporter and logs the access without reporter PII", async () => {
    authenticateAs({
      _id: SYSTEM_ADMIN_ID,
      email: "admin@example.test",
      role: "SYSTEM_ADMIN",
    });

    mockFindOneWithPopulate(createAnonymousReport());

    // Temporarily capture console.info calls made by the serializer.
    // mockImplementation prevents the test log from cluttering the terminal.
    const logSpy = jest
      .spyOn(console, "info")
      .mockImplementation(() => {});

    try {
      const response = await request(app)
        .get(`/api/reports/${REPORT_ID}`)
        .set(
          "Authorization",
          `Bearer ${tokenFor(SYSTEM_ADMIN_ID)}`
        );

      expect(response.status).toBe(200);
      expect(response.body.isAnonymous).toBe(true);

      expect(response.body.reportedBy).toMatchObject({
        _id: FISHERMAN_ID,
        email: REPORTER_EMAIL,
      });

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "anonymous_reporter.revealed"
        )
      );

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(`actorId=${SYSTEM_ADMIN_ID}`)
      );

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining(`reportId=${REPORT_ID}`)
      );

      const completeLogOutput = logSpy.mock.calls
        .flat()
        .join(" ");

      expect(completeLogOutput).not.toContain(REPORTER_EMAIL);
      expect(completeLogOutput).not.toContain(
        "Anonymous Reporter"
      );
      expect(completeLogOutput).not.toContain("Bearer ");
    } finally {
      // Always restore console.info, even if an expectation fails.
      logSpy.mockRestore();
    }
  });

  test("sanitizes anonymous reports in the general report list", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    mockReportListQuery([
      createAnonymousReport(),
      createPublicReport(),
    ]);

    const response = await request(app)
      .get("/api/reports")
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.reports).toHaveLength(2);

    const anonymousReport = response.body.reports.find(
      (report) => report._id === REPORT_ID
    );

    const publicReport = response.body.reports.find(
      (report) => report._id === PUBLIC_REPORT_ID
    );

    expect(anonymousReport.isAnonymous).toBe(true);
    expect(anonymousReport).not.toHaveProperty("reportedBy");

    expect(publicReport.isAnonymous).toBe(false);
    expect(publicReport).toHaveProperty("reportedBy");
  });

  test("sanitizes anonymous reports in the reporter's own list", async () => {
    authenticateAs({
      _id: FISHERMAN_ID,
      email: REPORTER_EMAIL,
      role: "FISHERMAN",
    });

    mockReportListQuery([createAnonymousReport()]);

    const response = await request(app)
      .get("/api/reports/my")
      .set("Authorization", `Bearer ${tokenFor(FISHERMAN_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.reports).toHaveLength(1);
    expect(response.body.reports[0].isAnonymous).toBe(true);
    expect(response.body.reports[0]).not.toHaveProperty(
      "reportedBy"
    );
  });

  test("hides reportedBy from ILLEGAL_ADMIN pending-report responses", async () => {
    authenticateAs({
      _id: ILLEGAL_ADMIN_ID,
      email: "illegal-admin@example.test",
      role: "ILLEGAL_ADMIN",
    });

    illegalCaseService.getPendingReports.mockResolvedValue([
      {
        ...createAnonymousReport(),
        illegalCase: null,
      },
    ]);

    const response = await request(app)
      .get("/api/illegal-cases/reports/pending")
      .set(
        "Authorization",
        `Bearer ${tokenFor(ILLEGAL_ADMIN_ID)}`
      );

    expect(response.status).toBe(200);
    expect(response.body).toHaveLength(1);
    expect(response.body[0].isAnonymous).toBe(true);
    expect(response.body[0]).not.toHaveProperty("reportedBy");
  });


test("hides reportedBy from an ILLEGAL_ADMIN mark-reviewed response", async () => {
  authenticateAs({
    _id: ILLEGAL_ADMIN_ID,
    email: "illegal-admin@example.test",
    role: "ILLEGAL_ADMIN",
  });

  illegalCaseService.markAsReviewed.mockResolvedValue({
    report: createAnonymousReport({
      status: "REJECTED",
    }),
    illegalCase: {
      _id: CASE_ID,
      baseReport: REPORT_ID,
      isReviewed: true,
    },
  });

  const response = await request(app)
    .patch(
      `/api/illegal-cases/reports/${REPORT_ID}/mark-reviewed`
    )
    .set(
      "Authorization",
      `Bearer ${tokenFor(ILLEGAL_ADMIN_ID)}`
    );

  expect(response.status).toBe(200);

  expect(response.body.report.isAnonymous).toBe(true);
  expect(response.body.report.status).toBe("REJECTED");
  expect(response.body.report).not.toHaveProperty(
    "reportedBy"
  );

  expect(response.body.illegalCase).toMatchObject({
    _id: CASE_ID,
    isReviewed: true,
  });
});  

  test("hides baseReport.reportedBy from OFFICER illegal-case responses", async () => {
    authenticateAs({
      _id: OFFICER_ID,
      email: "officer@example.test",
      role: "OFFICER",
    });

    illegalCaseService.listCases.mockResolvedValue({
      page: 1,
      limit: 10,
      total: 1,
      items: [
        {
          _id: CASE_ID,
          status: "OPEN",
          baseReport: createAnonymousReport(),
        },
      ],
    });

    const response = await request(app)
      .get("/api/illegal-cases")
      .set("Authorization", `Bearer ${tokenFor(OFFICER_ID)}`);

    expect(response.status).toBe(200);
    expect(response.body.items).toHaveLength(1);
    expect(response.body.items[0].baseReport.isAnonymous).toBe(
      true
    );
    expect(
      response.body.items[0].baseReport
    ).not.toHaveProperty("reportedBy");
  });

  test("hides reportedBy from HAZARD_ADMIN review-report responses", async () => {
    authenticateAs({
      _id: HAZARD_ADMIN_ID,
      email: "hazard-admin@example.test",
      role: "HAZARD_ADMIN",
    });

    hazardService.listReviewReports.mockResolvedValue({
      page: 1,
      limit: 10,
      total: 1,
      items: [
        createAnonymousReport({
          reportType: "HAZARD",
        }),
      ],
    });

    const response = await request(app)
      .get("/api/hazards/review-reports")
      .set(
        "Authorization",
        `Bearer ${tokenFor(HAZARD_ADMIN_ID)}`
      );

    expect(response.status).toBe(200);
    expect(response.body.items).toHaveLength(1);
    expect(response.body.items[0].isAnonymous).toBe(true);
    expect(response.body.items[0]).not.toHaveProperty(
      "reportedBy"
    );
  });

  test("hides baseReport.reportedBy from HAZARD_ADMIN hazard responses", async () => {
    authenticateAs({
      _id: HAZARD_ADMIN_ID,
      email: "hazard-admin@example.test",
      role: "HAZARD_ADMIN",
    });

    hazardService.list.mockResolvedValue({
      page: 1,
      limit: 10,
      total: 1,
      items: [
        {
          _id: HAZARD_ID,
          caseId: "HZ001",
          handlingStatus: "OPEN",
          baseReport: createAnonymousReport({
            reportType: "HAZARD",
          }),
        },
      ],
    });

    const response = await request(app)
      .get("/api/hazards")
      .set(
        "Authorization",
        `Bearer ${tokenFor(HAZARD_ADMIN_ID)}`
      );

    expect(response.status).toBe(200);
    expect(response.body.items).toHaveLength(1);
    expect(response.body.items[0].baseReport.isAnonymous).toBe(
      true
    );
    expect(
      response.body.items[0].baseReport
    ).not.toHaveProperty("reportedBy");
  });

  test("does not modify the original report while sanitizing it", () => {
    const original = createAnonymousReport();

    const serialized = serializeReport(original, {
      viewer: {
        _id: OFFICER_ID,
        role: "OFFICER",
      },
      req: {
        ip: "127.0.0.1",
      },
    });

    expect(serialized).not.toBe(original);
    expect(serialized).not.toHaveProperty("reportedBy");

    expect(original).toHaveProperty("reportedBy");
    expect(original.reportedBy.email).toBe(REPORTER_EMAIL);
  });
});