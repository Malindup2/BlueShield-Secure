const toPlainObject = (value) => {
  if (!value) return value;

  if (typeof value.toObject === "function") {
    return value.toObject();
  }

  return { ...value };
};

const getClientIp = (req) =>
  req?.ip || req?.socket?.remoteAddress || "unknown";

const logAnonymousReporterReveal = ({ req, viewer, reportId }) => {
  const actorId =
    viewer?._id?.toString?.() ||
    viewer?.id?.toString?.() ||
    "unknown";

  console.info(
    `[Security] anonymous_reporter.revealed ip=${getClientIp(req)} actorId=${actorId} reportId=${reportId}`
  );
};

const serializeReport = (report, { viewer, req } = {}) => {
  const data = toPlainObject(report);

  if (!data || data.isAnonymous !== true) {
    return data;
  }

  if (viewer?.role === "SYSTEM_ADMIN") {
    if (data.reportedBy) {
      logAnonymousReporterReveal({
        req,
        viewer,
        reportId: data._id?.toString?.() || "unknown",
      });
    }

    return data;
  }

  delete data.reportedBy;
  return data;
};

const serializeReports = (reports, context = {}) =>
  reports.map((report) => serializeReport(report, context));

const serializeEmbeddedReport = (
  container,
  fieldName,
  context = {}
) => {
  const data = toPlainObject(container);

  if (data?.[fieldName]) {
    data[fieldName] = serializeReport(data[fieldName], context);
  }

  return data;
};

module.exports = {
  serializeReport,
  serializeReports,
  serializeEmbeddedReport,
};