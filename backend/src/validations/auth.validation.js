// V6 — Type and format checks for the authentication endpoints.
// Every value that reaches a Mongoose filter must be a plain string, so an
// object ({"$ne": null}) or array (implicit $in) can never become part of a query.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_RE = /^\d{6}$/;
const RESET_TOKEN_RE = /^[a-fA-F0-9]{20,128}$/;

const isString = (v) => typeof v === "string";

const checkEmail = (errors, email) => {
  if (!isString(email) || email.length > 254 || !EMAIL_RE.test(email)) errors.push("email must be a valid email address");
};

const checkNewPassword = (errors, password) => {
  if (!isString(password) || password.length < 8 || password.length > 128) errors.push("password must be a string of 8-128 characters");
};

// V1 — registration accepts only these fields. Anything else, including
// role, isVerified or isActive, is rejected rather than ignored, so an
// attempt to set one is visible in the logs instead of failing silently.
const REGISTER_FIELDS = ["name", "email", "password", "phone"];

exports.register = (req) => {
  const errors = [];
  const body = req.body || {};

  const unexpected = Object.keys(body).filter((k) => !REGISTER_FIELDS.includes(k));
  if (unexpected.length) {
    errors.push(`unexpected field(s): ${unexpected.join(", ")}`);
  }

  if (!isString(body.name) || !body.name.trim() || body.name.length > 100) errors.push("name must be a string of 1-100 characters");
  checkEmail(errors, body.email);
  checkNewPassword(errors, body.password);
  if (body.phone != null && (!isString(body.phone) || body.phone.length > 20)) errors.push("phone must be a string of at most 20 characters");

  return { error: errors.length ? errors : null };
};

// V1 — an administrator may grant only a role from the known set, and the
// target must be a valid ObjectId.
const ROLES = ["FISHERMAN", "OFFICER", "HAZARD_ADMIN", "ILLEGAL_ADMIN", "SYSTEM_ADMIN"];
const OBJECT_ID_RE = /^[a-fA-F0-9]{24}$/;

exports.updateUserRole = (req) => {
  const errors = [];
  const body = req.body || {};

  if (!OBJECT_ID_RE.test(req.params.id || "")) errors.push("invalid user id");
  if (!isString(body.role) || !ROLES.includes(body.role)) {
    errors.push(`role must be one of: ${ROLES.join(", ")}`);
  }

  const unexpected = Object.keys(body).filter((k) => k !== "role");
  if (unexpected.length) errors.push(`unexpected field(s): ${unexpected.join(", ")}`);

  return { error: errors.length ? errors : null };
};

exports.login = (req) => {
  const errors = [];
  const body = req.body || {};

  checkEmail(errors, body.email);
  // Only type/length here: the password policy is not revealed at sign-in.
  if (!isString(body.password) || !body.password || body.password.length > 128) errors.push("password is required");

  return { error: errors.length ? errors : null };
};

exports.verifyOtp = (req) => {
  const errors = [];
  const body = req.body || {};

  checkEmail(errors, body.email);
  if (!isString(body.otp) || !OTP_RE.test(body.otp)) errors.push("otp must be a 6-digit code");

  return { error: errors.length ? errors : null };
};

exports.emailOnly = (req) => {
  const errors = [];
  checkEmail(errors, (req.body || {}).email);
  return { error: errors.length ? errors : null };
};

exports.resetPassword = (req) => {
  const errors = [];

  if (!RESET_TOKEN_RE.test(req.params.token || "")) errors.push("Invalid or expired token");
  checkNewPassword(errors, (req.body || {}).password);

  return { error: errors.length ? errors : null };
};
