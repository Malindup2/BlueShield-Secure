// V14 - security event logging.
//
// Authentication failures previously left no trace,These events are written to the
// server log only; nothing here is ever returned to a client.

const redactEmail = (email) => {
  if (typeof email !== 'string' || !email.includes('@')) return '<invalid>';
  const [local, domain] = email.split('@');
  const head = local.slice(0, 2);
  return `${head}${'*'.repeat(Math.max(local.length - 2, 1))}@${domain}`;
};

const clientIp = (req) =>
  (req && (req.ip || (req.socket && req.socket.remoteAddress))) || 'unknown';

const event = (name, req, detail = {}) => {
  const parts = Object.entries(detail)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');
  return `[Security] ${name} ip=${clientIp(req)}${parts ? ` ${parts}` : ''}`;
};

exports.loginFailed = (req, email, reason) =>
  console.warn(event('login.failed', req, { email: redactEmail(email), reason }));

exports.loginSucceeded = (req, email) =>
  console.info(event('login.success', req, { email: redactEmail(email) }));

exports.passwordResetRequested = (req, email, accountExists) =>
  console.info(
    event('password_reset.requested', req, {
      email: redactEmail(email),
      // Recorded server-side only; the HTTP response is identical either way.
      exists: accountExists,
    })
  );

exports.registrationBlocked = (req, email, reason) =>
  console.warn(event('registration.blocked', req, { email: redactEmail(email), reason }));

exports.otpFailed = (req, email, attempts) =>
  console.warn(event('otp.failed', req, { email: redactEmail(email), attempts }));

exports.serverError = (req, error) =>
  console.error(
    event('server.error', req, { path: req && req.originalUrl }),
    error && error.stack ? error.stack : error
  );

exports.redactEmail = redactEmail;
