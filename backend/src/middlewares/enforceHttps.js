// V17 — Enforce HTTPS (OWASP A02:2021, CWE-319)
//
// Redirects any plaintext HTTP request to the HTTPS equivalent so credentials,
// JWTs, OTPs and reset tokens never travel in cleartext. Works both when the
// app terminates TLS itself (req.secure) and when it sits behind a TLS-
// terminating proxy (X-Forwarded-Proto), which is why `trust proxy` is set in
// app.js.
//
// Enabled in production, or when FORCE_HTTPS=1. Left off in development and
// test so local HTTP and the test client keep working. HSTS itself is emitted
// by helmet (see V12).

module.exports = function enforceHttps(req, res, next) {
  const enabled =
    process.env.FORCE_HTTPS === '1' || process.env.NODE_ENV === 'production';
  if (!enabled) return next();

  const forwardedProto = req.headers['x-forwarded-proto'];
  const isHttps = req.secure || forwardedProto === 'https';
  if (isHttps) return next();

  const host = req.headers.host;
  return res.redirect(301, `https://${host}${req.originalUrl}`);
};
