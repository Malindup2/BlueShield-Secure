// V9 — Rate limiting (OWASP A07:2021, CWE-307)
//
// Two IP-based limiters built on express-rate-limit:
//   globalLimiter — a broad ceiling on every request, to blunt scraping/DoS.
//   authLimiter   — a tight limit on the credential/OTP endpoints, to stop
//                   online brute force and credential stuffing.
//
// Limits come from the environment so they can be tuned per deployment without
// a code change; the defaults below apply when the vars are unset.
//
// Both are skipped under `NODE_ENV=test` so the unit/integration suites can hit
// /api/auth/* repeatedly — unless RATE_LIMIT_IN_TESTS=1, which the V9 security
// test sets so it can prove the limiter fires.

const rateLimit = require('express-rate-limit');

const num = (value, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

// Evaluated per request, so a test can toggle RATE_LIMIT_IN_TESTS at runtime.
const skipInTests = () =>
  process.env.NODE_ENV === 'test' && process.env.RATE_LIMIT_IN_TESTS !== '1';

const globalLimiter = rateLimit({
  windowMs: num(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000), // 15 min
  limit: num(process.env.RATE_LIMIT_GLOBAL_MAX, 100),
  standardHeaders: 'draft-7', // RateLimit-* headers
  legacyHeaders: false,
  skip: skipInTests,
  message: { message: 'Too many requests, please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: num(process.env.RATE_LIMIT_AUTH_WINDOW_MS, 15 * 60 * 1000), // 15 min
  limit: num(process.env.RATE_LIMIT_AUTH_MAX, 5),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skip: skipInTests,
  // Generic wording — never reveal whether the account exists (avoids V14).
  message: { message: 'Too many attempts, please try again later.' },
});

module.exports = { globalLimiter, authLimiter };
