// V9 — No rate limiting / account lockout (OWASP A07:2021, CWE-307)
//
// Before the fix, POST /api/auth/login applied no rate limit and no account
// lockout: an attacker could submit unlimited failed password guesses against
// a single account, each answered with a plain 401, enabling offline-speed
// online brute force and credential stuffing.
//
// This regression test drives many consecutive failed logins for one account.
// It expects the application to eventually throttle the attacker with HTTP 429
// (Too Many Requests) once a threshold is crossed. On the vulnerable baseline
// every attempt returns 401, so the "eventually 429" assertion FAILS (red) —
// that red run is the V9 "before" evidence. After the rate-limit / lockout fix
// lands, the threshold response becomes 429 and the test passes (green).
//
// The IP limiter is skipped under NODE_ENV=test by default (so other suites can
// hammer /api/auth/*); enable it here, and pin the threshold, BEFORE app loads.
process.env.RATE_LIMIT_IN_TESTS = '1';
process.env.RATE_LIMIT_AUTH_MAX = '5';

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const request = require('supertest');
const app = require('../../src/app');
const User = require('../../src/models/User');
const { fakeUser, findOneResult } = require('./helpers');

// Number of failed attempts a real attacker would send. A correctly configured
// limiter should cut this off well before it reaches the end.
const ATTEMPTS = 20;
const VICTIM = { email: 'victim@example.com', password: 'wrong-password' };

describe('V9 — rate limiting / account lockout on login', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // The account exists, but every password check fails: this models an
    // attacker guessing passwords against a known account.
    User.findOne.mockImplementation(() =>
      findOneResult(fakeUser({ passwordMatches: false }))
    );
  });

  // Fire ATTEMPTS failed logins in sequence and record every status code.
  const bruteForce = async () => {
    const statuses = [];
    for (let i = 0; i < ATTEMPTS; i++) {
      const res = await request(app).post('/api/auth/login').send(VICTIM);
      statuses.push(res.status);
    }
    return statuses;
  };

  test('repeated failed logins are eventually throttled with 429', async () => {
    const statuses = await bruteForce();

    // Vulnerable baseline: every status is 401 and this expectation fails.
    // Fixed build: at least one attempt is rejected with 429 before the end.
    expect(statuses).toContain(429);
  });

  test('the account is locked out before all attempts are exhausted', async () => {
    const statuses = await bruteForce();
    const firstThrottled = statuses.findIndex((s) => s === 429);

    // A limiter/lockout must trigger strictly before the last attempt, not
    // only on the final request.
    expect(firstThrottled).toBeGreaterThanOrEqual(0);
    expect(firstThrottled).toBeLessThan(ATTEMPTS - 1);
  });
});
