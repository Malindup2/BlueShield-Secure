// V9 — Per-account lockout (OWASP A07:2021, CWE-307)
//
// Companion to v09-rate-limit-lockout.test.js. Where that file proves the
// IP-based limiter, this proves the account-level lockout: after MAX_LOGIN_
// ATTEMPTS wrong passwords the account is locked, and even the CORRECT password
// is refused until the lock expires — defeating an attacker who rotates IPs to
// dodge the per-IP limiter. Every failure returns the same 401 message, so a
// locked account is indistinguishable from a wrong password (no V14 leak).
//
// The IP limiter is left disabled here so lockout is tested in isolation.
process.env.RATE_LIMIT_IN_TESTS = '0';
process.env.MAX_LOGIN_ATTEMPTS = '5';

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const request = require('supertest');
const app = require('../../src/app');
const User = require('../../src/models/User');
const generateToken = require('../../src/utils/generateToken');
const { findOneResult } = require('./helpers');

const CORRECT = 'correct-horse';
const VICTIM_EMAIL = 'victim@example.com';

// A single stateful user document shared across findOne calls, so the failure
// counter persists between requests exactly as a real DB row would.
const makeStatefulVictim = () => {
  const doc = {
    _id: 'user-1',
    id: 'user-1',
    name: 'Victim',
    email: VICTIM_EMAIL,
    role: 'FISHERMAN',
    password: CORRECT,
    failedLoginAttempts: 0,
    lockUntil: null,
    matchPassword: jest.fn(function (entered) {
      return Promise.resolve(entered === CORRECT);
    }),
    save: jest.fn().mockResolvedValue(undefined),
  };
  return doc;
};

describe('V9 — per-account lockout on login', () => {
  let victim;

  beforeEach(() => {
    jest.clearAllMocks();
    victim = makeStatefulVictim();
    User.findOne.mockImplementation(() => findOneResult(victim));
    generateToken.mockReturnValue('token-123');
  });

  const login = (password) =>
    request(app).post('/api/auth/login').send({ email: VICTIM_EMAIL, password });

  test('locks the account after 5 wrong passwords and refuses the correct one', async () => {
    for (let i = 0; i < 5; i++) {
      const res = await login('wrong-guess');
      expect(res.status).toBe(401);
    }

    // The lock must now be set in the future.
    expect(victim.lockUntil).toBeInstanceOf(Date);
    expect(victim.lockUntil.getTime()).toBeGreaterThan(Date.now());

    // Correct password is still refused while locked — and with the SAME message.
    const afterLock = await login(CORRECT);
    expect(afterLock.status).toBe(401);
    expect(afterLock.body.message).toBe('Invalid email or password');
    expect(afterLock.body.token).toBeUndefined();
  });

  test('a correct password within the limit resets the failure counter', async () => {
    await login('wrong-guess');
    await login('wrong-guess');
    expect(victim.failedLoginAttempts).toBe(2);

    const ok = await login(CORRECT);
    expect(ok.status).toBe(200);
    expect(ok.body.token).toBeDefined();
    expect(victim.failedLoginAttempts).toBe(0);
    expect(victim.lockUntil).toBeNull();
  });
});
