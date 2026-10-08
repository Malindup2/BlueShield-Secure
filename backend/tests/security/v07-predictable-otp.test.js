// V7 — Predictable OTP generation (OWASP A02:2021, CWE-338 / CWE-330)
//
// The verification code was produced by
//   Math.floor(100000 + Math.random() * 900000)
// Math.random() is V8's xorshift128+ generator: non-cryptographic, and its
// internal state can be recovered from a handful of observed outputs. An
// attacker who registers repeatedly can therefore predict the code issued
// to somebody else's registration and complete it for an address they do
// not control.
//
// The code was also persisted in plaintext, so anyone with read access to
// the database — or to a backup, or to a response that over-selects — could
// use it directly. And nothing limited how many guesses a caller could make
// against a six-digit keyspace.

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const crypto = require('crypto');
const request = require('supertest');
const app = require('../../src/app');
const User = require('../../src/models/User');
const PendingUser = require('../../src/models/PendingUser');
const sendEmail = require('../../src/services/emailService');
const generateToken = require('../../src/utils/generateToken');
const { findOneResult } = require('./helpers');

const SHA256_HEX = /^[a-f0-9]{64}$/;
const SIX_DIGITS = /^\d{6}$/;

const registration = {
  name: 'Nimal',
  email: 'nimal@example.com',
  password: 'Password123!',
};

// The code actually emailed to the user, read out of the sendEmail mock.
const emailedCode = () => {
  const call = sendEmail.mock.calls.at(-1);
  if (!call) return null;
  const match = String(call[0].message).match(/\b\d{6}\b/);
  return match ? match[0] : null;
};

const storedOtp = () => {
  const call = PendingUser.create.mock.calls.at(-1);
  return call ? call[0].otp : undefined;
};

// A pending record as the fix should persist it: hashed code, attempt counter.
const pendingRecord = (plaintextOtp, overrides = {}) => ({
  _id: 'p1',
  name: 'Nimal',
  email: 'nimal@example.com',
  password: 'hashed',
  phone: null,
  role: 'FISHERMAN',
  otp: crypto.createHash('sha256').update(plaintextOtp).digest('hex'),
  otpExpire: new Date(Date.now() + 60000),
  attempts: 0,
  save: jest.fn().mockResolvedValue(undefined),
  deleteOne: jest.fn().mockResolvedValue(undefined),
  ...overrides,
});

describe('V7 — predictable and plaintext OTP', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    User.findOne.mockImplementation(() => findOneResult(null));
    User.create.mockImplementation(async (doc) => ({ ...doc, id: 'u1', _id: 'u1' }));
    PendingUser.findOneAndDelete.mockResolvedValue(null);
    PendingUser.create.mockImplementation(async (doc) => ({ ...doc, _id: 'p1' }));
    PendingUser.findByIdAndDelete.mockResolvedValue(null);
    sendEmail.mockResolvedValue(undefined);
    generateToken.mockReturnValue('token-123');
  });

  describe('generation', () => {
    test('uses a cryptographic source, not Math.random', async () => {
      const randomInt = jest.spyOn(crypto, 'randomInt');
      const mathRandom = jest.spyOn(Math, 'random');

      await request(app).post('/api/auth/register').send(registration);

      expect(randomInt).toHaveBeenCalled();
      expect(mathRandom).not.toHaveBeenCalled();

      randomInt.mockRestore();
      mathRandom.mockRestore();
    });

    test('the emailed code is six digits', async () => {
      await request(app).post('/api/auth/register').send(registration);
      expect(emailedCode()).toMatch(SIX_DIGITS);
    });

    test('the stored code is a hash, never the plaintext', async () => {
      await request(app).post('/api/auth/register').send(registration);

      const stored = storedOtp();
      expect(stored).toMatch(SHA256_HEX);
      expect(stored).not.toBe(emailedCode());
    });

    test('the stored hash matches the emailed code', async () => {
      await request(app).post('/api/auth/register').send(registration);

      const expected = crypto.createHash('sha256').update(emailedCode()).digest('hex');
      expect(storedOtp()).toBe(expected);
    });

    test('resend-otp also stores a hash', async () => {
      const record = pendingRecord('111111');
      PendingUser.findOne.mockImplementation(() => findOneResult(record));

      await request(app).post('/api/auth/resend-otp').send({ email: registration.email });

      expect(record.otp).toMatch(SHA256_HEX);
      expect(record.otp).not.toBe(emailedCode());
    });

    test('successive codes differ', async () => {
      const seen = new Set();
      for (let i = 0; i < 20; i += 1) {
        jest.clearAllMocks();
        sendEmail.mockResolvedValue(undefined);
        PendingUser.create.mockImplementation(async (doc) => ({ ...doc, _id: 'p1' }));
        User.findOne.mockImplementation(() => findOneResult(null));
        // eslint-disable-next-line no-await-in-loop
        await request(app).post('/api/auth/register').send(registration);
        seen.add(emailedCode());
      }
      expect(seen.size).toBeGreaterThan(15);
    });
  });

  describe('verification', () => {
    test('the correct code is accepted', async () => {
      PendingUser.findOne.mockImplementation(() => findOneResult(pendingRecord('424242')));

      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: registration.email, otp: '424242' });

      expect(res.status).toBe(200);
      expect(User.create).toHaveBeenCalled();
    });

    test('an incorrect code is rejected', async () => {
      PendingUser.findOne.mockImplementation(() => findOneResult(pendingRecord('424242')));

      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: registration.email, otp: '999999' });

      expect(res.status).toBe(400);
      expect(User.create).not.toHaveBeenCalled();
    });

    test('a failed attempt is counted', async () => {
      const record = pendingRecord('424242');
      PendingUser.findOne.mockImplementation(() => findOneResult(record));

      await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: registration.email, otp: '999999' });

      expect(record.attempts).toBe(1);
      expect(record.save).toHaveBeenCalled();
    });

    test('the registration is invalidated after repeated failures', async () => {
      const record = pendingRecord('424242', { attempts: 5 });
      PendingUser.findOne.mockImplementation(() => findOneResult(record));

      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: registration.email, otp: '424242' });

      // Even the correct code must not succeed once the limit is reached.
      expect(res.status).toBe(400);
      expect(User.create).not.toHaveBeenCalled();
    });

    test('an expired code is rejected', async () => {
      PendingUser.findOne.mockImplementation(() =>
        findOneResult(pendingRecord('424242', { otpExpire: new Date(Date.now() - 1000) }))
      );

      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: registration.email, otp: '424242' });

      expect(res.status).toBe(400);
      expect(User.create).not.toHaveBeenCalled();
    });
  });
});
