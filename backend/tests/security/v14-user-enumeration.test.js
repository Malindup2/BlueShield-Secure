// V14 — User enumeration and verbose error leakage
// (OWASP A01:2021 / A09:2021, CWE-204 / CWE-209)
//
// The API told an anonymous caller which email addresses hold accounts:
// forgot-password answered 404 "User not found with that email" for an
// unknown address and 200 "Email sent" for a known one, and registration
// answered 400 "User already exists and is verified."  Either response is
// enough to harvest a list of valid users before attacking them.
//
// Failures also returned raw exception text — res.status(500).json({
// message: error.message }) — exposing Mongoose and driver internals, and
// the translation proxy returned upstream Azure error bodies verbatim.
//
// Nothing was logged, so credential attacks left no trace.

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const request = require('supertest');
const app = require('../../src/app');
const User = require('../../src/models/User');
const PendingUser = require('../../src/models/PendingUser');
const sendEmail = require('../../src/services/emailService');
const generateToken = require('../../src/utils/generateToken');
const { fakeUser, findOneResult } = require('./helpers');

const KNOWN = 'known@example.com';
const UNKNOWN = 'nobody@example.com';

// Text that must never reach a client.
const INTERNAL_MARKERS = [
  'Mongo', 'mongoose', 'ECONNREFUSED', 'E11000', 'at Object.',
  'node_modules', 'Cast to ObjectId', 'buffering timed out',
];

const leaksInternals = (body) => {
  const text = JSON.stringify(body || {});
  return INTERNAL_MARKERS.some((m) => text.includes(m));
};

describe('V14 — user enumeration and verbose errors', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    sendEmail.mockResolvedValue(undefined);
    generateToken.mockReturnValue('token-123');
    PendingUser.findOneAndDelete.mockResolvedValue(null);
    PendingUser.create.mockImplementation(async (doc) => ({ ...doc, _id: 'p1' }));
  });

  describe('forgot-password does not disclose whether an account exists', () => {
    const forgot = (email) =>
      request(app).post('/api/auth/forgot-password').send({ email });

    test('an unknown address gets the same status as a known one', async () => {
      User.findOne.mockImplementation(() => findOneResult(null));
      const unknown = await forgot(UNKNOWN);

      User.findOne.mockImplementation(() =>
        findOneResult(fakeUser({ email: KNOWN, save: jest.fn() }))
      );
      const known = await forgot(KNOWN);

      expect(unknown.status).toBe(known.status);
      expect(unknown.status).toBe(200);
    });

    test('an unknown address gets the same body as a known one', async () => {
      User.findOne.mockImplementation(() => findOneResult(null));
      const unknown = await forgot(UNKNOWN);

      User.findOne.mockImplementation(() =>
        findOneResult(fakeUser({ email: KNOWN, save: jest.fn() }))
      );
      const known = await forgot(KNOWN);

      expect(unknown.body).toEqual(known.body);
    });

    test('the response never says the user was not found', async () => {
      User.findOne.mockImplementation(() => findOneResult(null));
      const res = await forgot(UNKNOWN);

      expect(JSON.stringify(res.body)).not.toMatch(/not found/i);
    });
  });

  describe('registration does not disclose existing accounts', () => {
    test('registering an address already in use does not reveal it', async () => {
      User.findOne.mockImplementation(() =>
        findOneResult(fakeUser({ email: KNOWN }))
      );

      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Mallory', email: KNOWN, password: 'Password123!' });

      expect(JSON.stringify(res.body)).not.toMatch(/already exists/i);
      // No pending registration is created for an address that is taken,
      // but the caller cannot tell that from the response.
      expect(PendingUser.create).not.toHaveBeenCalled();
    });

    test('a taken address and a free address are indistinguishable', async () => {
      User.findOne.mockImplementation(() => findOneResult(fakeUser({ email: KNOWN })));
      const taken = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Mallory', email: KNOWN, password: 'Password123!' });

      jest.clearAllMocks();
      sendEmail.mockResolvedValue(undefined);
      PendingUser.findOneAndDelete.mockResolvedValue(null);
      PendingUser.create.mockImplementation(async (doc) => ({ ...doc, _id: 'p1' }));
      User.findOne.mockImplementation(() => findOneResult(null));
      const free = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Mallory', email: UNKNOWN, password: 'Password123!' });

      expect(taken.status).toBe(free.status);
      expect(taken.body.message).toBe(free.body.message);
    });
  });

  describe('failures do not leak internals', () => {
    test('a database failure during login returns a generic message', async () => {
      User.findOne.mockImplementation(() => {
        throw new Error('E11000 duplicate key error collection: blueshield.users');
      });

      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: KNOWN, password: 'Password123!' });

      expect(res.status).toBe(500);
      expect(leaksInternals(res.body)).toBe(false);
      expect(res.body.stack).toBeUndefined();
    });

    test('a database failure during forgot-password returns a generic message', async () => {
      User.findOne.mockImplementation(() => {
        throw new Error('connect ECONNREFUSED 127.0.0.1:27017');
      });

      const res = await request(app).post('/api/auth/forgot-password').send({ email: KNOWN });

      expect(leaksInternals(res.body)).toBe(false);
    });

    test('a failure during verify-otp returns a generic message', async () => {
      PendingUser.findOne.mockImplementation(() => {
        throw new Error('Cast to ObjectId failed for value "x" at path "_id"');
      });

      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: KNOWN, otp: '123456' });

      expect(leaksInternals(res.body)).toBe(false);
    });
  });

  describe('security logging', () => {
    test('a failed sign-in is recorded', async () => {
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});

      User.findOne.mockImplementation(() =>
        findOneResult(fakeUser({ email: KNOWN, passwordMatches: false }))
      );

      await request(app).post('/api/auth/login').send({ email: KNOWN, password: 'wrong' });

      expect(warn).toHaveBeenCalled();
      expect(warn.mock.calls.flat().join(' ')).toMatch(/login/i);

      warn.mockRestore();
    });
  });
});
