// V6 — NoSQL injection in authentication flows (OWASP A03:2021, CWE-943)
//
// Before the fix, auth controllers passed req.body.email straight into
// Mongoose filters, so a JSON object such as {"$ne": null} became a query
// operator: login matched the first user in the collection, forgot-password
// targeted an arbitrary account, and register deleted someone else's pending
// registration via findOneAndDelete({ email: { $ne: null } }).

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
const { OPERATOR_PAYLOADS, fakeUser, findOneResult } = require('./helpers');

// Every filter object any model method was called with.
const filtersPassedToModels = () =>
  [User.findOne, PendingUser.findOne, PendingUser.findOneAndDelete]
    .flatMap((fn) => fn.mock.calls.map((args) => args[0]))
    .filter(Boolean);

const expectNoOperatorReachedMongo = () => {
  for (const filter of filtersPassedToModels()) {
    for (const value of Object.values(filter)) {
      if (value && typeof value === 'object' && !(value instanceof Date)) {
        const keys = Object.keys(value);
        expect(keys.some((k) => k.startsWith('$'))).toBe(false);
      }
    }
  }
};

describe('V6 — NoSQL injection in auth flows', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Model the database matching whatever filter it is given, so an injected
    // operator would "succeed" if it ever reached the query.
    User.findOne.mockImplementation(() => findOneResult(fakeUser()));
    PendingUser.findOne.mockResolvedValue({ _id: 'p1', email: 'victim@example.com', otp: '123456', otpExpire: new Date(Date.now() + 60000), save: jest.fn() });
    PendingUser.findOneAndDelete.mockResolvedValue(null);
    PendingUser.create.mockResolvedValue({ email: 'nimal@example.com' });
    sendEmail.mockResolvedValue(undefined);
    generateToken.mockReturnValue('token-123');
  });

  describe.each(Object.entries(OPERATOR_PAYLOADS))('operator payload %s', (_name, payload) => {
    test('POST /login rejects an operator in email and password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: payload, password: payload });

      expect(res.status).toBe(400);
      expect(res.body.token).toBeUndefined();
      expect(User.findOne).not.toHaveBeenCalled();
    });

    test('POST /forgot-password rejects an operator in email', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: payload });

      expect(res.status).toBe(400);
      expect(sendEmail).not.toHaveBeenCalled();
    });

    test('POST /verify-otp rejects an operator in email or otp', async () => {
      const res = await request(app)
        .post('/api/auth/verify-otp')
        .send({ email: payload, otp: payload });

      expect(res.status).toBe(400);
      expectNoOperatorReachedMongo();
    });

    test('POST /resend-otp rejects an operator in email', async () => {
      const res = await request(app)
        .post('/api/auth/resend-otp')
        .send({ email: payload });

      expect(res.status).toBe(400);
      expectNoOperatorReachedMongo();
    });

    test('POST /register rejects an operator in email and never deletes a pending user', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ name: 'Mallory', email: payload, password: 'Password123!' });

      expect(res.status).toBe(400);
      expect(PendingUser.findOneAndDelete).not.toHaveBeenCalled();
      expectNoOperatorReachedMongo();
    });
  });

  test('an operator nested anywhere in the body is rejected', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nimal@example.com', password: 'Password123!', x: { $where: '1' } });

    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test('a dotted key (path traversal into sub-documents) is rejected', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nimal@example.com', password: 'Password123!', 'profile.role': 'SYSTEM_ADMIN' });

    expect(res.status).toBe(400);
  });

  test('an array email (implicit $in match) is rejected', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: ['a@example.com', 'nimal@example.com'], password: 'Password123!' });

    expect(res.status).toBe(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test('POST /reset-password/:token rejects a non-string password', async () => {
    const res = await request(app)
      .post('/api/auth/reset-password/abc123')
      .send({ password: { $gt: '' } });

    expect(res.status).toBe(400);
  });

  // Regression: the fix must not break legitimate sign-in.
  test('a well-formed login still succeeds', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nimal@example.com', password: 'Password123!' });

    expect(res.status).toBe(200);
    expect(res.body.token).toBe('token-123');
    expect(User.findOne).toHaveBeenCalledWith({ email: 'nimal@example.com' });
  });
});
