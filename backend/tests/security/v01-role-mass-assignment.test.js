// V1 — Privilege escalation through role mass assignment
// (OWASP A01:2021, CWE-269 / CWE-915)
//
// registerUser destructured `role` from req.body and persisted it, so an
// anonymous caller could choose their own privilege level. The registration
// form offered FISHERMAN, OFFICER, HAZARD_ADMIN and ILLEGAL_ADMIN, and the
// API accepted SYSTEM_ADMIN as well — the one role deliberately withheld
// from the UI. The control existed only on the client.

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
const { findOneResult } = require('./helpers');

const PRIVILEGED_ROLES = ['SYSTEM_ADMIN', 'OFFICER', 'HAZARD_ADMIN', 'ILLEGAL_ADMIN'];

const validRegistration = {
  name: 'Mallory',
  email: 'mallory@example.com',
  password: 'Password123!',
};

// The role persisted to PendingUser by the last register call.
const roleWrittenToPendingUser = () => {
  const call = PendingUser.create.mock.calls.at(-1);
  return call ? call[0].role : undefined;
};

describe('V1 — role mass assignment on registration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    User.findOne.mockImplementation(() => findOneResult(null));
    PendingUser.findOneAndDelete.mockResolvedValue(null);
    PendingUser.create.mockImplementation(async (doc) => ({ ...doc, _id: 'p1' }));
    sendEmail.mockResolvedValue(undefined);
    generateToken.mockReturnValue('token-123');
  });

  describe.each(PRIVILEGED_ROLES)('caller requests role %s', (role) => {
    test('the requested role is never persisted', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ ...validRegistration, role });

      // Either the request is rejected outright, or it succeeds as a
      // FISHERMAN. What must never happen is the privileged role landing
      // in the database.
      if (PendingUser.create.mock.calls.length > 0) {
        expect(roleWrittenToPendingUser()).toBe('FISHERMAN');
      }
    });
  });

  test('a registration carrying no role still works and defaults to FISHERMAN', async () => {
    const res = await request(app).post('/api/auth/register').send(validRegistration);

    expect(res.status).toBe(201);
    expect(roleWrittenToPendingUser()).toBe('FISHERMAN');
  });

  test('role is rejected as an unexpected field rather than silently ignored', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ ...validRegistration, role: 'SYSTEM_ADMIN' });

    expect(res.status).toBe(400);
    expect(PendingUser.create).not.toHaveBeenCalled();
  });

  test('unknown fields in the body are rejected', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ ...validRegistration, isVerified: true, isActive: true });

    expect(res.status).toBe(400);
    expect(PendingUser.create).not.toHaveBeenCalled();
  });

  test('verify-otp creates the account with the role held server-side', async () => {
    PendingUser.findOne.mockResolvedValue({
      _id: 'p1',
      name: 'Mallory',
      email: 'mallory@example.com',
      password: 'hashed',
      phone: null,
      role: 'FISHERMAN',
      otp: '123456',
      otpExpire: new Date(Date.now() + 60000),
    });
    PendingUser.findByIdAndDelete.mockResolvedValue(null);
    User.create.mockImplementation(async (doc) => ({ ...doc, id: 'u1', _id: 'u1' }));

    const res = await request(app)
      .post('/api/auth/verify-otp')
      .send({ email: 'mallory@example.com', otp: '123456' });

    expect(res.status).toBe(200);
    expect(User.create.mock.calls.at(-1)[0].role).toBe('FISHERMAN');
  });

  describe('role management endpoint', () => {
    test('promoting a user requires authentication', async () => {
      const res = await request(app)
        .patch('/api/auth/users/507f1f77bcf86cd799439011/role')
        .send({ role: 'SYSTEM_ADMIN' });

      expect(res.status).toBe(401);
    });

    test('listing users requires authentication', async () => {
      const res = await request(app).get('/api/auth/users');
      expect(res.status).toBe(401);
    });
  });

  test('a pending registration cannot be escalated between register and verify', async () => {
    // Even if the pending record somehow holds a privileged role, account
    // creation must not honour it.
    PendingUser.findOne.mockResolvedValue({
      _id: 'p1',
      name: 'Mallory',
      email: 'mallory@example.com',
      password: 'hashed',
      phone: null,
      role: 'SYSTEM_ADMIN',
      otp: '123456',
      otpExpire: new Date(Date.now() + 60000),
    });
    PendingUser.findByIdAndDelete.mockResolvedValue(null);
    User.create.mockImplementation(async (doc) => ({ ...doc, id: 'u1', _id: 'u1' }));

    await request(app)
      .post('/api/auth/verify-otp')
      .send({ email: 'mallory@example.com', otp: '123456' });

    expect(User.create.mock.calls.at(-1)[0].role).toBe('FISHERMAN');
  });
});
