// V13 — Insecure JWT lifetime and absent revocation
// (OWASP A02:2021 / A07:2021, CWE-613 / CWE-522)
//
// Tokens were issued with expiresIn: '7d' and carried no identifier, so
// there was no way to refer to an individual token after issuing it.
// Logout only cleared localStorage on the client, which means a token
// captured by any means stayed valid for up to a week regardless of the
// user signing out, changing their password, or being deactivated.
//
// Scope:  Moving the token
// out of localStorage into an httpOnly cookie is deferred -- it introduces
// CSRF and requires a compensating control -- and is recorded as accepted
// residual risk.

jest.mock('../../src/models/User');
jest.mock('../../src/models/RevokedToken');

const jwt = require('jsonwebtoken');
const request = require('supertest');
const app = require('../../src/app');
const User = require('../../src/models/User');
const RevokedToken = require('../../src/models/RevokedToken');
const generateToken = require('../../src/utils/generateToken');
const { fakeUser, findOneResult } = require('./helpers');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

const decode = (token) => jwt.verify(token, process.env.JWT_SECRET);

describe('V13 — token lifetime and revocation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    RevokedToken.exists.mockResolvedValue(null);
    RevokedToken.create.mockResolvedValue({});
    User.findById.mockImplementation(() => ({
      select: jest.fn().mockResolvedValue(fakeUser()),
    }));
    User.findOne.mockImplementation(() => findOneResult(fakeUser()));
  });

  describe('lifetime', () => {
    test('an access token is short lived, not a week', () => {
      const claims = decode(generateToken('user-1', 'FISHERMAN'));
      const lifetimeSeconds = claims.exp - claims.iat;

      // 7 days was 604800. Anything beyond an hour leaves too long a window
      // for a captured token.
      expect(lifetimeSeconds).toBeLessThanOrEqual(60 * 60);
    });

    test('the token carries an identifier so it can be revoked', () => {
      const claims = decode(generateToken('user-1', 'FISHERMAN'));
      expect(typeof claims.jti).toBe('string');
      expect(claims.jti.length).toBeGreaterThan(16);
    });

    test('two tokens for the same user have different identifiers', () => {
      const a = decode(generateToken('user-1', 'FISHERMAN'));
      const b = decode(generateToken('user-1', 'FISHERMAN'));
      expect(a.jti).not.toBe(b.jti);
    });
  });

  describe('revocation', () => {
    test('a valid token is accepted', async () => {
      const token = generateToken('user-1', 'FISHERMAN');

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
    });

    test('a revoked token is rejected', async () => {
      const token = generateToken('user-1', 'FISHERMAN');
      RevokedToken.exists.mockResolvedValue({ _id: 'r1' });

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(401);
    });

    test('logout revokes the presented token', async () => {
      const token = generateToken('user-1', 'FISHERMAN');

      const res = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(RevokedToken.create).toHaveBeenCalled();

      const stored = RevokedToken.create.mock.calls.at(-1)[0];
      expect(stored.jti).toBe(decode(token).jti);
      // Stored with the token's own expiry so the record can be dropped
      // once the token would have expired anyway.
      expect(stored.expiresAt).toBeInstanceOf(Date);
    });

    test('logout requires authentication', async () => {
      const res = await request(app).post('/api/auth/logout');
      expect(res.status).toBe(401);
    });

    test('a token used after logout no longer works', async () => {
      const token = generateToken('user-1', 'FISHERMAN');

      await request(app).post('/api/auth/logout').set('Authorization', `Bearer ${token}`);

      // The revocation record now exists.
      RevokedToken.exists.mockResolvedValue({ _id: 'r1' });

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(401);
    });
  });
});
