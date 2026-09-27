// V17 — Transport security (OWASP A02:2021, CWE-319/311)
//
// Before the fix the API was served over plain HTTP with no HSTS and no
// redirect, so credentials/JWTs/OTPs travelled in cleartext. The fix serves
// HTTPS (TLS 1.2+) in server.js and, via enforceHttps, 301-redirects any
// plaintext request to HTTPS. This suite exercises that redirect and confirms
// HSTS is advertised.
//
// FORCE_HTTPS is enabled before app loads so the redirect is active under test
// (it is otherwise off in dev/test).
process.env.FORCE_HTTPS = '1';

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const request = require('supertest');
const app = require('../../src/app');

describe('V17 — HTTPS enforcement and HSTS', () => {
  test('a plaintext HTTP request is 301-redirected to HTTPS', async () => {
    const res = await request(app).get('/').set('X-Forwarded-Proto', 'http');

    expect(res.status).toBe(301);
    expect(res.headers.location).toMatch(/^https:\/\//);
  });

  test('a request already over HTTPS is served normally', async () => {
    const res = await request(app).get('/').set('X-Forwarded-Proto', 'https');

    expect(res.status).toBe(200);
  });

  test('HSTS header instructs clients to use HTTPS', async () => {
    const res = await request(app).get('/').set('X-Forwarded-Proto', 'https');

    expect(res.headers['strict-transport-security']).toMatch(/max-age=\d+/);
  });
});
