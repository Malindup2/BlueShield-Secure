// V12 — Security misconfiguration (OWASP A05:2021, CWE-693/16)
//
// Before the fix the app sent no security headers (no helmet), advertised its
// stack via X-Powered-By: Express, and served Swagger UI publicly at /api-docs,
// exposing the full API surface. This suite asserts the hardened state:
//   - helmet security headers are present on ordinary responses,
//   - X-Powered-By is gone,
//   - Swagger is not served outside development (off under NODE_ENV=test).

jest.mock('../../src/models/User');
jest.mock('../../src/models/PendingUser');
jest.mock('../../src/services/emailService');
jest.mock('../../src/utils/generateToken');

const request = require('supertest');
const app = require('../../src/app');

describe('V12 — security headers and Swagger exposure', () => {
  test('helmet security headers are present on responses', async () => {
    const res = await request(app).get('/');

    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBeDefined();
    expect(res.headers['content-security-policy']).toBeDefined();
    // HSTS is emitted by helmet (relevant once served over TLS — see V17).
    expect(res.headers['strict-transport-security']).toBeDefined();
  });

  test('the framework banner X-Powered-By is not exposed', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('Swagger UI is not served outside development', async () => {
    // NODE_ENV is "test" here and ENABLE_SWAGGER is unset, so the docs route is
    // never mounted and returns 404.
    const res = await request(app).get('/api-docs/');
    expect(res.status).toBe(404);
  });
});
