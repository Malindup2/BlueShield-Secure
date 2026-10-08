const crypto = require('crypto');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');

const User = require('../models/User');
const generateToken = require('../utils/generateToken');

const GOOGLE_AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

const FLOW_COOKIE = 'bs_oauth_flow';
const FLOW_COOKIE_OPTIONS = {
  httpOnly: true,
  // Must be 'lax': the callback is a top-level navigation from Google, and
  // a strict cookie would not be sent with it.
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  maxAge: 10 * 60 * 1000,
  path: '/api/auth/oauth',
};


const pendingSessions = new Map();
const SESSION_HANDLE_TTL_MS = 60 * 1000;

const putPendingSession = (payload) => {
  const handle = crypto.randomBytes(32).toString('base64url');
  pendingSessions.set(handle, { payload, expiresAt: Date.now() + SESSION_HANDLE_TTL_MS });
  return handle;
};

const takePendingSession = (handle) => {
  const entry = pendingSessions.get(handle);
  if (!entry) return null;
  pendingSessions.delete(handle);
  if (entry.expiresAt < Date.now()) return null;
  return entry.payload;
};

setInterval(() => {
  const now = Date.now();
  for (const [handle, entry] of pendingSessions) {
    if (entry.expiresAt < now) pendingSessions.delete(handle);
  }
}, SESSION_HANDLE_TTL_MS).unref();

const base64UrlSha256 = (input) =>
  crypto.createHash('sha256').update(input).digest('base64url');

const frontendUrl = () => process.env.FRONTEND_URL || 'http://localhost:5173';

const redirectWithError = (res, code) =>
  res.redirect(`${frontendUrl()}/oauth/callback?error=${encodeURIComponent(code)}`);

/**
 * Begin the Google sign-in flow
 * @route   GET /api/auth/oauth/google
 * @access  Public
 */
exports.startGoogleAuth = (req, res) => {
  const { GOOGLE_CLIENT_ID, GOOGLE_REDIRECT_URI } = process.env;

  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
    console.error('[OAuth] GOOGLE_CLIENT_ID or GOOGLE_REDIRECT_URI is not configured');
    return res.status(500).json({ message: 'Google sign-in is not configured on this server' });
  }

  const codeVerifier = crypto.randomBytes(48).toString('base64url');
  const codeChallenge = base64UrlSha256(codeVerifier);
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');

  res.cookie(FLOW_COOKIE, JSON.stringify({ codeVerifier, state, nonce }), FLOW_COOKIE_OPTIONS);

  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'online',
    prompt: 'select_account',
  });

  return res.redirect(`${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`);
};

/**
 * Verify Google's response, provision the local account and hand the
 * frontend a single-use session handle
 * @route   GET /api/auth/oauth/google/callback
 * @access  Public
 */
exports.googleCallback = async (req, res) => {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI } = process.env;

  const rawFlow = req.cookies ? req.cookies[FLOW_COOKIE] : null;
  res.clearCookie(FLOW_COOKIE, { path: FLOW_COOKIE_OPTIONS.path });

  try {
    if (req.query.error) {
      return redirectWithError(res, 'access_denied');
    }

    if (!rawFlow) {
      return redirectWithError(res, 'invalid_session');
    }

    let flow;
    try {
      flow = JSON.parse(rawFlow);
    } catch {
      return redirectWithError(res, 'invalid_session');
    }

    // CSRF protection: a forged callback cannot carry the state bound to
    // this browser's cookie.
    const received = Buffer.from(String(req.query.state || ''));
    const expected = Buffer.from(String(flow.state || ''));
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      console.warn('[OAuth] state mismatch on callback');
      return redirectWithError(res, 'state_mismatch');
    }

    const code = req.query.code;
    if (!code) return redirectWithError(res, 'missing_code');

    // The code_verifier proves the exchange comes from the browser that
    // started the flow.
    const tokenResponse = await axios.post(
      GOOGLE_TOKEN_ENDPOINT,
      new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
        code_verifier: flow.codeVerifier,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 }
    );

    const idToken = tokenResponse.data && tokenResponse.data.id_token;
    if (!idToken) {
      console.error('[OAuth] Token response contained no id_token');
      return redirectWithError(res, 'token_exchange_failed');
    }

    // Verifies the RS256 signature against Google's JWKS and checks iss,
    // aud and exp. The token is never trusted on decoding alone.
    const client = new OAuth2Client(GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const claims = ticket.getPayload();

    if (claims.nonce !== flow.nonce) {
      console.warn('[OAuth] nonce mismatch — possible ID token replay');
      return redirectWithError(res, 'nonce_mismatch');
    }

    const validIssuers = ['accounts.google.com', 'https://accounts.google.com'];
    if (!validIssuers.includes(claims.iss)) {
      return redirectWithError(res, 'invalid_issuer');
    }

    // Without this an attacker could claim someone else's address and take
    // over the matching BlueShield account.
    if (!claims.email || claims.email_verified !== true) {
      return redirectWithError(res, 'email_not_verified');
    }

    const email = String(claims.email).toLowerCase();

    let user = await User.findOne({ googleId: claims.sub });

    if (!user) {
      user = await User.findOne({ email });

      if (user) {
        user.googleId = claims.sub;
        user.authProvider = 'google';
        user.isVerified = true;
      } else {
        // The role is assigned here, never taken from the provider or the
        // client — the same defect class as V1, prevented structurally.
        user = new User({
          name: claims.name || email.split('@')[0],
          email,
          googleId: claims.sub,
          authProvider: 'google',
          role: 'FISHERMAN',
          isVerified: true,
        });
      }
    }

    if (user.isActive === false) {
      return redirectWithError(res, 'account_disabled');
    }

    user.lastLoginAt = Date.now();
    await user.save();

    const handle = putPendingSession({
      _id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id, user.role),
    });

    return res.redirect(`${frontendUrl()}/oauth/callback?handle=${handle}`);
  } catch (error) {
    // Upstream errors can expose client configuration, so they are logged
    // server-side only.
    console.error('[OAuth] Callback failed:', error.response?.data || error.message);
    return redirectWithError(res, 'authentication_failed');
  }
};

/**
 * Exchange a single-use handle for the session payload
 * @route   POST /api/auth/oauth/session
 * @access  Public
 */
exports.exchangeSession = (req, res) => {
  const { handle } = req.body || {};

  if (!handle || typeof handle !== 'string') {
    return res.status(400).json({ message: 'A session handle is required' });
  }

  const payload = takePendingSession(handle);
  if (!payload) {
    return res.status(401).json({ message: 'This sign-in link has expired or already been used' });
  }

  return res.status(200).json(payload);
};
