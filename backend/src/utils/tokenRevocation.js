const RevokedToken = require('../models/RevokedToken');

// V13 - withdrawal of already-issued access tokens.
//
// Logout previously only cleared localStorage on the client, so the token
// itself stayed valid until it expired. These helpers give the server a way
// to refuse a token it has already signed.

// Tokens issued before the jti claim existed cannot be revoked
// individually; they are still bound by the shortened expiry.
const isRevoked = async (jti) => {
  if (!jti) return false;
  return Boolean(await RevokedToken.exists({ jti }));
};

const revoke = async (decoded, userId, reason = 'logout') => {
  if (!decoded || !decoded.jti) return false;

  await RevokedToken.create({
    jti: decoded.jti,
    userId,
    reason,
    // Kept only until the token would have expired anyway, after which the TTL index removes the record.
    expiresAt: new Date((decoded.exp || Math.floor(Date.now() / 1000)) * 1000),
  });

  return true;
};

module.exports = { isRevoked, revoke };
