const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// V13 — access tokens are short lived and individually identifiable.
//
// The previous 7-day lifetime meant a captured token stayed usable for a
// week. The jti gives each token an identity, which is what makes
// revocation possible at all:
const ACCESS_TOKEN_TTL = process.env.JWT_EXPIRE || '15m';

const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
    jwtid: crypto.randomBytes(16).toString('hex'),
  });
};

module.exports = generateToken;
