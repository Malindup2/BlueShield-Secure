const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { isRevoked } = require('../utils/tokenRevocation');

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      // Get token from header (Bearer <token>)
      token = req.headers.authorization.split(' ')[1];

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // V13: a signed, unexpired token may still have been withdrawn.
      if (await isRevoked(decoded.jti)) {
        return res.status(401).json({ message: 'Not authorized, token failed' });
      }

      // V13: kept so logout can revoke the exact token presented.
      req.tokenClaims = decoded;


      // This is a second,
      // independent layer of protection on top of the User schema's
      // select:false fields (otp, otpExpire, resetPasswordToken,
      // resetPasswordExpire, failedLoginAttempts, lockUntil) — even if a
      // future sensitive field is added to the schema without select:false,
      // it still cannot leak through here, since only named fields are ever returned.
      req.user = await User.findById(decoded.id).select(
        'name email phone role isActive isVerified authProvider lastLoginAt createdAt updatedAt'
      );

      if (!req.user) {
        return res.status(401).json({ message: 'Not authorized, user not found' });
      }

      next(); 
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

// Admin Role Check Middleware
// Uses strict set membership instead of a substring match, so a role
// name merely containing "ADMIN" cannot accidentally pass this check.
const ADMIN_ROLES = new Set(['SYSTEM_ADMIN', 'HAZARD_ADMIN', 'ILLEGAL_ADMIN']);

const adminOnly = (req, res, next) => {
  if (req.user && ADMIN_ROLES.has(req.user.role)) {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized as an admin' });
  }
};

module.exports = { protect, adminOnly };