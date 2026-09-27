const jwt = require('jsonwebtoken');
const User = require('../models/User');

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
const adminOnly = (req, res, next) => {
  if (req.user && (req.user.role === 'SYSTEM_ADMIN' || req.user.role.includes('ADMIN'))) {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized as an admin' });
  }
};

module.exports = { protect, adminOnly };