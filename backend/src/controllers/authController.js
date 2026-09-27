const User = require('../models/User');
const PendingUser = require('../models/PendingUser');
const generateToken = require('../utils/generateToken');
const sendEmail = require('../services/emailService');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// @desc    Register new user (Phase 1: OTP)
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res, next) => {
  try {
    const { name, email, password, phone, role } = req.body;

    // 1. Check if user already exists in main collection
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists and is verified.' });
    }

    // 2. Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // 3. Save to PendingUser collection (Upsert if already pending)
    await PendingUser.findOneAndDelete({ email }); // Clear any previous attempt
    
    const pendingUser = await PendingUser.create({
      name,
      email,
      password, // Stored temporarily to be hashed by User model later
      phone,
      role: role || 'FISHERMAN',
      otp,
      otpExpire,
    });

    if (pendingUser) {
      // 4. Send OTP via email
      try {
        await sendEmail({
          email: pendingUser.email,
          subject: 'BlueShield - Your Verification Code',
          message: `Your verification code is ${otp}. It expires in 10 minutes.`,
          html: `<h1>Verify Your Account</h1><p>Your verification code is <strong>${otp}</strong>. It expires in 10 minutes.</p>`,
        });

        res.status(201).json({
          message: 'OTP sent to your email. Please verify to complete registration.',
          email: pendingUser.email,
        });
      } catch (err) {
        console.error('Email send failed:', err);
        res.status(201).json({
          message: 'User details saved, but verification email failed to send. Check your configuration.',
          email: pendingUser.email,
          debugCode: otp, // For development purposes
        });
      }
    } else {
      res.status(400).json({ message: 'Invalid registration data' });
    }
  } catch (error) {
    next(error);
  }
};

// @desc    Verify OTP and Create Account
// @route   POST /api/auth/verify-otp
// @access  Public
const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const pendingUser = await PendingUser.findOne({ email });

    if (!pendingUser) {
      return res.status(404).json({ message: 'Registration session expired or not found. Please register again.' });
    }

    // Check OTP (String comparison to be safe)
    if (String(pendingUser.otp) !== String(otp)) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    if (pendingUser.otpExpire < new Date()) {
      return res.status(400).json({ message: 'Verification code has expired. Please request a new one.' });
    }

    // Move to User collection
    const user = await User.create({
      name: pendingUser.name,
      email: pendingUser.email,
      password: pendingUser.password, // This will be hashed by User pre-save hook
      phone: pendingUser.phone,
      role: pendingUser.role,
      isVerified: true,
    });

    // Delete pending record
    await PendingUser.findByIdAndDelete(pendingUser._id);

    res.status(200).json({
      message: 'Account verified and created successfully',
      _id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id, user.role),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Resend OTP
// @route   POST /api/auth/resend-otp
// @access  Public
const resendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    const pendingUser = await PendingUser.findOne({ email });

    if (!pendingUser) {
      return res.status(404).json({ message: 'Registration session not found. Please register again.' });
    }

    // Generate new OTP
    const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
    pendingUser.otp = newOtp;
    pendingUser.otpExpire = new Date(Date.now() + 10 * 60 * 1000);
    await pendingUser.save();

    try {
      await sendEmail({
        email: pendingUser.email,
        subject: 'BlueShield - New Verification Code',
        message: `Your new verification code is ${newOtp}. It expires in 10 minutes.`,
        html: `<h1>New Verification Code</h1><p>Your new verification code is <strong>${newOtp}</strong>.</p>`,
      });

      res.status(200).json({ message: 'New OTP sent to your email.' });
    } catch (err) {
      console.error('Resend Email failed:', err);
      res.status(500).json({ 
        message: 'Failed to send new OTP. Check email configuration.',
        debugCode: newOtp // Allow testing if email fails
      });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Authenticate a user
// @route   POST /api/auth/login
// @access  Public
// V9 — per-account lockout parameters (OWASP A07:2021, CWE-307).
// Complements the IP-based authLimiter: even an attacker rotating IPs cannot
// keep guessing one account's password. Every failure path returns the SAME
// 401 message so a locked account is indistinguishable from a wrong password
// or an unknown user (avoids V14 user enumeration).
const MAX_LOGIN_ATTEMPTS = Number(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const LOCK_TIME_MS = (Number(process.env.LOCK_TIME_MINUTES) || 15) * 60 * 1000;
const GENERIC_LOGIN_ERROR = 'Invalid email or password';

const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Lockout state lives in select:false fields, so request them explicitly.
    const user = await User.findOne({ email }).select(
      '+password +failedLoginAttempts +lockUntil'
    );

    // Account currently locked: refuse without checking the password, using the
    // generic message so the lock is not observable to an attacker.
    if (user && user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(401).json({ message: GENERIC_LOGIN_ERROR });
    }

    if (user && (await user.matchPassword(password))) {
      // Success: clear any accumulated failures and record the login.
      user.failedLoginAttempts = 0;
      user.lockUntil = null;
      user.lastLoginAt = Date.now();
      await user.save();

      return res.json({
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: generateToken(user._id, user.role),
      });
    }

    // Failure against a real account: count it and lock once the threshold is
    // reached. (An unknown email falls through to the same generic response,
    // so the two are indistinguishable.)
    if (user) {
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = new Date(Date.now() + LOCK_TIME_MS);
      }
      await user.save();
    }

    return res.status(401).json({ message: GENERIC_LOGIN_ERROR });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Forgot Password
// @route   POST /api/auth/forgot-password
// @access  Public
const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({ message: 'User not found with that email' });
    }

    // Get reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 30 * 60 * 1000; // 30 minutes

    await user.save();

    // Create reset URL
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    // However, in a real app, this should be the frontend URL
    const frontendResetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password/${resetToken}`;

    const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${frontendResetUrl}`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'BlueShield - Password Reset Token',
        message,
        html: `<h1>Password Reset</h1><p>Click <a href="${frontendResetUrl}">here</a> to reset your password.</p>`,
      });

      res.status(200).json({ message: 'Email sent' });
    } catch (err) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      res.status(500).json({ message: 'Email could not be sent' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Reset Password
// @route   POST /api/auth/reset-password/:token
// @access  Public
const resetPassword = async (req, res) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Set new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(200).json({
      message: 'Password reset successful',
      token: generateToken(user._id, user.role),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Get user data
// @route   GET /api/auth/me
// @access  Private
const getMe = async (req, res) => {
  res.status(200).json(req.user);
};

module.exports = {
  registerUser,
  verifyOTP,
  resendOTP,
  loginUser,
  forgotPassword,
  resetPassword,
  getMe,
};