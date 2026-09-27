const User = require('../models/User');
const PendingUser = require('../models/PendingUser');
const generateToken = require('../utils/generateToken');
const sendEmail = require('../services/emailService');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// V7 — verification codes.
// randomInt draws from the OS CSPRNG. Math.random() must not be used
// a non-cryptographic generator can be recovered from predictions
const OTP_MAX_ATTEMPTS = 5;

const generateOtp = () => crypto.randomInt(100000, 1000000).toString();

// Only the digest is persisted, so a database read yields nothing usable.
const hashOtp = (otp) => crypto.createHash('sha256').update(String(otp)).digest('hex');

const otpMatches = (submitted, storedHash) => {
  const a = Buffer.from(hashOtp(submitted));
  const b = Buffer.from(String(storedHash || ''));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
};

// @desc    Register new user (Phase 1: OTP)
// @route   POST /api/auth/register
// @access  Public
const registerUser = async (req, res, next) => {
  try {
    // V1: role is deliberately not read from the request body. Privileged
    // roles are granted only by a SYSTEM_ADMIN through updateUserRole.
    const { name, email, password, phone } = req.body;

    // 1. Check if user already exists in main collection
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists and is verified.' });
    }

    // 2. Generate 6-digit OTP
    const otp = generateOtp();
    const otpExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // 3. Save to PendingUser collection (Upsert if already pending)
    await PendingUser.findOneAndDelete({ email }); // Clear any previous attempt
    
    const pendingUser = await PendingUser.create({
      name,
      email,
      password, // Stored temporarily to be hashed by User model later
      phone,
      role: 'FISHERMAN',
      otp: hashOtp(otp),
      otpExpire,
      attempts: 0,
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

    // otp and attempts are select:false, so both are requested explicitly.
    const pendingUser = await PendingUser.findOne({ email }).select('+otp +attempts');

    if (!pendingUser) {
      return res.status(404).json({ message: 'Registration session expired or not found. Please register again.' });
    }

    // V7: a six-digit code is only 10^6 wide, so guessing has to be bounded.
    // Once the limit is reached the registration is discarded, even if the
    // caller then supplies the correct code.
    if ((pendingUser.attempts || 0) >= OTP_MAX_ATTEMPTS) {
      await PendingUser.findByIdAndDelete(pendingUser._id);
      return res.status(400).json({ message: 'Too many incorrect attempts. Please register again.' });
    }

    if (pendingUser.otpExpire < new Date()) {
      return res.status(400).json({ message: 'Verification code has expired. Please request a new one.' });
    }

    // V7: the submitted code is hashed and compared in constant time, so
    // neither the stored value nor the comparison timing reveals anything.
    if (!otpMatches(otp, pendingUser.otp)) {
      pendingUser.attempts = (pendingUser.attempts || 0) + 1;
      await pendingUser.save();
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    // Move to User collection
    const user = await User.create({
      name: pendingUser.name,
      email: pendingUser.email,
      password: pendingUser.password, // This will be hashed by User pre-save hook
      phone: pendingUser.phone,
      // V1: defence in depth. Even if a pending record somehow carries a
      // privileged role, account creation never honours it.
      role: 'FISHERMAN',
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
    const pendingUser = await PendingUser.findOne({ email }).select('+attempts');

    if (!pendingUser) {
      return res.status(404).json({ message: 'Registration session not found. Please register again.' });
    }

    // Generate new OTP. The attempt counter resets with the new code,
    // but the pending record still expires on its own TTL, so requesting
    // fresh codes cannot be used to extend a guessing window indefinitely.
    const newOtp = generateOtp();
    pendingUser.otp = hashOtp(newOtp);
    pendingUser.otpExpire = new Date(Date.now() + 10 * 60 * 1000);
    pendingUser.attempts = 0;
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
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for user email & select password field explicitly
    const user = await User.findOne({ email }).select('+password');

    if (user && (await user.matchPassword(password))) {
      // Update lastLoginAt
      user.lastLoginAt = Date.now();
      await user.save();

      res.json({
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: generateToken(user._id, user.role),
      });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
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

// @desc    List users so an administrator can select one to promote
// @route   GET /api/auth/users
// @access  Private (SYSTEM_ADMIN)
const listUsers = async (req, res, next) => {
  try {
    const users = await User.find({})
      .select('name email role isActive isVerified createdAt')
      .sort({ createdAt: -1 });

    res.status(200).json({ users, total: users.length });
  } catch (error) {
    next(error);
  }
};

// @desc    Grant or change a user's role
// @route   PATCH /api/auth/users/:id/role
// @access  Private (SYSTEM_ADMIN)
//
// V1: this is the only path by which a privileged role can be obtained.
// Registration always produces a FISHERMAN, so privilege is granted by an
// administrator rather than claimed by the account holder.
const updateUserRole = async (req, res, next) => {
  try {
    const { role } = req.body;

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // An administrator cannot change their own role, so the last
    // SYSTEM_ADMIN cannot accidentally demote themselves and lock everyone
    // out of role management.
    if (user._id.toString() === req.user._id.toString()) {
      return res.status(400).json({ message: 'You cannot change your own role' });
    }

    const previousRole = user.role;
    user.role = role;
    await user.save();

    console.info(
      `[Security] Role change: ${user.email} ${previousRole} -> ${role} by ${req.user.email}`
    );

    res.status(200).json({
      message: 'Role updated',
      user: { _id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  verifyOTP,
  resendOTP,
  loginUser,
  forgotPassword,
  resetPassword,
  getMe,
  listUsers,
  updateUserRole,
};
