const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ROLES = ['FISHERMAN', 'ILLEGAL_ADMIN', 'HAZARD_ADMIN', 'OFFICER', 'SYSTEM_ADMIN'];

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name'],
      trim: true,
      minlength: 2,
      maxlength: 60,
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please add a valid email'],
    },
    phone: {
      type: String,
      default: null,
      trim: true,
      match: [/^\+?\d{9,15}$/, 'Invalid phone number'],
    },
    password: {
      type: String,
      // Federated accounts (Google OIDC) have no local password.
      required: [
        function () {
          return this.authProvider === 'local';
        },
        'Please add a password',
      ],
      minlength: 8,
      select: false,
    },
    role: {
      type: String,
      enum: ROLES,
      default: 'FISHERMAN',
      index: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    // --- Sensitive verification/recovery material (V10) -------------------
    // select: false keeps these out of query results by default, so they
    // cannot be returned to a client by accident.
    otp: { type: String, select: false },
    otpExpire: { type: Date, select: false },
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpire: { type: Date, select: false },

    // --- Brute-force protection (V9) --------------------------------------
    failedLoginAttempts: { type: Number, default: 0, select: false },
    lockUntil: { type: Date, default: null, select: false },

    // --- Federated identity (OAuth / OIDC) --------------------------------
    googleId: { type: String, default: null, index: true, sparse: true },
    authProvider: {
      type: String,
      enum: ['local', 'google'],
      default: 'local',
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

// Ensure unique email index
userSchema.index({ email: 1 }, { unique: true });

// Hash password before save
userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Compare password. Federated accounts hold no password hash, so password
// login must always fail for them 
userSchema.methods.matchPassword = async function (enteredPassword) {
  if (!this.password) return false;
  return bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);