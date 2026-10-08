const mongoose = require('mongoose');

const pendingUserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    phone: String,
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      default: 'FISHERMAN',
    },
    // V7: SHA-256 of the verification code, never the code itself.
    otp: {
      type: String,
      required: true,
      select: false,
    },
    otpExpire: {
      type: Date,
      required: true,
    },
    // V7: failed verification attempts against this registration. The
    // registration is discarded once the limit is reached, so a six-digit
    // keyspace cannot be walked.
    attempts: {
      type: Number,
      default: 0,
      select: false,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 900, // Automatically delete after 15 minutes (900 seconds)
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('PendingUser', pendingUserSchema);
