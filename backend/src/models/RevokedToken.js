const mongoose = require('mongoose');

// V13 - tokens revoked before their natural expiry.
// Records are removed automatically once the token would have expired.
const revokedTokenSchema = new mongoose.Schema(
  {
    jti: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    reason: {
      type: String,
      default: 'logout',
    },
    expiresAt: {
      type: Date,
      required: true,
      // TTL index: MongoDB deletes the document at this time.
      expires: 0,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('RevokedToken', revokedTokenSchema);
