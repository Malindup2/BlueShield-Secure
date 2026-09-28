const rateLimit = require("express-rate-limit");

// /zone proxies a metered, paid external vessel-tracking API.
// This limiter prevents any single account from running up usage/cost.
const zoneRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.user ? req.user._id.toString() : req.ip),
  message: { message: "Too many vessel zone requests. Please wait a few minutes and try again." },
});

module.exports = zoneRateLimiter;