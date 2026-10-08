const express = require("express");
const router = express.Router();
const vesselController = require("../controllers/vesselController");
const { protect } = require("../middlewares/authMiddleware");
const authorize = require("../middlewares/authorize");
const zoneRateLimiter = require("../middlewares/zoneRateLimiter");

// FISHERMAN accounts have no legitimate need to create, list, or zone-query vessel records directly — this data feeds officer/admin investigation workflows, so every route here requires an elevated role.
const vesselRoles = ["OFFICER", "ILLEGAL_ADMIN", "SYSTEM_ADMIN"];

router.post("/", protect, authorize(...vesselRoles), vesselController.createVessel);
router.get("/", protect, authorize(...vesselRoles), vesselController.getVessels);
router.get(
  "/zone",
  protect,
  authorize(...vesselRoles),
  zoneRateLimiter,
  vesselController.getVesselsInZone
);

module.exports = router;