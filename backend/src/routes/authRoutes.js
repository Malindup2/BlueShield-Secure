const express = require('express');
const router = express.Router();
const { registerUser, verifyOTP, resendOTP, loginUser, forgotPassword, resetPassword, getMe, listUsers, updateUserRole } = require('../controllers/authController');
const { protect } = require('../middlewares/authMiddleware');
const authorize = require('../middlewares/authorize');
const validate = require('../middlewares/validate');
const v = require('../validations/auth.validation');

router.post('/register', validate(v.register), registerUser);
router.post('/verify-otp', validate(v.verifyOtp), verifyOTP);
router.post('/resend-otp', validate(v.emailOnly), resendOTP);
router.post('/login', validate(v.login), loginUser);
router.post('/forgot-password', validate(v.emailOnly), forgotPassword);
router.post('/reset-password/:token', validate(v.resetPassword), resetPassword);
router.get('/me', protect, getMe);

// V1 — role management. The only way to obtain a privileged role.
router.get('/users', protect, authorize('SYSTEM_ADMIN'), listUsers);
router.patch('/users/:id/role', protect, authorize('SYSTEM_ADMIN'), validate(v.updateUserRole), updateUserRole);

module.exports = router;
