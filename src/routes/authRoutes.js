const { Router } = require("express");
const authCtrl = require("../controllers/authController");
const { authenticate } = require("../middleware/auth");
const { loginLimiter } = require("../middleware/rateLimiter");
const { validate, loginSchema, changePasswordSchema } = require("../middleware/validate");

const router = Router();

// POST /api/auth/login
router.post("/login", loginLimiter, validate(loginSchema), authCtrl.login);

// POST /api/auth/refresh
router.post("/refresh", authCtrl.refresh);

// POST /api/auth/logout  (authenticated)
router.post("/logout", authenticate, authCtrl.logout);

// POST /api/auth/change-password  (authenticated)
router.post("/change-password", authenticate, validate(changePasswordSchema), authCtrl.changePassword);

// ── Password reset flow (unauthenticated) ─────────────────────────────────
// POST /api/auth/send-otp
router.post("/send-otp", authCtrl.sendOtp);

// POST /api/auth/verify-otp
router.post("/verify-otp", authCtrl.verifyOtp);

// POST /api/auth/find-by-email
router.post("/find-by-email", authCtrl.findByEmail);

// POST /api/auth/reset-password
router.post("/reset-password", authCtrl.resetPassword);

module.exports = router;
