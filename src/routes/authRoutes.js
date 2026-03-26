const { Router } = require("express");
const authCtrl = require("../controllers/authController");
const { authenticate } = require("../middleware/auth");
const { loginLimiter, createRateLimiter, getClientIp } = require("../middleware/rateLimiter");
const { validate, loginSchema, changePasswordSchema } = require("../middleware/validate");

const router = Router();

// ── Rate limiters for sensitive endpoints ──
const otpLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 3,
  keyFn: (req) => `otp:${getClientIp(req)}`,
});

const resetLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) => `reset:${getClientIp(req)}`,
});

const findEmailLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) => `find-email:${getClientIp(req)}`,
});

// POST /api/auth/login
router.post("/login", loginLimiter, validate(loginSchema), authCtrl.login);

// POST /api/auth/refresh
router.post("/refresh", authCtrl.refresh);

// POST /api/auth/logout  (authenticated)
router.post("/logout", authenticate, authCtrl.logout);

// POST /api/auth/change-password  (authenticated)
router.post("/change-password", authenticate, validate(changePasswordSchema), authCtrl.changePassword);

// ── Password reset flow (unauthenticated, rate-limited) ──
router.post("/send-otp", otpLimiter, authCtrl.sendOtp);
router.post("/verify-otp", otpLimiter, authCtrl.verifyOtp);
router.post("/find-by-email", findEmailLimiter, authCtrl.findByEmail);
router.post("/reset-password", resetLimiter, authCtrl.resetPassword);

// POST /api/auth/register-fcm  (authenticated)
router.post("/register-fcm", authenticate, authCtrl.registerFcm);

module.exports = router;
