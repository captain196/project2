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
router.post(
  "/change-password",
  authenticate,
  validate(changePasswordSchema),
  authCtrl.changePassword
);

module.exports = router;
