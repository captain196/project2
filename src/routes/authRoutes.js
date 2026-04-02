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

// POST /api/auth/update-profile-pic  (authenticated)
// Updates profilePic URL in Firestore (students can't write directly due to security rules)
router.post("/update-profile-pic", authenticate, async (req, res) => {
  try {
    const { profilePicUrl } = req.body;
    const userId = req.user.userId;
    const schoolCode = req.user.schoolCode || req.user.schoolId;

    if (!profilePicUrl || !userId) {
      return res.status(400).json({ success: false, message: "profilePicUrl is required" });
    }

    // Resolve Firebase school key
    const firestoreRepo = require("../repositories/firestoreRepo");
    const firebaseUserRepo = require("../repositories/firebaseUserRepo");
    let firebaseKey = schoolCode;
    if (schoolCode && !schoolCode.startsWith("SCH_")) {
      const resolved = await firebaseUserRepo.get(`Indexes/School_codes/${schoolCode}`);
      if (resolved) firebaseKey = resolved;
    }

    // Determine user role for correct Firestore paths (lookup from DB if JWT role missing)
    let role = req.user.role;
    if (!role) {
      const User = require("../models/User");
      const dbUser = await User.findOne({ userId }).select("role").lean();
      role = dbUser?.role || "student";
    }
    const isTeacher = ["teacher", "class_teacher"].includes(role);
    const isStaff = ["librarian", "accountant", "transport_manager", "hostel_warden", "hr_manager", "front_office", "principal", "vice_principal", "academic_coordinator"].includes(role);
    const isAdmin = ["admin", "school_super_admin"].includes(role);

    // Update Firestore: role-aware user collection
    const firestoreUserRole = isTeacher ? "teacher" : isStaff ? "staff" : isAdmin ? "admin" : "student";
    const userCollection = firestoreRepo.userCollectionPath(firestoreUserRole, firebaseKey);
    await firestoreRepo.setDoc(userCollection, userId, { profilePic: profilePicUrl }, { merge: true });

    // Update Firestore: school data collection (students or staff)
    if (!isTeacher && !isStaff && !isAdmin) {
      await firestoreRepo.setDoc(`schools/${firebaseKey}/students`, userId, { profilePic: profilePicUrl }, { merge: true });
    }

    // Update MongoDB profilePic field
    const User = require("../models/User");
    await User.updateOne({ userId }, { $set: { profilePic: profilePicUrl } });

    res.json({ success: true, message: "Profile photo updated", profilePicUrl });
  } catch (error) {
    console.error("update-profile-pic error:", error.message);
    res.status(500).json({ success: false, message: "Failed to update profile photo" });
  }
});

module.exports = router;
