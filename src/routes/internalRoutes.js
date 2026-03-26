/**
 * Internal routes for PHP ↔ Node.js communication.
 * Authenticated via X-Internal-Key header.
 */
const { Router } = require("express");
const crypto = require("crypto");
const mongoUserRepo = require("../repositories/mongoUserRepo");
const firebaseUserRepo = require("../repositories/firebaseUserRepo");
const { hashPassword, comparePassword, hashToken, isBcryptHash } = require("../utils/hash");
const { signAccessToken, signRefreshToken } = require("../utils/token");
const { getFirebasePath } = require("../services/userService");
const User = require("../models/User");
const Otp = require("../models/Otp");
const { sendOtpEmail } = require("../utils/email");

const { createRateLimiter, getClientIp } = require("../middleware/rateLimiter");

const router = Router();

function requireInternalKey(req, res, next) {
  const key = req.headers["x-internal-key"];
  if (!key || key !== process.env.AUTH_INTERNAL_SECRET) {
    return res.status(403).json({ success: false, message: "Invalid internal key" });
  }
  next();
}

// Rate limit: 30 requests/minute per IP per endpoint (general internal endpoints)
const internalLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  keyFn: (req) => `internal:${getClientIp(req)}:${req.path}`,
});

// Tighter rate limits for sensitive endpoints
const webLoginLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  keyFn: (req) => `internal-login:${getClientIp(req)}`,
});

const resetPasswordLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) => `internal-reset:${getClientIp(req)}`,
});

router.use(requireInternalKey);
router.use(internalLimiter);

// ─── POST /internal/web-login ─────────────────────────────────────────────────

const LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes
const MAX_LOGIN_ATTEMPTS = 5;

router.post("/web-login", webLoginLimiter, async (req, res) => {
  try {
    const { adminId, password, schoolCode: reqSchoolCode } = req.body;
    if (!adminId || !password) {
      return res.status(400).json({ success: false, message: "adminId and password required" });
    }
    if (typeof adminId !== "string" || typeof password !== "string") {
      return res.status(400).json({ success: false, message: "Invalid input types" });
    }

    // Look up user directly by userId in MongoDB — schoolCode is resolved from the record
    const user = await mongoUserRepo.findByUserId(adminId);

    if (!user || user.status !== "Active") {
      console.info(`AUTH_AUDIT: LOGIN_FAILURE | user=${adminId} | ip=${req.ip} | type=web | reason=${!user ? 'user_not_found' : 'account_inactive'}`);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // School context check: validate schoolCode matches for non-super-admin users
    if (reqSchoolCode && user.role !== "super_admin") {
      if (user.schoolId !== reqSchoolCode && user.schoolCode !== reqSchoolCode) {
        console.warn(`Web-login school mismatch: userId=${adminId}, expected=${reqSchoolCode}, actual schoolId=${user.schoolId} schoolCode=${user.schoolCode}`);
        console.info(`AUTH_AUDIT: LOGIN_FAILURE | user=${adminId} | ip=${req.ip} | type=web | reason=school_mismatch`);
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }
    }

    // Check account lockout
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const remainingMs = new Date(user.lockedUntil).getTime() - Date.now();
      const remainingMin = Math.ceil(remainingMs / 60000);
      return res.status(423).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMin} minute(s).`,
      });
    }

    // If password is not a valid bcrypt hash (legacy plaintext or corrupt), upgrade it
    let passwordToCompare = user.password;
    if (!isBcryptHash(user.password)) {
      // Legacy plaintext password — upgrade to bcrypt immediately
      const upgraded = await hashPassword(user.password);
      await mongoUserRepo.updateByUserId(user.userId, { $set: { password: upgraded } });
      passwordToCompare = upgraded;
      console.info(`AUTH_AUDIT: PASSWORD_UPGRADE | user=${adminId} | from=plaintext | to=bcrypt`);
    }

    // bcrypt.compare handles $2a$/$2b$/$2y$ normalization internally via comparePassword()
    const valid = await comparePassword(password, passwordToCompare);
    if (!valid) {
      // Increment failed login attempts
      const newAttempts = (user.loginAttempts || 0) + 1;
      const updateFields = { $set: { loginAttempts: newAttempts } };
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        updateFields.$set.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
        console.warn(`Account locked after ${MAX_LOGIN_ATTEMPTS} failed attempts: userId=${adminId}`);
      }
      await mongoUserRepo.updateByUserId(user.userId, updateFields);
      console.info(`AUTH_AUDIT: LOGIN_FAILURE | user=${adminId} | ip=${req.ip} | type=web | reason=invalid_password | attempts=${newAttempts}`);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Successful login — reset lockout counters
    if (user.loginAttempts > 0 || user.lockedUntil) {
      await mongoUserRepo.updateByUserId(user.userId, {
        $set: { loginAttempts: 0, lockedUntil: null },
      });
    }

    // schoolId = login code (e.g. 10005) — used for Users/Admin/{schoolId}/
    // schoolCode = Firebase key (e.g. SCH_XXXXXX) — used for System/Schools/{schoolCode}/
    const loginCode = user.schoolId;       // login code for Firebase user path
    const firebaseKey = user.schoolCode;   // internal Firebase key for school data

    let fbPath;
    if (user.role === "super_admin") {
      fbPath = `Users/Admin/Our Panel/${user.userId}`;
    } else {
      fbPath = `Users/Admin/${loginCode}/${user.userId}`;
    }
    const firebaseProfile = await firebaseUserRepo.get(fbPath);

    // Fetch subscription + sessions for school-scoped users
    let subscription = {};
    let sessions = {};
    let displayName = user.name;

    if (firebaseKey && user.role !== "super_admin") {
      // Subscription from System/Schools/{firebaseKey}
      const subSnap = await firebaseUserRepo.get(`System/Schools/${firebaseKey}/subscription`);
      if (subSnap) {
        subscription = {
          status: subSnap.status || "Inactive",
          endDate: subSnap.expiry_date || (subSnap.duration ? subSnap.duration.endDate : ""),
          graceEnd: subSnap.grace_end || "",
          features: subSnap.features || [],
        };
      }

      // Sessions from Schools/{firebaseKey}
      const sessSnap = await firebaseUserRepo.get(`Schools/${firebaseKey}/Sessions`);
      const activeSnap = await firebaseUserRepo.get(`Schools/${firebaseKey}/Config/ActiveSession`);
      const available = Array.isArray(sessSnap) ? sessSnap : (sessSnap ? Object.values(sessSnap) : []);
      sessions = {
        active: activeSnap || (available.length ? available[available.length - 1] : ""),
        available,
      };

      // Display name
      const profileSnap = await firebaseUserRepo.get(`System/Schools/${firebaseKey}/profile`);
      if (profileSnap) displayName = profileSnap.school_name || profileSnap.name || firebaseKey;
    }

    const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    await mongoUserRepo.addRefreshToken(user.userId, hashToken(refreshToken));

    console.info(`AUTH_AUDIT: LOGIN_SUCCESS | user=${adminId} | ip=${req.ip} | type=web | role=${user.role}`);

    res.json({
      success: true,
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email,
        role: user.role,
        schoolId: user.schoolId,
        schoolCode: user.schoolCode,
      },
      firebaseProfile,
      subscription,
      sessions,
      displayName,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Internal web-login error:", error);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// ─── POST /internal/sync-admin ────────────────────────────────────────────────

router.post("/sync-admin", async (req, res) => {
  try {
    let {
      adminId, name, email, phone, role, passwordHash, schoolId, schoolCode, createdBy,
      // Teacher-specific fields
      profilePic, position, department, staffRoles, primaryRole, classesAssigned, subjects, gender,
    } = req.body;
    if (!adminId) return res.status(400).json({ success: false, message: "adminId required" });

    const roleMap = {
      super_admin: "super_admin", school_super_admin: "school_super_admin",
      admin: "admin", teacher: "teacher", student: "student",
      DSA: "super_admin", SSA: "school_super_admin", ADM: "admin",
      TEA: "teacher", STU: "student",
    };
    const mappedRole = roleMap[role] || "admin";

    // Auto-generate IDs if requested (__AUTO_XXX__ pattern)
    const { generateIdForRole } = require("../services/idGenerator");
    const autoMap = {
      "__AUTO_SUP__": "super_admin",
      "__AUTO_SSA__": "school_super_admin",
      "__AUTO_ADM__": "admin",
      "__AUTO_STU__": "student",
      "__AUTO_TEA__": "teacher",
    };
    if (autoMap[adminId]) {
      adminId = await generateIdForRole(autoMap[adminId]);
    }

    const isSuperAdmin = mappedRole === "super_admin";
    const update = {
      $set: {
        name: name || "",
        email: email ? email.toLowerCase() : null,
        phone: phone || null,
        role: mappedRole,
        schoolId: isSuperAdmin ? null : (schoolId || null),
        schoolCode: isSuperAdmin ? null : (schoolCode || null),
        status: "Active",
      },
      $setOnInsert: {
        userId: adminId,
        createdAt: new Date(),
        createdBy: createdBy || "system",
        refreshTokens: [],
        devices: [],
        // Placeholder password for upsert inserts (real hash comes via $set if provided)
        ...(!passwordHash ? { password: "__PENDING__" } : {}),
      },
    };
    if (passwordHash) update.$set.password = passwordHash;

    // Teacher-specific fields — only set if provided (avoids nulling on partial updates)
    if (mappedRole === "teacher") {
      if (profilePic !== undefined) update.$set.profilePic = profilePic || null;
      if (position !== undefined)   update.$set.position = position || null;
      if (department !== undefined)  update.$set.department = department || null;
      if (gender !== undefined)      update.$set.gender = gender || null;
      if (Array.isArray(staffRoles))     update.$set.staffRoles = staffRoles;
      if (primaryRole !== undefined)     update.$set.primaryRole = primaryRole || null;
      if (Array.isArray(classesAssigned)) update.$set.classesAssigned = classesAssigned;
      if (Array.isArray(subjects))        update.$set.subjects = subjects;
    }

    await User.findOneAndUpdate({ userId: adminId }, update, { upsert: true, new: true });

    // ── Dual-write: sync to Firestore 'schoolsync' database ──
    try {
      const firestoreRepo = require("../repositories/firestoreRepo");
      const collection = (mappedRole === "teacher") ? "staff" : "staff";
      await firestoreRepo.setDoc(collection, adminId, {
        userId: adminId,
        name: name || "",
        email: email ? email.toLowerCase() : "",
        phone: phone || "",
        role: mappedRole,
        schoolId: schoolCode || schoolId || "",
        loginCode: schoolId || "",
        department: department || "Administration",
        position: position || mappedRole,
        subjects: Array.isArray(subjects) ? subjects : [],
        classesAssigned: Array.isArray(classesAssigned) ? classesAssigned : [],
        gender: gender || "",
        profilePic: profilePic || "",
        status: "Active",
        syncedAt: firestoreRepo.serverTimestamp(),
        syncSource: "sync-admin",
      }, { merge: true });

      await firestoreRepo.setDoc("users", adminId, {
        userId: adminId,
        name: name || "",
        email: email ? email.toLowerCase() : "",
        role: mappedRole,
        schoolId: schoolCode || schoolId || "",
        profilePic: profilePic || "",
        status: "Active",
        syncedAt: firestoreRepo.serverTimestamp(),
      }, { merge: true });
    } catch (fsErr) {
      console.error("Firestore sync-admin error (non-fatal):", fsErr.message);
    }

    res.json({ success: true, message: "Admin synced", adminId });
  } catch (error) {
    console.error("Internal sync-admin error:", error);
    res.status(500).json({ success: false, message: "Sync failed" });
  }
});

// ─── POST /internal/delete-admin ──────────────────────────────────────────────

router.post("/delete-admin", async (req, res) => {
  try {
    const { adminId } = req.body;
    if (!adminId) return res.status(400).json({ success: false, message: "adminId required" });
    await mongoUserRepo.deleteByUserId(adminId);
    res.json({ success: true, message: "Admin deleted" });
  } catch (error) {
    console.error("Internal delete-admin error:", error);
    res.status(500).json({ success: false, message: "Delete failed" });
  }
});

// ─── POST /internal/reset-password ────────────────────────────────────────────

router.post("/reset-password", resetPasswordLimiter, async (req, res) => {
  try {
    const { adminId, passwordHash } = req.body;
    if (!adminId || !passwordHash) return res.status(400).json({ success: false, message: "adminId and passwordHash required" });
    if (typeof adminId !== "string" || typeof passwordHash !== "string") {
      return res.status(400).json({ success: false, message: "Invalid input types" });
    }

    // passwordHash field actually receives PLAINTEXT password — hash it before storing
    const hashed = await hashPassword(passwordHash);
    const result = await mongoUserRepo.updateByUserId(adminId, {
      $set: { password: hashed, refreshTokens: [], devices: [], loginAttempts: 0, lockedUntil: null },
    });

    // ── Sync to Firebase RTDB (same as /reset-password-otp) ──
    const user = await mongoUserRepo.findByUserId(adminId);
    if (user) {
      const fbPath = getFirebasePath(user.role, user.schoolId, adminId);
      await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch((e) => {
        console.error(`Firebase password sync failed for ${adminId}:`, e.message);
      });
    }

    console.info(`AUTH_AUDIT: PASSWORD_RESET | user=${adminId} | type=admin_direct | firebase_synced=${!!user}`);
    res.json({ success: true, message: result ? "Password reset" : "Admin not found" });
  } catch (error) {
    console.error("Internal reset-password error:", error);
    res.status(500).json({ success: false, message: "Reset failed" });
  }
});

// ─── POST /internal/generate-id ───────────────────────────────────────────────

router.post("/generate-id", async (req, res) => {
  try {
    let { prefix } = req.body;
    if (!prefix) return res.status(400).json({ success: false, message: "prefix required" });

    // Peek mode: return next ID without incrementing (for form preview)
    // e.g. prefix="STU_PEEK" → peek at next STU counter
    const isPeek = prefix.endsWith("_PEEK");
    const actualPrefix = isPeek ? prefix.replace("_PEEK", "") : prefix;

    const { getNextSequence, peekNextSequence } = require("../repositories/counterRepo");
    const seq = isPeek
      ? await peekNextSequence(actualPrefix)
      : await getNextSequence(actualPrefix);

    // School codes: 5-digit number starting from 10001
    if (actualPrefix === "SCHCODE") {
      return res.json({ success: true, id: String(10000 + seq) });
    }

    // Role-based IDs: PREFIX + 4-digit padded
    res.json({ success: true, id: `${actualPrefix}${String(seq).padStart(4, "0")}` });
  } catch (error) {
    console.error("Internal generate-id error:", error);
    res.status(500).json({ success: false, message: "ID generation failed" });
  }
});

// ─── POST /internal/reset-counter ─────────────────────────────────────────────
// Reset an ID counter to a specific value (admin/migration use only).

router.post("/reset-counter", async (req, res) => {
  try {
    const { prefix, value } = req.body;
    if (!prefix) return res.status(400).json({ success: false, message: "prefix required" });
    const Counter = require("../models/Counter");
    await Counter.findOneAndUpdate({ _id: prefix }, { seq: value ?? 0 }, { upsert: true });
    const doc = await Counter.findOne({ _id: prefix });
    res.json({ success: true, prefix, seq: doc.seq });
  } catch (error) {
    console.error("Internal reset-counter error:", error);
    res.status(500).json({ success: false, message: "Counter reset failed" });
  }
});

// ─── POST /internal/forgot-password ───────────────────────────────────────────
// Step 1: User submits adminId → system finds email → sends OTP

router.post("/forgot-password", async (req, res) => {
  try {
    const { adminId } = req.body;
    if (!adminId) return res.status(400).json({ success: false, message: "Admin ID is required" });

    const user = await mongoUserRepo.findByUserId(adminId);
    if (!user || !user.email) {
      // Don't reveal if user exists — always show same message
      return res.json({ success: true, message: "If this Admin ID exists, an OTP has been sent to the registered email." });
    }

    if (user.status !== "Active") {
      return res.json({ success: true, message: "If this Admin ID exists, an OTP has been sent to the registered email." });
    }

    // Rate limit: max 3 OTPs per user in 15 minutes
    const recentCount = await Otp.countDocuments({
      userId: adminId,
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) },
    });
    if (recentCount >= 3) {
      return res.status(429).json({ success: false, message: "Too many OTP requests. Try again in 15 minutes." });
    }

    // Generate 6-digit OTP
    const otpCode = crypto.randomInt(100000, 999999).toString();

    // Save OTP (hashed — plain text never stored)
    await Otp.create({
      userId: adminId,
      email: user.email,
      code: hashToken(otpCode),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    });

    // Send email (plain OTP sent to user's inbox)
    const emailSent = await sendOtpEmail(user.email, user.name, otpCode);

    // Mask email for response
    const parts = user.email.split("@");
    const masked = parts[0].substring(0, 2) + "***@" + parts[1];

    res.json({
      success: true,
      message: "OTP sent to " + masked,
      email_masked: masked,
      email_sent: emailSent,
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ success: false, message: "Failed to process request" });
  }
});

// ─── POST /internal/verify-otp ───────────────────────────────────────────────
// Step 2: User submits adminId + OTP → verify

router.post("/verify-otp", async (req, res) => {
  try {
    const { adminId, otp } = req.body;
    if (!adminId || !otp) {
      return res.status(400).json({ success: false, message: "Admin ID and OTP are required" });
    }

    const otpDoc = await Otp.findOne({
      userId: adminId,
      code: hashToken(otp),
      used: false,
      expiresAt: { $gt: new Date() },
    }).sort({ createdAt: -1 });

    if (!otpDoc) {
      // Track attempts on most recent OTP
      await Otp.updateMany(
        { userId: adminId, used: false },
        { $inc: { attempts: 1 } }
      );
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    if (otpDoc.attempts >= 5) {
      return res.status(429).json({ success: false, message: "Too many failed attempts. Request a new OTP." });
    }

    // Generate a one-time reset token (valid 10 minutes)
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Mark OTP as used
    otpDoc.used = true;
    await otpDoc.save();

    // Store reset token (hashed — plain text never stored)
    await Otp.create({
      userId: adminId,
      email: otpDoc.email,
      code: hashToken(resetToken),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    });

    res.json({ success: true, message: "OTP verified", resetToken });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// ─── POST /internal/reset-password-otp ───────────────────────────────────────
// Step 3: User submits adminId + resetToken + newPassword → reset

router.post("/reset-password-otp", async (req, res) => {
  try {
    const { adminId, resetToken, newPassword } = req.body;
    if (!adminId || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: "Password must be at least 8 characters" });
    }

    // Verify reset token (compare hashes)
    const tokenDoc = await Otp.findOne({
      userId: adminId,
      code: hashToken(resetToken),
      used: false,
      expiresAt: { $gt: new Date() },
    });

    if (!tokenDoc) {
      return res.status(400).json({ success: false, message: "Invalid or expired reset token. Please start over." });
    }

    // Mark token as used
    tokenDoc.used = true;
    await tokenDoc.save();

    // Hash new password
    const hashed = await hashPassword(newPassword);

    // Update MongoDB
    await mongoUserRepo.updateByUserId(adminId, {
      $set: { password: hashed, refreshTokens: [] },
    });

    // Update Firebase
    const user = await mongoUserRepo.findByUserId(adminId);
    if (user) {
      const fbPath = getFirebasePath(user.role, user.schoolId, adminId);
      await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch(() => {});
    }

    // Cleanup all OTPs for this user
    await Otp.deleteMany({ userId: adminId });

    res.json({ success: true, message: "Password reset successfully. You can now login with your new password." });
  } catch (error) {
    console.error("Reset password OTP error:", error);
    res.status(500).json({ success: false, message: "Password reset failed" });
  }
});

// ─── POST /internal/forgot-password-student ───────────────────────────────────
// Student password reset: parent enters email → finds ALL student accounts with
// that email → sends ONE OTP → returns masked account list for selection.
// Works for siblings sharing a parent email.

router.post("/forgot-password-student", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: "Email is required" });

    const normalizedEmail = email.toLowerCase().trim();

    // Find ALL student accounts with this email
    const students = await User.find({
      email: normalizedEmail,
      role: "student",
      status: "Active",
    }).lean();

    if (!students.length) {
      // Don't reveal if email exists
      return res.json({ success: true, message: "If this email is registered, an OTP has been sent." });
    }

    // Rate limit: max 3 OTPs per email in 15 minutes
    const recentCount = await Otp.countDocuments({
      email: normalizedEmail,
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) },
    });
    if (recentCount >= 3) {
      return res.status(429).json({ success: false, message: "Too many OTP requests. Try again in 15 minutes." });
    }

    // Generate 6-digit OTP (one OTP for all accounts under this email)
    const otpCode = crypto.randomInt(100000, 999999).toString();

    // Save OTP linked to email (not userId — covers all siblings)
    await Otp.create({
      userId: "__EMAIL__" + normalizedEmail,
      email: normalizedEmail,
      code: hashToken(otpCode),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    // Send email
    const firstName = students[0].name.split(" ")[0];
    const emailSent = await sendOtpEmail(normalizedEmail, firstName, otpCode);

    // Build masked account list for the UI
    const accounts = students.map((s) => ({
      userId: s.userId,
      name: s.name,
      className: s.className || "",
      section: s.section || "",
      schoolDisplayName: s.schoolDisplayName || "",
      // Mask userId partially: STU0001 → STU***1
      userIdMasked: s.userId.substring(0, 3) + "***" + s.userId.slice(-1),
    }));

    const parts = normalizedEmail.split("@");
    const emailMasked = parts[0].substring(0, 2) + "***@" + parts[1];

    res.json({
      success: true,
      message: "OTP sent to " + emailMasked,
      email_masked: emailMasked,
      email_sent: emailSent,
      accounts,
    });
  } catch (error) {
    console.error("Forgot password student error:", error);
    res.status(500).json({ success: false, message: "Failed to process request" });
  }
});

// ─── POST /internal/verify-otp-student ────────────────────────────────────────
// Step 2: Parent submits email + OTP + selected userId → verify and issue reset token

router.post("/verify-otp-student", async (req, res) => {
  try {
    const { email, otp, userId } = req.body;
    if (!email || !otp || !userId) {
      return res.status(400).json({ success: false, message: "Email, OTP, and selected account are required" });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const otpKey = "__EMAIL__" + normalizedEmail;

    const otpDoc = await Otp.findOne({
      userId: otpKey,
      code: hashToken(otp),
      used: false,
      expiresAt: { $gt: new Date() },
    }).sort({ createdAt: -1 });

    if (!otpDoc) {
      await Otp.updateMany({ userId: otpKey, used: false }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    if (otpDoc.attempts >= 5) {
      return res.status(429).json({ success: false, message: "Too many failed attempts. Request a new OTP." });
    }

    // Verify the selected userId actually belongs to this email
    const student = await User.findOne({ userId, email: normalizedEmail, role: "student" });
    if (!student) {
      return res.status(400).json({ success: false, message: "Account not found for this email" });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Mark OTP as used
    otpDoc.used = true;
    await otpDoc.save();

    // Store reset token for the specific student
    await Otp.create({
      userId,
      email: normalizedEmail,
      code: hashToken(resetToken),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    res.json({ success: true, message: "OTP verified", resetToken, userId });
  } catch (error) {
    console.error("Verify OTP student error:", error);
    res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// ─── POST /internal/reset-password-student ────────────────────────────────────
// Step 3: Reset password for the selected student account

router.post("/reset-password-student", async (req, res) => {
  try {
    const { userId, resetToken, newPassword } = req.body;
    if (!userId || !resetToken || !newPassword) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters" });
    }

    // Verify reset token
    const tokenDoc = await Otp.findOne({
      userId,
      code: hashToken(resetToken),
      used: false,
      expiresAt: { $gt: new Date() },
    });

    if (!tokenDoc) {
      return res.status(400).json({ success: false, message: "Invalid or expired reset token. Please start over." });
    }

    tokenDoc.used = true;
    await tokenDoc.save();

    const hashed = await hashPassword(newPassword);

    // Update MongoDB
    await mongoUserRepo.updateByUserId(userId, {
      $set: { password: hashed, refreshTokens: [], devices: [] },
    });

    // Update Firebase — use HASHED password (NEVER plaintext)
    const user = await mongoUserRepo.findByUserId(userId);
    if (user) {
      const fbKey = user.parentDbKey || user.schoolId;
      const fbPath = getFirebasePath(user.role, fbKey, userId);
      await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch((e) => {
        console.error(`Firebase password sync failed for ${userId}:`, e.message);
      });
    }

    // Cleanup OTPs
    await Otp.deleteMany({ userId });
    // Also clean email-based OTPs
    if (user && user.email) {
      await Otp.deleteMany({ userId: "__EMAIL__" + user.email });
    }

    console.info(`AUTH_AUDIT: PASSWORD_RESET | user=${userId} | type=student_otp | firebase_synced=${!!user}`);
    res.json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    console.error("Reset password student error:", error);
    res.status(500).json({ success: false, message: "Password reset failed" });
  }
});

// ─── POST /internal/sync-student ──────────────────────────────────────────────
// Called by PHP after saving student to Firebase. Syncs auth credentials to MongoDB.
// Stores full profile for mobile app login + device binding.

router.post("/sync-student", async (req, res) => {
  try {
    let {
      studentId, name, email, phone, password, passwordHash,
      schoolId, schoolCode, parentDbKey, parentPhone, createdBy,
      // Student profile fields (for mobile app quick access)
      className, section, rollNo, fatherName, motherName, dob,
      admissionDate, gender, profilePic, schoolDisplayName,
      // Device binding config
      deviceBindingMethod,
    } = req.body;

    if (!studentId) {
      return res.status(400).json({ success: false, message: "studentId required" });
    }

    // Auto-generate ID if requested
    if (studentId === "__AUTO_STU__") {
      const { generateIdForRole } = require("../services/idGenerator");
      studentId = await generateIdForRole("student");
    }

    // Hash password if raw password provided (not pre-hashed)
    let finalHash = passwordHash || null;
    if (!finalHash && password) {
      finalHash = await hashPassword(password);
    }

    const update = {
      $set: {
        name: name || "",
        email: email ? email.toLowerCase() : null,
        phone: phone || null,
        role: "student",
        schoolId: schoolId || null,        // Login code (e.g. "10004")
        schoolCode: schoolCode || null,    // Firebase key (e.g. "Demo" or "SCH_XXXXXX")
        parentDbKey: parentDbKey || schoolId || null,  // Firebase Users/Parents key
        parentPhone: parentPhone || phone || null,
        status: "Active",
        // Student profile fields
        className: className || null,
        section: section || null,
        rollNo: rollNo || null,
        fatherName: fatherName || null,
        motherName: motherName || null,
        dob: dob || null,
        admissionDate: admissionDate || null,
        gender: gender || null,
        profilePic: profilePic || null,
        schoolDisplayName: schoolDisplayName || null,
        // Device binding: "otp" = require OTP for new devices, "auto" = auto-bind first device
        deviceBindingMethod: deviceBindingMethod || "otp",
      },
      $setOnInsert: {
        userId: studentId,
        createdAt: new Date(),
        createdBy: createdBy || "system",
        refreshTokens: [],
        devices: [],
      },
    };
    if (finalHash) update.$set.password = finalHash;

    const doc = await User.findOneAndUpdate(
      { userId: studentId },
      update,
      { upsert: true, new: true }
    );

    // ── Dual-write: sync to Firestore 'schoolsync' database ──
    try {
      const firestoreRepo = require("../repositories/firestoreRepo");
      await firestoreRepo.setDoc("students", studentId, {
        userId: studentId,
        name: name || "",
        email: email ? email.toLowerCase() : "",
        phone: phone || "",
        schoolId: schoolCode || schoolId || "",
        loginCode: schoolId || "",
        className: className || "",
        section: section || "",
        rollNo: rollNo || "",
        fatherName: fatherName || "",
        motherName: motherName || "",
        dob: dob || "",
        gender: gender || "",
        admissionDate: admissionDate || "",
        parentDbKey: parentDbKey || schoolId || "",
        profilePic: profilePic || "",
        status: "Active",
        session: "",
        syncedAt: firestoreRepo.serverTimestamp(),
        syncSource: "sync-student",
      }, { merge: true });

      await firestoreRepo.setDoc("users", studentId, {
        userId: studentId,
        name: name || "",
        email: email ? email.toLowerCase() : "",
        role: "student",
        schoolId: schoolCode || schoolId || "",
        profilePic: profilePic || "",
        status: "Active",
        syncedAt: firestoreRepo.serverTimestamp(),
      }, { merge: true });
    } catch (fsErr) {
      console.error("Firestore sync-student error (non-fatal):", fsErr.message);
    }

    res.json({ success: true, message: "Student synced", studentId, mongoId: doc._id });
  } catch (error) {
    console.error("Internal sync-student error:", error.message, error.code, error.keyPattern);
    const detail = error.code === 11000
      ? `Duplicate key: ${JSON.stringify(error.keyPattern)}`
      : error.message;
    res.status(500).json({ success: false, message: "Student sync failed", detail });
  }
});

// ─── POST /internal/mobile-app-login ─────────────────────────────────────────
// Mobile app login with device binding for students AND teachers.
// First login from any device auto-binds it.
// Subsequent logins from unknown devices → DEVICE_NOT_BOUND error → app must
// call /request-device-otp then /verify-device-otp to bind new device.
// Legacy alias: /student-app-login still works (redirects here).

const DEVICE_LIMITS = { super_admin: 5, school_super_admin: 3, admin: 3, teacher: 2, student: 3 };

const mobileAppLoginHandler = async (req, res) => {
  try {
    const { userId: studentId, password, device } = req.body;

    if (!studentId || !password) {
      return res.status(400).json({ success: false, message: "userId and password required" });
    }
    if (!device || !device.deviceId) {
      return res.status(400).json({ success: false, message: "device.deviceId required for mobile login" });
    }

    // 1. Find user — userId is globally unique (all IDs from central counter)
    const user = await mongoUserRepo.findByUserId(studentId);
    if (!user || user.status !== "Active") {
      console.info(`AUTH_AUDIT: LOGIN_FAILURE | user=${studentId} | ip=${req.ip} | type=mobile | deviceId=${device.deviceId} | reason=${!user ? 'user_not_found' : 'account_inactive'}`);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // 1b. Check account lockout
    if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
      const remainingMs = new Date(user.lockedUntil).getTime() - Date.now();
      const remainingMin = Math.ceil(remainingMs / 60000);
      return res.status(423).json({
        success: false,
        message: `Account temporarily locked. Try again in ${remainingMin} minute(s).`,
      });
    }

    // 2. Verify password — if legacy plaintext, hash it first then always use bcrypt
    let passwordToCompare = user.password;
    if (!user.password.startsWith("$2")) {
      // Legacy plaintext password — upgrade immediately
      const upgraded = await hashPassword(user.password);
      await mongoUserRepo.updateByUserId(user.userId, { $set: { password: upgraded } });
      passwordToCompare = upgraded;
    }

    const valid = await comparePassword(password, passwordToCompare);
    if (!valid) {
      // Increment failed login attempts
      const newAttempts = (user.loginAttempts || 0) + 1;
      const updateFields = { $set: { loginAttempts: newAttempts } };
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        updateFields.$set.lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MS);
        console.warn(`Mobile account locked after ${MAX_LOGIN_ATTEMPTS} failed attempts: userId=${studentId}`);
      }
      await mongoUserRepo.updateByUserId(user.userId, updateFields);
      console.info(`AUTH_AUDIT: LOGIN_FAILURE | user=${studentId} | ip=${req.ip} | type=mobile | reason=invalid_password | attempts=${newAttempts}`);
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Successful login — reset lockout counters
    if (user.loginAttempts > 0 || user.lockedUntil) {
      await mongoUserRepo.updateByUserId(user.userId, {
        $set: { loginAttempts: 0, lockedUntil: null },
      });
    }

    // 3. Device binding check
    const activeDevices = (user.devices || []).filter(d => d.status === "active");
    const knownDevice = activeDevices.find(d => d.deviceId === device.deviceId);
    const blockedDevice = (user.devices || []).find(d => d.deviceId === device.deviceId && d.status === "blocked");

    if (blockedDevice) {
      return res.status(403).json({
        success: false,
        code: "DEVICE_BLOCKED",
        message: "This device has been blocked. Contact your school admin.",
      });
    }

    if (!knownDevice && activeDevices.length > 0) {
      // Unknown device + already has bound device(s) → require OTP
      return res.status(403).json({
        success: false,
        code: "DEVICE_NOT_BOUND",
        message: "This device is not registered. Verify with OTP to add this device.",
        parentPhoneMasked: user.parentPhone
          ? user.parentPhone.replace(/.(?=.{4})/g, "*")
          : null,
        emailMasked: user.email
          ? user.email.replace(/(.{2}).*(@.*)/, "$1***$2")
          : null,
      });
    }

    // 4. Auto-bind if first device (no devices yet)
    // Use _id for updates to avoid cross-school collisions on duplicate studentIds
    const userFilter = { _id: user._id };
    if (!knownDevice && activeDevices.length === 0) {
      const newDevice = {
        deviceId: device.deviceId,
        deviceName: device.deviceName || "Unknown Device",
        platform: device.platform || "android",
        os: device.os || "",
        appVersion: device.appVersion || "",
        boundAt: new Date(),
        lastUsedAt: new Date(),
        status: "active",
      };
      await User.findOneAndUpdate(userFilter, { $push: { devices: newDevice } });
    } else if (knownDevice) {
      // Update lastUsedAt
      await User.findOneAndUpdate(
        { _id: user._id, "devices.deviceId": device.deviceId },
        {
          $set: {
            "devices.$.lastUsedAt": new Date(),
            "devices.$.appVersion": device.appVersion || knownDevice.appVersion,
          },
        }
      );
    }

    // 5. Issue tokens
    const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    // Enforce refresh token limit per role
    const maxDevices = DEVICE_LIMITS[user.role] || 2;
    if (user.refreshTokens.length >= maxDevices) {
      await User.findOneAndUpdate(userFilter, { $pop: { refreshTokens: -1 } });
    }
    await User.findOneAndUpdate(userFilter, {
      $push: { refreshTokens: { tokenHash: hashToken(refreshToken), createdAt: new Date() } },
    });

    // 6. Fetch Firebase profile (role-aware paths)
    //    For students/teachers: parentDbKey is the correct Firebase Users/Parents key
    //    (handles legacy schools where parentDbKey differs from schoolId)
    const { getFirebasePath } = require("../services/userService");
    const fbKey = user.parentDbKey || user.schoolId;
    const fbPath = getFirebasePath(user.role, fbKey, user.userId);
    const firebaseProfile = await firebaseUserRepo.get(fbPath);

    // 7. Fetch school info for the app
    let schoolInfo = null;
    if (user.schoolCode) {
      const profile = await firebaseUserRepo.get(`System/Schools/${user.schoolCode}/profile`);
      if (profile) {
        schoolInfo = {
          schoolName: profile.school_name || "",
          city: profile.city || "",
          logo: profile.logo_url || "",
        };
      }
    }

    console.info(`AUTH_AUDIT: LOGIN_SUCCESS | user=${user.userId} | ip=${req.ip} | type=mobile | deviceId=${device.deviceId} | role=${user.role}`);

    res.json({
      success: true,
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone || "",
        role: user.role,
        schoolId: user.schoolId,
        schoolCode: user.schoolCode,
        schoolDisplayName: user.schoolDisplayName || schoolInfo?.schoolName || "",
        parentDbKey: user.parentDbKey || user.schoolId || "",
        className: user.className || "",
        section: user.section || "",
        rollNo: user.rollNo || "",
        fatherName: user.fatherName || "",
        motherName: user.motherName || "",
        dob: user.dob || "",
        gender: user.gender || "",
        admissionDate: user.admissionDate || "",
        profilePic: user.profilePic || "",
        position: user.position || "",
        department: user.department || "",
        classesAssigned: user.classesAssigned || [],
        subjects: user.subjects || [],
      },
      firebaseProfile,
      schoolInfo,
      accessToken,
      refreshToken,
      deviceBound: !knownDevice ? "new_binding" : "existing",
    });
  } catch (error) {
    console.error("Mobile app login error:", error);
    res.status(500).json({ success: false, message: "Login failed" });
  }
};

// Register both routes (new name + legacy alias)
router.post("/mobile-app-login", mobileAppLoginHandler);
router.post("/student-app-login", mobileAppLoginHandler);

// ─── POST /internal/request-device-otp ───────────────────────────────────────
// Sends OTP to parent's email for new device binding verification.
// Mobile app calls this when it gets DEVICE_NOT_BOUND from student-app-login.

router.post("/request-device-otp", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, message: "userId required" });
    }

    const user = await mongoUserRepo.findByUserId(userId);
    if (!user || user.status !== "Active") {
      return res.json({ success: true, message: "If this account exists, an OTP has been sent." });
    }

    // Rate limit: max 3 OTPs per 15 minutes
    const recentCount = await Otp.countDocuments({
      userId,
      createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) },
    });
    if (recentCount >= 3) {
      return res.status(429).json({ success: false, message: "Too many OTP requests. Try again in 15 minutes." });
    }

    const otpCode = crypto.randomInt(100000, 999999).toString();

    await Otp.create({
      userId,
      email: user.email || "",
      code: hashToken(otpCode),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    // Send OTP via email (SMS integration can be added later)
    let emailSent = false;
    if (user.email) {
      emailSent = await sendOtpEmail(user.email, user.name, otpCode);
    }

    const maskedPhone = user.parentPhone
      ? user.parentPhone.replace(/.(?=.{4})/g, "*")
      : null;
    const maskedEmail = user.email
      ? user.email.replace(/(.{2}).*(@.*)/, "$1***$2")
      : null;

    res.json({
      success: true,
      message: "OTP sent",
      phoneMasked: maskedPhone,
      emailMasked: maskedEmail,
      emailSent,
    });
  } catch (error) {
    console.error("Request device OTP error:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ─── POST /internal/verify-device-otp ────────────────────────────────────────
// Verify OTP and bind new device + auto-login. Called after /request-device-otp.

router.post("/verify-device-otp", async (req, res) => {
  try {
    const { userId, otp, device } = req.body;
    if (!userId || !otp || !device || !device.deviceId) {
      return res.status(400).json({ success: false, message: "userId, otp, and device required" });
    }

    // Verify OTP
    const otpDoc = await Otp.findOne({
      userId,
      code: hashToken(otp),
      used: false,
      expiresAt: { $gt: new Date() },
    }).sort({ createdAt: -1 });

    if (!otpDoc) {
      await Otp.updateMany({ userId, used: false }, { $inc: { attempts: 1 } });
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    if (otpDoc.attempts >= 5) {
      return res.status(429).json({ success: false, message: "Too many failed attempts. Request a new OTP." });
    }

    otpDoc.used = true;
    await otpDoc.save();

    const user = await mongoUserRepo.findByUserId(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Enforce device limit — remove oldest if at max
    const maxDevices = DEVICE_LIMITS[user.role] || 2;
    const activeDevices = (user.devices || []).filter(d => d.status === "active");
    if (activeDevices.length >= maxDevices) {
      const oldest = activeDevices.sort((a, b) => new Date(a.boundAt) - new Date(b.boundAt))[0];
      await User.findOneAndUpdate({ userId }, { $pull: { devices: { deviceId: oldest.deviceId } } });
    }

    // Bind new device
    const newDevice = {
      deviceId: device.deviceId,
      deviceName: device.deviceName || "Unknown Device",
      platform: device.platform || "android",
      os: device.os || "",
      appVersion: device.appVersion || "",
      boundAt: new Date(),
      lastUsedAt: new Date(),
      status: "active",
    };
    await User.findOneAndUpdate({ userId }, { $push: { devices: newDevice } });

    // Auto-login: issue tokens
    const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);
    await mongoUserRepo.addRefreshToken(user.userId, hashToken(refreshToken));

    const { getFirebasePath: getFbPath } = require("../services/userService");
    const fbPath = getFbPath(user.role, user.schoolId, user.userId);
    const firebaseProfile = await firebaseUserRepo.get(fbPath);

    res.json({
      success: true,
      message: "Device verified and bound successfully",
      user: {
        userId: user.userId, name: user.name, email: user.email,
        role: user.role, schoolId: user.schoolId, schoolCode: user.schoolCode,
      },
      firebaseProfile,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Verify device OTP error:", error);
    res.status(500).json({ success: false, message: "Device verification failed" });
  }
});

// ─── POST /internal/bind-device ───────────────────────────────────────────────
// Called from mobile app on first login — binds device to user account.
// For teachers: device binding is mandatory (enforced on mobile login).
// Max 2 devices per teacher by default.

router.post("/bind-device", async (req, res) => {
  try {
    const { userId, deviceId, deviceName, platform, os, appVersion, ip } = req.body;
    if (!userId || !deviceId) {
      return res.status(400).json({ success: false, message: "userId and deviceId required" });
    }

    const user = await User.findOne({ userId });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.status !== "Active") return res.status(403).json({ success: false, message: "Account is inactive" });

    // Check if device already bound
    const existing = user.devices.find((d) => d.deviceId === deviceId);
    if (existing) {
      if (existing.status === "blocked") {
        return res.status(403).json({ success: false, message: "This device has been blocked. Contact your school admin." });
      }
      // Update last used
      existing.lastUsedAt = new Date();
      if (deviceName) existing.deviceName = deviceName;
      if (os) existing.os = os;
      if (appVersion) existing.appVersion = appVersion;
      await user.save();
      return res.json({ success: true, message: "Device already bound", device: existing });
    }

    // Check max devices limit (default 2 for teacher/student)
    const MAX_DEVICES = { super_admin: 5, school_super_admin: 3, admin: 3, teacher: 2, student: 3 };
    const maxDevices = MAX_DEVICES[user.role] || 2;
    const activeDevices = user.devices.filter((d) => d.status === "active");

    if (activeDevices.length >= maxDevices) {
      return res.status(403).json({
        success: false,
        message: `Maximum ${maxDevices} devices allowed. Remove an existing device first.`,
        code: "MAX_DEVICES_REACHED",
        devices: activeDevices.map((d) => ({ deviceId: d.deviceId, deviceName: d.deviceName, platform: d.platform, boundAt: d.boundAt })),
      });
    }

    // Bind new device
    const newDevice = {
      deviceId,
      deviceName: deviceName || "Unknown Device",
      platform: platform || "android",
      os: os || "",
      appVersion: appVersion || "",
      boundAt: new Date(),
      lastUsedAt: new Date(),
      status: "active",
      registeredIp: ip || null,
    };
    user.devices.push(newDevice);
    await user.save();

    res.json({ success: true, message: "Device bound successfully", device: newDevice });
  } catch (error) {
    console.error("Internal bind-device error:", error);
    res.status(500).json({ success: false, message: "Device binding failed" });
  }
});

// ─── POST /internal/verify-device ────────────────────────────────────────────
// Check if a device is bound to a user (called before mobile login).

router.post("/verify-device", async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    if (!userId || !deviceId) {
      return res.status(400).json({ success: false, message: "userId and deviceId required" });
    }

    const user = await User.findOne({ userId });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const device = user.devices.find((d) => d.deviceId === deviceId);
    if (!device) {
      return res.json({
        success: true,
        bound: false,
        message: "Device not bound to this account",
        totalDevices: user.devices.filter((d) => d.status === "active").length,
      });
    }

    if (device.status === "blocked") {
      return res.json({ success: true, bound: false, blocked: true, message: "Device has been blocked" });
    }

    res.json({ success: true, bound: true, device: { deviceId: device.deviceId, deviceName: device.deviceName, platform: device.platform, boundAt: device.boundAt } });
  } catch (error) {
    console.error("Internal verify-device error:", error);
    res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// ─── POST /internal/remove-device ────────────────────────────────────────────
// Remove a bound device (called by admin panel or user self-service).

router.post("/remove-device", async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    if (!userId || !deviceId) {
      return res.status(400).json({ success: false, message: "userId and deviceId required" });
    }

    const result = await User.findOneAndUpdate(
      { userId },
      { $pull: { devices: { deviceId } } },
      { new: true }
    );

    if (!result) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, message: "Device removed", remainingDevices: result.devices.length });
  } catch (error) {
    console.error("Internal remove-device error:", error);
    res.status(500).json({ success: false, message: "Device removal failed" });
  }
});

// ─── POST /internal/block-device ─────────────────────────────────────────────
// Block a device (called by admin when device is compromised/stolen).

router.post("/block-device", async (req, res) => {
  try {
    const { userId, deviceId } = req.body;
    if (!userId || !deviceId) {
      return res.status(400).json({ success: false, message: "userId and deviceId required" });
    }

    const user = await User.findOne({ userId });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    const device = user.devices.find((d) => d.deviceId === deviceId);
    if (!device) return res.status(404).json({ success: false, message: "Device not found" });

    device.status = "blocked";
    await user.save();

    // Also clear refresh tokens to force re-login
    await mongoUserRepo.clearRefreshTokens(userId);

    res.json({ success: true, message: "Device blocked and all sessions invalidated" });
  } catch (error) {
    console.error("Internal block-device error:", error);
    res.status(500).json({ success: false, message: "Device blocking failed" });
  }
});

// ─── POST /internal/list-devices ─────────────────────────────────────────────
// List all devices bound to a user.

router.post("/list-devices", async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ success: false, message: "userId required" });

    const user = await User.findOne({ userId });
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({
      success: true,
      devices: user.devices.map((d) => ({
        deviceId: d.deviceId,
        deviceName: d.deviceName,
        platform: d.platform,
        os: d.os,
        appVersion: d.appVersion,
        status: d.status,
        boundAt: d.boundAt,
        lastUsedAt: d.lastUsedAt,
      })),
    });
  } catch (error) {
    console.error("Internal list-devices error:", error);
    res.status(500).json({ success: false, message: "Failed to list devices" });
  }
});

// ─── POST /internal/sync-to-firestore ──────────────────────────────────────────
// Syncs entity data from admin panel to Firestore.
// Body: { entity: "schools"|"staff"|"students"|"parents"|"sections"|"users", id: string, data: object }

router.post("/sync-to-firestore", async (req, res) => {
  try {
    const { entity, id, data } = req.body;
    if (!entity || !id) {
      return res.status(400).json({ success: false, message: "entity and id required" });
    }

    const firestoreRepo = require("../repositories/firestoreRepo");
    const validEntities = ["schools", "staff", "students", "parents", "sections", "users"];
    if (!validEntities.includes(entity)) {
      return res.status(400).json({ success: false, message: `Invalid entity: ${entity}` });
    }

    const docData = {
      ...data,
      syncedAt: firestoreRepo.serverTimestamp(),
      syncSource: "admin_panel",
    };

    await firestoreRepo.setDoc(entity, id, docData, { merge: true });

    res.json({ success: true, message: `Synced ${entity}/${id} to Firestore` });
  } catch (err) {
    console.error("sync-to-firestore error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── POST /internal/notifications/library ─────────────────────────────────────
// Send FCM push notification for library overdue reminders.
// Called by PHP admin panel after writing notification to Firestore.
// Body: { userId, schoolId, title, body }

const { getStudentTokensById, sendToTokens } = require("../controllers/notificationController");

router.post("/notifications/library", async (req, res) => {
  try {
    const { userId, schoolId, title, body } = req.body;
    if (!userId || !schoolId) {
      return res.status(400).json({ success: false, message: "userId and schoolId are required" });
    }

    const tokens = await getStudentTokensById(schoolId, userId);

    const notifTitle = title || "Library Reminder";
    const notifBody = body || "You have a library book reminder";
    const data = {
      type: "library_reminder",
      studentId: String(userId),
      schoolId: String(schoolId),
    };

    const result = await sendToTokens(tokens, notifTitle, notifBody, data);

    res.json({
      success: true,
      message: `Library notification sent to ${result.successCount} device(s)`,
      tokensTargeted: tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (err) {
    console.error("internal/notifications/library error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── GET /internal/health ─────────────────────────────────────────────────────

router.get("/health", (req, res) => {
  res.json({ success: true, status: "ok", timestamp: new Date().toISOString() });
});

module.exports = router;
