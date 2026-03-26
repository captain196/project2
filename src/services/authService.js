const mongoUserRepo = require("../repositories/mongoUserRepo");
const firebaseUserRepo = require("../repositories/firebaseUserRepo");
const firestoreRepo = require("../repositories/firestoreRepo");
const { comparePassword, hashPassword, hashToken, isBcryptHash } = require("../utils/hash");
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../utils/token");
const { AuthError, ValidationError, NotFoundError } = require("../utils/errors");
const { getFirebasePath, MAX_REFRESH_TOKENS } = require("./userService");
const Otp = require("../models/Otp");
const { sendOtpEmail } = require("../utils/email");
const User = require("../models/User");
const crypto = require("crypto");
const { admin } = require("../config/firebase");

// Helper: hash OTP code with SHA-256 before storing/comparing
function hashOtp(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
}

// Roles that require device binding for mobile login
const DEVICE_BOUND_ROLES = ["teacher", "student"];

// ─── Login (email + password) ─────────────────────────────────────────────────
// deviceId is optional — when provided (mobile app), device binding is enforced
// for teacher/student roles.

async function loginUser(userId, password, deviceId) {
  if (!userId || !password) throw new ValidationError("User ID and password are required");
  if (typeof userId !== "string" || typeof password !== "string") throw new ValidationError("Invalid input types");

  const user = await mongoUserRepo.findByUserId(userId);
  if (!user) {
    // Log actual reason server-side, return generic message to client
    console.warn(`Login failed: user not found — userId=${userId}`);
    throw new AuthError("Invalid credentials");
  }
  if (user.status !== "Active") {
    console.warn(`Login failed: account inactive — userId=${userId}`);
    throw new AuthError("Invalid credentials");
  }

  const valid = await comparePassword(password, user.password);
  if (!valid) {
    console.warn(`Login failed: invalid password — userId=${userId}`);
    throw new AuthError("Invalid credentials");
  }

  // ── Device binding check for mobile logins ──
  if (deviceId && DEVICE_BOUND_ROLES.includes(user.role)) {
    const device = user.devices.find((d) => d.deviceId === deviceId);

    if (!device) {
      // First-time device — auto-bind if under limit
      const MAX_DEVICES = { teacher: 2, student: 2 };
      const maxDevices = MAX_DEVICES[user.role] || 2;
      const activeDevices = user.devices.filter((d) => d.status === "active");

      if (activeDevices.length >= maxDevices) {
        const err = new AuthError(
          `Device not registered. Maximum ${maxDevices} devices allowed. Contact your school admin to remove an old device.`
        );
        err.code = "DEVICE_LIMIT_REACHED";
        err.devices = activeDevices.map((d) => ({ deviceName: d.deviceName, boundAt: d.boundAt }));
        throw err;
      }

      // Auto-bind this device on successful login
      user.devices.push({
        deviceId,
        deviceName: "Auto-bound on login",
        platform: "android",
        boundAt: new Date(),
        lastUsedAt: new Date(),
        status: "active",
      });
      await user.save();
    } else if (device.status === "blocked") {
      throw new AuthError("This device has been blocked. Contact your school admin.");
    } else {
      // Update last used timestamp
      device.lastUsedAt = new Date();
      await user.save();
    }
  }

  // Fetch full profile from Firebase
  const fbPath = getFirebasePath(user.role, user.schoolId, user.userId);
  const firebaseProfile = await firebaseUserRepo.get(fbPath);

  // Generate tokens
  const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);
  const tokenHash = hashToken(refreshToken);

  // Enforce max device tokens
  const maxTokens = MAX_REFRESH_TOKENS[user.role] || 2;
  let currentTokens = user.refreshTokens || [];
  if (currentTokens.length >= maxTokens) {
    currentTokens.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const toRemove = currentTokens.slice(0, currentTokens.length - maxTokens + 1);
    for (const t of toRemove) {
      await mongoUserRepo.removeRefreshToken(user.userId, t.tokenHash);
    }
  }

  await mongoUserRepo.addRefreshToken(user.userId, tokenHash);

  // Update last login in Firebase (best-effort)
  const now = new Date().toISOString().replace("T", " ").substring(0, 19);
  await firebaseUserRepo.update(fbPath, {
    "AccessHistory/SA_LastLogin": now,
  }).catch(() => {});

  // Base fields — all roles
  const userPayload = {
    userId:     user.userId,
    name:       user.name,
    email:      user.email       || null,
    phone:      user.phone       || null,
    role:       user.role,
    schoolId:   user.schoolId    || null,
    schoolDisplayName: user.schoolDisplayName || null,
    status:     user.status,
    profilePic: user.profilePic  || null,
  };

  // Student-specific fields
  if (user.role === "student") {
    Object.assign(userPayload, {
      className:     user.className     || null,
      section:       user.section       || null,
      rollNo:        user.rollNo        || null,
      fatherName:    user.fatherName    || null,
      motherName:    user.motherName    || null,
      dob:           user.dob           || null,
      gender:        user.gender        || null,
      admissionDate: user.admissionDate || null,
      parentDbKey:   user.parentDbKey   || null,
    });
  }

  // Teacher-specific fields
  if (user.role === "teacher") {
    Object.assign(userPayload, {
      position:        user.position    || null,
      department:      user.department  || null,
      primaryRole:     user.primaryRole || null,
      staffRoles:      user.staffRoles  || [],
      classesAssigned: user.classesAssigned || [],
      subjects:        user.subjects    || [],
    });
  }

  // Generate Firebase custom token for RTDB Security Rules
  // Claims must include parentDbKey + schoolId so Security Rules can
  // restrict reads to Users/Parents/{parentDbKey}/{userId}/ and
  // Schools/{schoolId}/ subtrees only.
  let firebaseToken = null;
  try {
    firebaseToken = await admin.auth().createCustomToken(user.userId, {
      role:        user.role,
      userId:      user.userId,
      schoolId:    user.schoolCode  || user.schoolId || null,  // Firebase school key (SCH_XXX) for Firestore rules
      loginCode:   user.schoolId    || null,                   // Login code (10005) for RTDB paths
      parentDbKey: user.parentDbKey || user.schoolCode || user.schoolId || null,
      schoolCode:  user.schoolCode  || user.schoolId || null,
    });
  } catch (fbErr) {
    console.error("Firebase custom token error:", fbErr.message);
  }

  // ── Dual-write: sync user to Firestore 'schoolsync' database ──
  try {
    await firestoreRepo.setDoc("users", user.userId, {
      userId: user.userId,
      name: userPayload.name || "",
      email: userPayload.email || "",
      role: user.role,
      schoolId: user.schoolCode || user.schoolId || "",
      profilePic: userPayload.profilePic || "",
      status: user.status,
      lastLoginAt: firestoreRepo.serverTimestamp(),
    }, { merge: true });
  } catch (fsErr) {
    console.error("Firestore user sync error (non-fatal):", fsErr.message);
  }

  console.info(`AUTH_AUDIT: LOGIN_SUCCESS | user=${user.userId} | type=mobile | role=${user.role}${deviceId ? ` | deviceId=${deviceId}` : ''}`);

  return { accessToken, refreshToken, firebaseToken, user: userPayload };
}

// ─── Refresh Token ────────────────────────────────────────────────────────────

async function refreshAccessToken(refreshToken) {
  if (!refreshToken) throw new AuthError("Refresh token required");

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch {
    throw new AuthError("Invalid or expired refresh token");
  }

  // Validate JWT payload structure — reject tokens with missing required fields
  if (!decoded.userId || !decoded.role) {
    throw new AuthError("Malformed token: missing required fields");
  }

  const user = await mongoUserRepo.findByUserId(decoded.userId);
  if (!user || user.status !== "Active") throw new AuthError("User not found or inactive");

  const tokenHash = hashToken(refreshToken);
  const tokenExists = user.refreshTokens.some((t) => t.tokenHash === tokenHash);

  if (!tokenExists) {
    // Token hash not found — it was already used (possible replay attack).
    // Revoke ALL refresh tokens for this user as a security precaution.
    console.warn(`Refresh token replay detected — revoking all tokens for userId=${user.userId}`);
    await mongoUserRepo.clearRefreshTokens(user.userId);
    throw new AuthError("Suspicious activity detected. All sessions have been revoked. Please log in again.");
  }

  // Remove the old token BEFORE issuing a new one (prevents replay window)
  await mongoUserRepo.removeRefreshToken(user.userId, tokenHash);

  // Check session idle timeout (reject if no activity in 24 hours)
  if (user.lastActivityAt) {
    const idleMs = Date.now() - new Date(user.lastActivityAt).getTime();
    const IDLE_TIMEOUT_MS = 24 * 60 * 60 * 1000; // 24 hours
    if (idleMs > IDLE_TIMEOUT_MS) {
      console.warn(`Session idle timeout — userId=${user.userId}, last activity ${Math.round(idleMs / 3600000)}h ago`);
      await mongoUserRepo.clearRefreshTokens(user.userId);
      throw new AuthError("Session expired due to inactivity. Please log in again.");
    }
  }

  const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
  const newAccessToken = signAccessToken(payload);
  const newRefreshToken = signRefreshToken(payload);
  await mongoUserRepo.addRefreshToken(user.userId, hashToken(newRefreshToken));

  // Re-issue Firebase custom token (Firebase custom tokens expire after 1 hour)
  let firebaseToken = null;
  try {
    firebaseToken = await admin.auth().createCustomToken(user.userId, {
      role:        user.role,
      userId:      user.userId,
      schoolId:    user.schoolCode  || user.schoolId || null,
      loginCode:   user.schoolId    || null,
      parentDbKey: user.parentDbKey || user.schoolCode || user.schoolId || null,
      schoolCode:  user.schoolCode  || user.schoolId || null,
    });
  } catch (fbErr) {
    console.error("Firebase custom token error on refresh:", fbErr.message);
  }

  return { accessToken: newAccessToken, refreshToken: newRefreshToken, firebaseToken };
}

// ─── Logout ───────────────────────────────────────────────────────────────────

async function logoutUser(userId, refreshToken, deviceId) {
  // Remove the specific refresh token (this device's session)
  if (refreshToken) {
    await mongoUserRepo.removeRefreshToken(userId, hashToken(refreshToken));
  } else {
    // No token provided — revoke ALL sessions for safety
    await mongoUserRepo.clearRefreshTokens(userId);
  }

  // Remove device binding on logout
  if (deviceId) {
    try {
      await mongoUserRepo.updateByUserId(userId, {
        $pull: { devices: { deviceId } },
      });
    } catch (e) {
      console.warn("Failed to remove device on logout:", e.message);
    }
  }

  // Update lastActivityAt so other sessions see accurate state
  await mongoUserRepo.updateByUserId(userId, {
    $set: { lastActivityAt: new Date() },
  }).catch(() => {});

  // Clear Firebase RTDB presence (best-effort)
  try {
    const user = await mongoUserRepo.findByUserId(userId);
    if (user) {
      const schoolCode = user.schoolCode || user.schoolId || "";
      if (schoolCode) {
        // Clear presence node so other systems know user is offline
        await firebaseUserRepo.update(`Presence/${userId}`, { online: false, lastSeen: new Date().toISOString() }).catch(() => {});
      }
      // Clear notification badge for this device
      if (deviceId) {
        await firebaseUserRepo.update(`NotifBadge/${userId}`, { [deviceId]: null }).catch(() => {});
      }
    }
  } catch (_) { /* best effort */ }

  console.info(`AUTH_AUDIT: LOGOUT | user=${userId}${deviceId ? ` | deviceId=${deviceId}` : ""} | token=${refreshToken ? "specific" : "all"}`);
  return { message: "Logged out successfully" };
}

// ─── Change Password ─────────────────────────────────────────────────────────

async function changePassword(userId, currentPassword, newPassword) {
  if (!currentPassword || !newPassword) throw new ValidationError("Current and new password required");
  if (newPassword.length < 8) throw new ValidationError("Password must be at least 8 characters");

  const user = await mongoUserRepo.findByUserId(userId);
  if (!user) throw new NotFoundError("User not found");

  const valid = await comparePassword(currentPassword, user.password);
  if (!valid) throw new AuthError("Current password is incorrect");

  const hashed = await hashPassword(newPassword);

  // MongoDB — clear all sessions, devices, and unlock
  await mongoUserRepo.updateByUserId(userId, {
    $set: { password: hashed, refreshTokens: [], devices: [], loginAttempts: 0, lockedUntil: null },
  });

  // Firebase RTDB — sync hashed password
  const fbPath = getFirebasePath(user.role, user.schoolId, userId);
  await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch((e) => {
    console.error(`Firebase password sync failed for ${userId}:`, e.message);
  });

  console.info(`AUTH_AUDIT: PASSWORD_CHANGED | user=${userId} | all_sessions_cleared=true`);
  return { message: "Password changed. All sessions invalidated." };
}

// ─── Send Password Reset OTP ──────────────────────────────────────────────────

async function sendPasswordResetOtp(email) {
  if (!email) throw new ValidationError("Email is required");

  const users = await User.find({ email: email.toLowerCase() }).lean();
  if (!users.length) throw new NotFoundError("No account found with this email");

  const code = crypto.randomInt(100000, 999999).toString();
  const hashedCode = hashOtp(code);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

  // Upsert OTP — one per email at a time (store hashed, never plaintext)
  await Otp.findOneAndUpdate(
    { email: email.toLowerCase() },
    { userId: users[0].userId, email: email.toLowerCase(), code: hashedCode, expiresAt, attempts: 0, used: false },
    { upsert: true, new: true }
  );

  const sent = await sendOtpEmail(email, users[0].name, code);
  if (!sent) throw new Error("Failed to send OTP email. Please try again.");

  return { message: "OTP sent to your email" };
}

// ─── Verify OTP ───────────────────────────────────────────────────────────────

async function verifyPasswordResetOtp(email, otp) {
  if (!email || !otp) throw new ValidationError("Email and OTP are required");

  const record = await Otp.findOne({ email: email.toLowerCase(), used: false });
  if (!record) throw new AuthError("OTP not found or already used");
  if (record.expiresAt < new Date()) throw new AuthError("OTP has expired. Please request a new one");

  // Lockout after 5 failed attempts
  if (record.attempts >= 5) {
    record.used = true;
    await record.save();
    throw new AuthError("Too many failed attempts. Request a new OTP.");
  }

  // Compare hashed OTP (never store or compare plaintext)
  const hashedInput = hashOtp(otp);
  if (hashedInput !== record.code) {
    record.attempts += 1;
    // If this attempt is the 5th, also lock it out immediately
    if (record.attempts >= 5) {
      record.used = true;
    }
    await record.save();
    throw new AuthError("Invalid OTP");
  }

  record.used = true;
  await record.save();

  return { message: "OTP verified successfully" };
}

// ─── Find Users By Email (for password reset user selection) ─────────────────

async function findUsersByEmail(email) {
  if (!email) throw new ValidationError("Email is required");

  const users = await User.find({ email: email.toLowerCase() }).lean();
  return users.map((u) => ({
    userId: u.userId,
    schoolId: u.schoolId,
    email: u.email,
    name: u.name,
    role: u.role,
  }));
}

// ─── Reset Password (unauthenticated, after OTP verified) ────────────────────

async function resetPassword(userId, newPassword) {
  if (!userId || !newPassword) throw new ValidationError("User ID and new password are required");
  if (newPassword.length < 8) throw new ValidationError("Password must be at least 8 characters");

  const user = await mongoUserRepo.findByUserId(userId);
  if (!user) throw new NotFoundError("User not found");

  const hashed = await hashPassword(newPassword);

  // MongoDB — clear all sessions + devices + unlock
  await mongoUserRepo.updateByUserId(userId, {
    $set: { password: hashed, refreshTokens: [], devices: [], loginAttempts: 0, lockedUntil: null },
  });

  // Firebase RTDB — sync hashed password
  const fbPath = getFirebasePath(user.role, user.schoolId, userId);
  await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch((e) => {
    console.error(`Firebase password sync failed for ${userId}:`, e.message);
  });

  console.info(`AUTH_AUDIT: PASSWORD_RESET | user=${userId} | type=mobile_otp | firebase_synced=true`);
  return { message: "Password reset successfully. Please log in with your new password." };
}

// ─── Register FCM Token ───────────────────────────────────────────────────────

async function registerFcmToken(userId, fcmToken, deviceId) {
  await mongoUserRepo.setFcmToken(userId, deviceId, fcmToken);
}

module.exports = { loginUser, refreshAccessToken, logoutUser, changePassword, sendPasswordResetOtp, verifyPasswordResetOtp, findUsersByEmail, resetPassword, registerFcmToken };
