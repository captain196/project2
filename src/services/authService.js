const mongoUserRepo = require("../repositories/mongoUserRepo");
const firebaseUserRepo = require("../repositories/firebaseUserRepo");
const { comparePassword, hashPassword, hashToken } = require("../utils/hash");
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../utils/token");
const { AuthError, ValidationError, NotFoundError } = require("../utils/errors");
const { getFirebasePath, MAX_REFRESH_TOKENS } = require("./userService");

// Roles that require device binding for mobile login
const DEVICE_BOUND_ROLES = ["teacher", "student"];

// ─── Login (email + password) ─────────────────────────────────────────────────
// deviceId is optional — when provided (mobile app), device binding is enforced
// for teacher/student roles.

async function loginUser(email, password, deviceId) {
  if (!email || !password) throw new ValidationError("Email and password are required");

  const user = await mongoUserRepo.findByEmail(email);
  if (!user) throw new AuthError("Invalid email or password");
  if (user.status !== "Active") throw new AuthError("Account is inactive");

  const valid = await comparePassword(password, user.password);
  if (!valid) throw new AuthError("Invalid email or password");

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

  return {
    accessToken,
    refreshToken,
    user: {
      userId: user.userId,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      schoolId: user.schoolId,
      status: user.status,
    },
    firebaseProfile,
  };
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

  const user = await mongoUserRepo.findByUserId(decoded.userId);
  if (!user || user.status !== "Active") throw new AuthError("User not found or inactive");

  const tokenHash = hashToken(refreshToken);
  const tokenExists = user.refreshTokens.some((t) => t.tokenHash === tokenHash);
  if (!tokenExists) throw new AuthError("Refresh token revoked");

  // Rotate tokens
  await mongoUserRepo.removeRefreshToken(user.userId, tokenHash);

  const payload = { userId: user.userId, role: user.role, schoolId: user.schoolId };
  const newAccessToken = signAccessToken(payload);
  const newRefreshToken = signRefreshToken(payload);
  await mongoUserRepo.addRefreshToken(user.userId, hashToken(newRefreshToken));

  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
}

// ─── Logout ───────────────────────────────────────────────────────────────────

async function logoutUser(userId, refreshToken) {
  if (refreshToken) {
    await mongoUserRepo.removeRefreshToken(userId, hashToken(refreshToken));
  } else {
    await mongoUserRepo.clearRefreshTokens(userId);
  }
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

  // MongoDB — also clears all sessions
  await mongoUserRepo.updateByUserId(userId, { $set: { password: hashed, refreshTokens: [] } });

  // Firebase
  const fbPath = getFirebasePath(user.role, user.schoolId, userId);
  await firebaseUserRepo.update(fbPath, { "Credentials/Password": hashed }).catch(() => {});

  return { message: "Password changed. All sessions invalidated." };
}

module.exports = { loginUser, refreshAccessToken, logoutUser, changePassword };
