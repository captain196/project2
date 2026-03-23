const authService = require("../services/authService");

async function login(req, res, next) {
  try {
    const { userId, password, deviceId } = req.body;
    const result = await authService.loginUser(userId, password, deviceId);

    res.json({
      success: true,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      firebaseToken: result.firebaseToken,
      user: result.user,
    });
  } catch (err) {
    next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const { refreshToken } = req.body;
    const tokens = await authService.refreshAccessToken(refreshToken);

    res.json({ success: true, ...tokens });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    const { refreshToken, deviceId } = req.body;
    const result = await authService.logoutUser(req.user.userId, refreshToken, deviceId);

    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
}

async function changePassword(req, res, next) {
  try {
    const { currentPassword, newPassword } = req.body;
    const result = await authService.changePassword(
      req.user.userId,
      currentPassword,
      newPassword
    );

    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
}

async function sendOtp(req, res, next) {
  try {
    const { email } = req.body;
    const result = await authService.sendPasswordResetOtp(email);
    res.json({ success: true, message: result.message });
  } catch (err) {
    next(err);
  }
}

async function verifyOtp(req, res, next) {
  try {
    const { email, otp } = req.body;
    const result = await authService.verifyPasswordResetOtp(email, otp);
    res.json({ success: true, message: result.message });
  } catch (err) {
    next(err);
  }
}

async function findByEmail(req, res, next) {
  try {
    const { email } = req.body;
    const result = await authService.findUsersByEmail(email);
    res.json({ success: true, count: result.length, users: result });
  } catch (err) {
    next(err);
  }
}

async function resetPassword(req, res, next) {
  try {
    const { userId, newPassword } = req.body;
    const result = await authService.resetPassword(userId, newPassword);
    res.json({ success: true, message: result.message });
  } catch (err) {
    next(err);
  }
}

async function registerFcm(req, res, next) {
  try {
    const { fcmToken, deviceId } = req.body;
    if (!fcmToken || !deviceId) {
      return res.status(400).json({ success: false, message: "fcmToken and deviceId required" });
    }
    await authService.registerFcmToken(req.user.userId, fcmToken, deviceId);
    res.json({ success: true, message: "FCM token registered" });
  } catch (err) {
    next(err);
  }
}

module.exports = { login, refresh, logout, changePassword, sendOtp, verifyOtp, findByEmail, resetPassword, registerFcm };
