const authService = require("../services/authService");

async function login(req, res, next) {
  try {
    const { email, password, deviceId } = req.body;
    const result = await authService.loginUser(email, password, deviceId);

    res.json({
      success: true,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
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
    const { refreshToken } = req.body;
    const result = await authService.logoutUser(req.user.userId, refreshToken);

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

module.exports = { login, refresh, logout, changePassword };
