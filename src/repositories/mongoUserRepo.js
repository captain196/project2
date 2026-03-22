const User = require("../models/User");

async function create(data) {
  return User.create(data);
}

async function findByUserId(userId) {
  return User.findOne({ userId });
}

async function findByEmail(email) {
  return User.findOne({ email: email.toLowerCase() });
}

async function findByRole(role) {
  return User.find({ role }).sort({ createdAt: -1 });
}

async function findBySchoolId(schoolId) {
  return User.find({ schoolId }).sort({ createdAt: -1 });
}

async function updateByUserId(userId, update) {
  return User.findOneAndUpdate({ userId }, update, { new: true });
}

async function deleteByUserId(userId) {
  return User.deleteOne({ userId });
}

async function addRefreshToken(userId, tokenHash) {
  return User.findOneAndUpdate(
    { userId },
    { $push: { refreshTokens: { tokenHash, createdAt: new Date() } } },
    { new: true }
  );
}

async function removeRefreshToken(userId, tokenHash) {
  return User.findOneAndUpdate(
    { userId },
    { $pull: { refreshTokens: { tokenHash } } },
    { new: true }
  );
}

async function clearRefreshTokens(userId) {
  return User.findOneAndUpdate(
    { userId },
    { $set: { refreshTokens: [] } },
    { new: true }
  );
}

async function setFcmToken(userId, deviceId, fcmToken) {
  return User.findOneAndUpdate(
    { userId, "devices.deviceId": deviceId },
    { $set: { "devices.$.fcmToken": fcmToken } },
    { new: true }
  );
}

module.exports = {
  create,
  findByUserId,
  findByEmail,
  findByRole,
  findBySchoolId,
  updateByUserId,
  deleteByUserId,
  addRefreshToken,
  removeRefreshToken,
  clearRefreshTokens,
  setFcmToken,
};
