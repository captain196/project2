const bcrypt = require("bcrypt");
const crypto = require("crypto");

const SALT_ROUNDS = 12;

async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

async function comparePassword(plain, hashed) {
  return bcrypt.compare(plain, hashed);
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function generateRandomPassword(length = 12) {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghjkmnpqrstuvwxyz";
  const digits = "23456789";
  const all = upper + lower + digits;

  // Guarantee at least one of each category
  let password = "";
  password += upper[crypto.randomInt(upper.length)];
  password += lower[crypto.randomInt(lower.length)];
  password += digits[crypto.randomInt(digits.length)];

  for (let i = 3; i < length; i++) {
    password += all[crypto.randomInt(all.length)];
  }

  // Shuffle
  return password
    .split("")
    .sort(() => crypto.randomInt(3) - 1)
    .join("");
}

module.exports = { hashPassword, comparePassword, hashToken, generateRandomPassword };
