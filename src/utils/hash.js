const bcrypt = require("bcrypt");
const crypto = require("crypto");

const SALT_ROUNDS = 12;

/**
 * Hash a password using bcrypt with $2b$ prefix (Node.js standard).
 * Always produces consistent $2b$ hashes.
 */
async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

/**
 * Compare password against a bcrypt hash.
 * Handles all bcrypt prefixes: $2a$, $2b$, $2y$ (from PHP/other systems).
 * Normalizes $2y$ (PHP) → $2b$ (Node) before comparison so cross-system hashes work.
 */
async function comparePassword(plain, hashed) {
  if (!hashed || typeof hashed !== "string") return false;

  // If it's not a bcrypt hash at all (legacy plaintext or corrupt), direct compare
  if (!hashed.startsWith("$2")) {
    return plain === hashed;
  }

  // Normalize $2y$ (PHP bcrypt) → $2b$ (Node bcrypt) — they are identical algorithms
  let normalized = hashed;
  if (hashed.startsWith("$2y$")) {
    normalized = "$2b$" + hashed.slice(4);
  }

  return bcrypt.compare(plain, normalized);
}

/**
 * Check if a string is a valid bcrypt hash (any variant).
 */
function isBcryptHash(str) {
  return typeof str === "string" && /^\$2[aby]\$\d{2}\$.{53}$/.test(str);
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

module.exports = { hashPassword, comparePassword, hashToken, generateRandomPassword, isBcryptHash };
