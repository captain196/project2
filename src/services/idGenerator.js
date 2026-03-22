const { getNextSequence } = require("../repositories/counterRepo");

/**
 * All role/entity → ID prefix mappings.
 * Every ID is globally unique and sequential via atomic MongoDB counter.
 */
const ROLE_PREFIX = {
  super_admin: "SUP",
  school_super_admin: "SSA",
  admin: "ADM",
  student: "STU",
  teacher: "TEA",
};

/**
 * All entity prefixes (including non-user entities).
 */
const ALL_PREFIXES = {
  ...ROLE_PREFIX,
  school: "SCH",
  school_code: "SCHCODE",
};

/**
 * Generate a universal sequential ID.
 * Format: PREFIX + zero-padded 4 digits.
 * Examples: SUP0001, SSA0001, ADM0001, STU0001, TEA0001, SCH0001
 *
 * Uses atomic MongoDB $inc — safe under concurrent requests.
 * No duplicate IDs possible across any school.
 *
 * @param {string} prefix - "SUP", "SSA", "ADM", "STU", "TEA", "SCH"
 * @returns {Promise<string>}
 */
async function generateId(prefix) {
  const seq = await getNextSequence(prefix);
  return `${prefix}${String(seq).padStart(4, "0")}`;
}

/**
 * Generate ID from role name.
 * @param {string} role - "super_admin", "school_super_admin", "admin", "student", "teacher"
 */
async function generateIdForRole(role) {
  const prefix = ROLE_PREFIX[role];
  if (!prefix) throw new Error(`Unknown role: ${role}`);
  return generateId(prefix);
}

module.exports = { generateId, generateIdForRole, ROLE_PREFIX, ALL_PREFIXES };
