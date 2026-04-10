const { getNextSequence } = require("../repositories/counterRepo");

/**
 * All role/entity → ID prefix mappings.
 * Every ID is globally unique and sequential via atomic MongoDB counter.
 *
 * Prefix standard (universal):
 *   SUP — Super Admin (platform-level)
 *   SSA — School Super Admin
 *   STA — All school staff (admin, principal, VP, coordinators, HR, accountant,
 *          front office, librarian, transport, hostel warden, generic staff)
 *   TEA — Teachers & Class Teachers
 *   STU — Students
 */
const ROLE_PREFIX = {
  super_admin: "SUP",
  school_super_admin: "SSA",
  admin: "STA",
  principal: "STA",
  vice_principal: "STA",
  academic_coordinator: "STA",
  hr_manager: "STA",
  accountant: "STA",
  front_office: "STA",
  librarian: "STA",
  transport_manager: "STA",
  hostel_warden: "STA",
  staff: "STA",
  teacher: "TEA",
  class_teacher: "TEA",
  student: "STU",
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
 * Examples: SUP0001, SSA0001, STA0001, STU0001, TEA0001, SCH0001
 *
 * Uses atomic MongoDB $inc — safe under concurrent requests.
 * No duplicate IDs possible across any school.
 *
 * @param {string} prefix - "SUP", "SSA", "STA", "STU", "TEA", "SCH"
 * @returns {Promise<string>}
 */
async function generateId(prefix) {
  const seq = await getNextSequence(prefix);
  return `${prefix}${String(seq).padStart(4, "0")}`;
}

/**
 * Generate ID from role name.
 * @param {string} role - Any role from User model enum (maps to SUP/SSA/STA/TEA/STU prefix)
 */
async function generateIdForRole(role) {
  const prefix = ROLE_PREFIX[role];
  if (!prefix) throw new Error(`Unknown role: ${role}`);
  return generateId(prefix);
}

module.exports = { generateId, generateIdForRole, ROLE_PREFIX, ALL_PREFIXES };
