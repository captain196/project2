const { generateIdForRole, generateId } = require("./idGenerator");
const mongoUserRepo = require("../repositories/mongoUserRepo");
const firebaseUserRepo = require("../repositories/firebaseUserRepo");
const { hashPassword, generateRandomPassword } = require("../utils/hash");
const {
  ConflictError,
  ValidationError,
  AppError,
  NotFoundError,
  ForbiddenError,
} = require("../utils/errors");

// ─── Constants ────────────────────────────────────────────────────────────────

const ROLE_DISPLAY = {
  super_admin: "Super Admin",
  school_super_admin: "School Super Admin",
  admin: "Admin",
  teacher: "Teacher",
  student: "Student",
};

const CAN_CREATE = {
  super_admin: ["super_admin", "school_super_admin", "admin", "teacher", "student"],
  school_super_admin: ["admin", "teacher", "student"],
  admin: ["teacher", "student"],
  teacher: [],
  student: [],
};

const MAX_REFRESH_TOKENS = { super_admin: 3, school_super_admin: 2, admin: 2, teacher: 2, student: 2 };

// ─── Firebase path helpers ────────────────────────────────────────────────────

/**
 * Validate that a segment is safe for Firebase path construction.
 * Prevents path traversal (../, /, .) and injection attacks.
 */
function _safeFbSegment(segment) {
  if (!segment || typeof segment !== "string") return "unknown";
  // Strip any characters that could enable path traversal or injection
  return segment.replace(/[\/\.\#\$\[\]]/g, "_");
}

function getFirebasePath(role, schoolId, userId) {
  const safeSchool = _safeFbSegment(schoolId);
  const safeUser = _safeFbSegment(userId);
  if (role === "super_admin") return `Users/Admin/Our Panel/${safeUser}`;
  if (role === "teacher") return `Users/Teachers/${safeSchool}/${safeUser}`;
  if (role === "student") return `Users/Parents/${safeSchool}/${safeUser}`;
  return `Users/Admin/${safeSchool}/${safeUser}`;
}

function buildFirebaseProfile(data) {
  const ts = new Date(data.createdAt)
    .toISOString()
    .replace("T", " ")
    .substring(0, 19);

  return {
    Status: data.status,
    Name: data.name,
    Email: data.email || null,
    Credentials: {
      Id: data.userId,
      Password: data.password, // bcrypt hash
    },
    Profile: {
      name: data.name,
      email: data.email || null,
      phone: data.phone || null,
      role: data.role,
      created_at: ts,
      created_by: data.createdBy,
    },
    AccessHistory: {
      SA_LastLogin: null,
      SA_LastLoginIP: null,
      LoginAttempts: 0,
    },
    Privileges: { accountmanagement: "" },
    Role: ROLE_DISPLAY[data.role] || data.role,
    ...(data.isPrimary ? { is_primary: true } : {}),
  };
}

// ─── Create User (dual-write with rollback) ───────────────────────────────────

async function createUser({ name, email, phone, password, role, schoolId, createdBy }) {
  // Permission check
  const creator = await mongoUserRepo.findByUserId(createdBy);
  if (!creator) throw new ForbiddenError("Creator not found");

  const allowed = CAN_CREATE[creator.role] || [];
  if (!allowed.includes(role)) {
    throw new ForbiddenError(`${creator.role} cannot create ${role}`);
  }

  // Validate
  if (!name || !password) {
    throw new ValidationError("Name and password are required");
  }
  if (password.length < 8) {
    throw new ValidationError("Password must be at least 8 characters");
  }
  if (role !== "super_admin" && !schoolId) {
    throw new ValidationError("schoolId is required for school_super_admin/admin roles");
  }

  // Email uniqueness
  if (email) {
    const existing = await mongoUserRepo.findByEmail(email);
    if (existing) throw new ConflictError("Email already in use");
  }

  // Generate ID
  const userId = await generateIdForRole(role);
  const hashedPassword = await hashPassword(password);
  const now = new Date();

  const mongoData = {
    userId,
    password: hashedPassword,
    email: email ? email.toLowerCase() : null,
    name,
    phone: phone || null,
    role,
    schoolId: role === "super_admin" ? null : schoolId,
    createdAt: now,
    createdBy,
    status: "Active",
    refreshTokens: [],
  };

  // Step 1: MongoDB first
  let mongoDoc;
  try {
    mongoDoc = await mongoUserRepo.create(mongoData);
  } catch (err) {
    if (err.code === 11000) throw new ConflictError("Duplicate userId or email");
    throw err;
  }

  // Step 1b: Strip irrelevant fields for this role
  await mongoUserRepo.unsetIrrelevantFields(userId, role);

  // Step 2: Firebase
  const fbPath = getFirebasePath(role, schoolId, userId);
  const fbData = buildFirebaseProfile({ ...mongoData, createdAt: now });
  try {
    await firebaseUserRepo.set(fbPath, fbData);
  } catch (err) {
    // Rollback MongoDB
    await mongoUserRepo.deleteByUserId(userId);
    throw new AppError("Firebase write failed — rolled back. " + err.message);
  }

  return { userId, name, email: mongoData.email, role, schoolId: mongoData.schoolId, status: "Active" };
}

// ─── Seed SUP0001 on first boot ───────────────────────────────────────────────

async function seedPrimarySuperAdmin() {
  // Check if any super_admin exists
  const existing = await mongoUserRepo.findByRole("super_admin");
  if (existing.length > 0) return; // Already seeded

  const rawPassword = process.env.SUPER_ADMIN_PASSWORD || generateRandomPassword();
  const hashedPassword = await hashPassword(rawPassword);
  const userId = await generateIdForRole("super_admin"); // SUP0001
  const now = new Date();

  const mongoData = {
    userId,
    password: hashedPassword,
    email: "yugant196@gmail.com",
    name: "Yugant Verma",
    phone: "+919131879380",
    role: "super_admin",
    schoolId: null,
    createdAt: now,
    createdBy: "system",
    status: "Active",
    refreshTokens: [],
  };

  await mongoUserRepo.create(mongoData);

  // Strip irrelevant fields for super_admin
  await mongoUserRepo.unsetIrrelevantFields(userId, "super_admin");

  const fbData = buildFirebaseProfile({ ...mongoData, createdAt: now, isPrimary: true });
  await firebaseUserRepo.set(`Users/Admin/Our Panel/${userId}`, fbData);

  console.log("========================================");
  console.log("🔐 PRIMARY SUPER ADMIN CREATED");
  console.log(`   User ID:  ${userId}`);
  console.log(`   Name:     ${mongoData.name}`);
  console.log(`   Email:    ${mongoData.email}`);
  console.log(`   Phone:    ${mongoData.phone}`);
  console.log(`   Role:     ${mongoData.role}`);
  console.log(`   Password: ${rawPassword}`);
  console.log(`   Status:   ${mongoData.status}`);
  console.log(`   Created:  ${now.toISOString()}`);
  console.log("   ─────────────────────────────────");
  console.log(`   ✅ Firebase: Users/Admin/Our Panel/${userId}`);
  console.log(`   ✅ MongoDB:  graderIQ.users`);
  console.log("   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!");
  console.log("========================================");
}

// ─── Update Profile ───────────────────────────────────────────────────────────

async function updateUserProfile(userId, { name, email, phone }) {
  const user = await mongoUserRepo.findByUserId(userId);
  if (!user) throw new NotFoundError("User not found");

  if (email && email.toLowerCase() !== user.email) {
    const dup = await mongoUserRepo.findByEmail(email);
    if (dup) throw new ConflictError("Email already in use");
  }

  const updates = {};
  if (name) updates.name = name;
  if (email !== undefined) updates.email = email ? email.toLowerCase() : null;
  if (phone !== undefined) updates.phone = phone || null;

  // MongoDB
  const updated = await mongoUserRepo.updateByUserId(userId, { $set: updates });

  // Firebase
  const fbPath = getFirebasePath(user.role, user.schoolId, userId);
  const fbUpdates = {};
  if (name) {
    fbUpdates.Name = name;
    fbUpdates["Profile/name"] = name;
  }
  if (email !== undefined) {
    fbUpdates.Email = updates.email;
    fbUpdates["Profile/email"] = updates.email;
  }
  if (phone !== undefined) {
    fbUpdates["Profile/phone"] = updates.phone;
  }
  await firebaseUserRepo.update(fbPath, fbUpdates);

  return {
    userId: updated.userId,
    name: updated.name,
    email: updated.email,
    phone: updated.phone,
    role: updated.role,
    schoolId: updated.schoolId,
    status: updated.status,
  };
}

// ─── Delete User ──────────────────────────────────────────────────────────────

async function deleteUser(userId, actorId) {
  const user = await mongoUserRepo.findByUserId(userId);
  if (!user) throw new NotFoundError("User not found");

  if (user.role === "super_admin") {
    const fbData = await firebaseUserRepo.get(`Users/Admin/Our Panel/${userId}`);
    if (fbData && fbData.is_primary) {
      throw new ForbiddenError("Primary super admin cannot be deleted");
    }
  }

  if (userId === actorId) {
    throw new ForbiddenError("Cannot delete your own account");
  }

  const fbPath = getFirebasePath(user.role, user.schoolId, userId);
  await firebaseUserRepo.remove(fbPath);
  await mongoUserRepo.deleteByUserId(userId);

  return { message: `User ${userId} deleted` };
}

// ─── List Users ───────────────────────────────────────────────────────────────

async function listUsers({ role, schoolId }) {
  let users;
  if (schoolId) {
    users = await mongoUserRepo.findBySchoolId(schoolId);
  } else if (role) {
    users = await mongoUserRepo.findByRole(role);
  } else {
    users = [];
  }

  return users.map((u) => ({
    userId: u.userId,
    name: u.name,
    email: u.email,
    phone: u.phone,
    role: u.role,
    schoolId: u.schoolId,
    status: u.status,
    createdAt: u.createdAt,
    createdBy: u.createdBy,
  }));
}

module.exports = {
  createUser,
  seedPrimarySuperAdmin,
  updateUserProfile,
  deleteUser,
  listUsers,
  getFirebasePath,
  buildFirebaseProfile,
  MAX_REFRESH_TOKENS,
  CAN_CREATE,
  ROLE_DISPLAY,
};
