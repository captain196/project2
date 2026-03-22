const { generateId } = require("./idGenerator");
const firebaseUserRepo = require("../repositories/firebaseUserRepo");
const { ValidationError, ForbiddenError, AppError } = require("../utils/errors");
const mongoUserRepo = require("../repositories/mongoUserRepo");

/**
 * Create a new school.
 * Writes to Firebase in the same structure the PHP panel expects:
 *   System/Schools/{schoolId}/profile
 *   System/Schools/{schoolId}/subscription
 *   System/Schools/{schoolId}/stats_cache
 *   System/Schools/{schoolId} (top-level status)
 *
 * Only super_admin can create schools.
 */
async function createSchool({ schoolName, city, email, phone, createdBy }) {
  const actor = await mongoUserRepo.findByUserId(createdBy);
  if (!actor || actor.role !== "super_admin") {
    throw new ForbiddenError("Only super admins can create schools");
  }

  if (!schoolName) throw new ValidationError("schoolName is required");

  const schoolId = await generateId("SCH");
  const now = new Date().toISOString().replace("T", " ").substring(0, 19);
  const domainId = schoolName.toLowerCase().replace(/[^a-z0-9]/g, "");

  const basePath = `System/Schools/${schoolId}`;

  try {
    // 1. Profile (canonical school data)
    await firebaseUserRepo.set(`${basePath}/profile`, {
      school_name: schoolName,
      name: schoolName,
      school_id: schoolId,
      school_code: "",
      city: city || "",
      street: "",
      email: email || "",
      phone: phone || "",
      logo_url: "",
      domain_identifier: domainId,
      firebase_key: schoolId,
      status: "active",
      created_at: now,
      created_by: createdBy,
    });

    // 2. Subscription
    await firebaseUserRepo.set(`${basePath}/subscription`, {
      status: "Active",
      plan_id: "trial",
      plan_name: "Trial",
      expiry_date: "",
      grace_end: "",
      duration: { startDate: now.substring(0, 10), endDate: "" },
      features: [],
      modules: {},
    });

    // 3. Top-level status + identifiers + stats_cache
    await firebaseUserRepo.update(basePath, {
      status: "active",
      school_id: schoolId,
      "School Id": "",
      stats_cache: {
        total_students: 0,
        total_staff: 0,
        last_updated: now,
      },
    });
  } catch (err) {
    // Rollback on failure
    await firebaseUserRepo.remove(basePath).catch(() => {});
    throw new AppError("Failed to create school in Firebase: " + err.message);
  }

  return { schoolId, name: schoolName, status: "active", createdAt: now };
}

module.exports = { createSchool };
