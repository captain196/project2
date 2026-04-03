const { getFirestore } = require("../config/firebase");

/**
 * Canonical Firestore collection name constants.
 * Import these instead of sprinkling string literals across controllers.
 */
const COLLECTIONS = {
  SUBJECT_ASSIGNMENTS: "subjectAssignments",
  ACADEMIC_CALENDAR: "academicCalendar",
  SUBSTITUTES: "substitutes",
  CURRICULUM: "curriculum",
  TIMETABLES: "timetables",
};

/**
 * Get a document by collection and ID.
 * @returns {Object|null} Document data with id, or null if not found.
 */
async function getDoc(collection, docId) {
  const snap = await getFirestore().collection(collection).doc(docId).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

/**
 * Set (create/overwrite) a document.
 * @param {Object} options - { merge: true } for partial updates.
 */
async function setDoc(collection, docId, data, options = {}) {
  await getFirestore().collection(collection).doc(docId).set(data, options);
}

/**
 * Update specific fields on an existing document.
 */
async function updateDoc(collection, docId, data) {
  await getFirestore().collection(collection).doc(docId).update(data);
}

/**
 * Delete a document.
 */
async function deleteDoc(collection, docId) {
  await getFirestore().collection(collection).doc(docId).delete();
}

/**
 * Query documents in a collection.
 * @param {string} collection - Collection name
 * @param {Array} conditions - Array of [field, operator, value] tuples
 * @param {Object} options - { orderBy, limit, startAfter }
 * @returns {Array} Array of { id, ...data }
 */
async function query(collection, conditions = [], options = {}) {
  let ref = getFirestore().collection(collection);

  for (const [field, op, value] of conditions) {
    ref = ref.where(field, op, value);
  }

  if (options.orderBy) {
    const [field, direction] = Array.isArray(options.orderBy)
      ? options.orderBy
      : [options.orderBy, "asc"];
    ref = ref.orderBy(field, direction);
  }

  if (options.limit) {
    ref = ref.limit(options.limit);
  }

  if (options.startAfter) {
    ref = ref.startAfter(options.startAfter);
  }

  const snap = await ref.get();
  return snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
}

/**
 * Batch write — up to 500 operations.
 * @param {Array} operations - [{ type: "set"|"update"|"delete", collection, docId, data, options }]
 */
async function batchWrite(operations) {
  const db = getFirestore();
  const batch = db.batch();

  for (const op of operations) {
    const ref = db.collection(op.collection).doc(op.docId);
    switch (op.type) {
      case "set":
        batch.set(ref, op.data, op.options || {});
        break;
      case "update":
        batch.update(ref, op.data);
        break;
      case "delete":
        batch.delete(ref);
        break;
    }
  }

  await batch.commit();
}

/**
 * Get Firestore server timestamp value.
 */
function serverTimestamp() {
  const admin = require("firebase-admin");
  return admin.firestore.FieldValue.serverTimestamp();
}

/**
 * Map a user role to the correct Firestore hierarchical subcollection path.
 *
 * NEW structure:
 *   users/global/superadmins/{userId}           — Super Admins
 *   users/{schoolId}/schoolsuperadmins/{userId}  — School Super Admins
 *   users/{schoolId}/admins/{userId}             — School Admins
 *   users/{schoolId}/staff/{userId}              — Staff (non-teacher roles)
 *   users/{schoolId}/teachers/{userId}           — Teachers
 *   users/{schoolId}/parents/{userId}            — Parents/Students
 *
 * @param {string} role      e.g. "super_admin", "admin", "teacher", "student"
 * @param {string} schoolId  Firebase school key, e.g. "SCH_9738C22243"
 * @returns {string}         Subcollection path, e.g. "users/SCH_xxx/teachers"
 */
function userCollectionPath(role, schoolId) {
  // Normalize: "School Super Admin" / "school super admin" / "school_super_admin" → "school_super_admin"
  const r = (role || "").toLowerCase().trim().replace(/\s+/g, "_");
  switch (r) {
    case "super_admin":
    case "superadmin":
      return "users/global/superadmins";
    case "school_super_admin":
    case "schoolsuperadmin":
      return `users/${schoolId}/schoolsuperadmins`;
    case "admin":
      return `users/${schoolId}/admins`;
    case "principal":
    case "vice_principal":
    case "academic_coordinator":
    case "hr_manager":
    case "accountant":
    case "front_office":
    case "librarian":
    case "transport_manager":
    case "hostel_warden":
      return `users/${schoolId}/staff`;
    case "teacher":
    case "class_teacher":
      return `users/${schoolId}/teachers`;
    case "staff":
      return `users/${schoolId}/staff`;
    case "student":
      return `users/${schoolId}/students`;
    case "parent":
      return `users/${schoolId}/parents`;
    default:
      return `users/${schoolId}/staff`;
  }
}

/**
 * Return the Firestore subcollection path for sections under a school.
 * e.g. sectionCollectionPath("SCH_xxx") -> "schools/SCH_xxx/sections"
 */
function sectionCollectionPath(schoolId) {
    return `schools/${schoolId}/sections`;
}

/**
 * Return the Firestore subcollection path for students under a school.
 * e.g. studentCollectionPath("SCH_xxx") -> "schools/SCH_xxx/students"
 */
function studentCollectionPath(schoolId) {
    return `schools/${schoolId}/students`;
}

/**
 * Return the Firestore subcollection path for subject assignments under a school.
 * e.g. subjectAssignmentCollectionPath("SCH_xxx") -> "schools/SCH_xxx/subjectAssignments"
 */
function subjectAssignmentCollectionPath(schoolId) {
    return `schools/${schoolId}/subjectAssignments`;
}

/**
 * Return the Firestore subcollection path for timetable settings under a school.
 * e.g. timetableSettingsCollectionPath("SCH_xxx") -> "schools/SCH_xxx/timetableSettings"
 */
function timetableSettingsCollectionPath(schoolId) {
    return `schools/${schoolId}/timetableSettings`;
}

function timetableCollectionPath(schoolId) {
    return `schools/${schoolId}/timetables`;
}

function curriculumCollectionPath(schoolId) {
    return `schools/${schoolId}/curriculum`;
}

function academicCalendarCollectionPath(schoolId) {
    return `schools/${schoolId}/academicCalendar`;
}

function substituteCollectionPath(schoolId) {
    return `schools/${schoolId}/substitutes`;
}

module.exports = { COLLECTIONS, getDoc, setDoc, updateDoc, deleteDoc, query, batchWrite, serverTimestamp, userCollectionPath, sectionCollectionPath, studentCollectionPath, subjectAssignmentCollectionPath, timetableSettingsCollectionPath, timetableCollectionPath, curriculumCollectionPath, academicCalendarCollectionPath, substituteCollectionPath };
