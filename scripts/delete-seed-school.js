/**
 * DELETE SEED SCHOOL: SCH_SCHOOL01 (login code 10001)
 * Removes all 21 users + school data from MongoDB, Firebase RTDB, and Firestore.
 *
 * Usage: node scripts/delete-seed-school.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const { initFirebase, getFirebaseDb, getFirestore } = require("../src/config/firebase");
const User = require("../src/models/User");
const Otp = require("../src/models/Otp");

const SCHOOL_CODE = "SCH_SCHOOL01";
const SCHOOL_ID = "10001"; // login code

initFirebase();
const rtdb = getFirebaseDb();
const fs = getFirestore();

async function main() {
  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("Connected to MongoDB\n");

  // ── 1. Find all users belonging to SCH_SCHOOL01 ──
  const users = await User.find({ schoolCode: SCHOOL_CODE }).lean();
  console.log(`Found ${users.length} users with schoolCode=${SCHOOL_CODE}\n`);

  if (!users.length) {
    console.log("No users to delete. Skipping to school data cleanup...");
  }

  // ── 2. Delete each user from Firebase RTDB ──
  console.log("── Deleting users from Firebase RTDB ──");
  for (const u of users) {
    let fbPath;
    if (u.role === "super_admin") {
      fbPath = `Users/Admin/Our Panel/${u.userId}`;
    } else if (u.role === "teacher") {
      fbPath = `Users/Teachers/${SCHOOL_ID}/${u.userId}`;
    } else if (u.role === "student") {
      fbPath = `Users/Parents/${SCHOOL_ID}/${u.userId}`;
    } else {
      // admin, school_super_admin, staff
      fbPath = `Users/Admin/${SCHOOL_ID}/${u.userId}`;
    }

    try {
      await rtdb.ref(fbPath).remove();
      console.log(`  RTDB deleted: ${fbPath} (${u.userId} - ${u.name})`);
    } catch (e) {
      console.log(`  RTDB skip: ${fbPath} - ${e.message}`);
    }

    // Also delete Presence and NotifBadge nodes
    await rtdb.ref(`Presence/${u.userId}`).remove().catch(() => {});
    await rtdb.ref(`NotifBadge/${u.userId}`).remove().catch(() => {});
  }

  // ── 3. Delete each user from Firestore ──
  console.log("\n── Deleting users from Firestore ──");
  for (const u of users) {
    // users collection
    try {
      await fs.collection("users").doc(u.userId).delete();
      console.log(`  Firestore users/${u.userId} deleted`);
    } catch (e) {
      console.log(`  Firestore users/${u.userId} skip: ${e.message}`);
    }

    // staff collection (admin/teacher roles)
    if (["admin", "school_super_admin", "teacher"].includes(u.role)) {
      try {
        await fs.collection("staff").doc(u.userId).delete();
        console.log(`  Firestore staff/${u.userId} deleted`);
      } catch (e) {
        console.log(`  Firestore staff/${u.userId} skip: ${e.message}`);
      }
    }

    // students collection
    if (u.role === "student") {
      try {
        await fs.collection("students").doc(u.userId).delete();
        console.log(`  Firestore students/${u.userId} deleted`);
      } catch (e) {
        console.log(`  Firestore students/${u.userId} skip: ${e.message}`);
      }
    }
  }

  // ── 4. Delete users from MongoDB ──
  console.log("\n── Deleting users from MongoDB ──");
  const userIds = users.map(u => u.userId);
  const delResult = await User.deleteMany({ schoolCode: SCHOOL_CODE });
  console.log(`  Deleted ${delResult.deletedCount} user documents`);

  // Delete any OTPs for these users
  const otpResult = await Otp.deleteMany({ userId: { $in: userIds } });
  console.log(`  Deleted ${otpResult.deletedCount} OTP documents`);

  // ── 5. Delete school data from Firebase RTDB ──
  console.log("\n── Deleting school data from Firebase RTDB ──");

  const rtdbPaths = [
    `System/Schools/${SCHOOL_CODE}`,
    `Schools/${SCHOOL_CODE}`,
  ];

  for (const path of rtdbPaths) {
    try {
      const snap = await rtdb.ref(path).once("value");
      if (snap.exists()) {
        await rtdb.ref(path).remove();
        console.log(`  RTDB deleted: ${path}`);
      } else {
        console.log(`  RTDB not found: ${path}`);
      }
    } catch (e) {
      console.log(`  RTDB error: ${path} - ${e.message}`);
    }
  }

  // Check if Users/Admin/10001, Users/Teachers/10001, Users/Parents/10001
  // still have data (from the real school SCH_964210072F)
  console.log("\n── Checking shared RTDB paths (login code 10001) ──");
  for (const prefix of ["Users/Admin", "Users/Teachers", "Users/Parents"]) {
    const snap = await rtdb.ref(`${prefix}/${SCHOOL_ID}`).once("value");
    const children = snap.exists() ? Object.keys(snap.val() || {}) : [];
    if (children.length > 0) {
      console.log(`  ${prefix}/${SCHOOL_ID}: ${children.length} remaining nodes → ${children.join(", ")}`);
    } else {
      console.log(`  ${prefix}/${SCHOOL_ID}: empty (clean)`);
    }
  }

  // ── 6. Delete school from Firestore ──
  console.log("\n── Deleting school from Firestore ──");
  try {
    await fs.collection("schools").doc(SCHOOL_CODE).delete();
    console.log(`  Firestore schools/${SCHOOL_CODE} deleted`);
  } catch (e) {
    console.log(`  Firestore schools/${SCHOOL_CODE} skip: ${e.message}`);
  }

  // ── 7. Verify MongoDB is clean ──
  console.log("\n── Verification ──");
  const remaining = await User.countDocuments({ schoolCode: SCHOOL_CODE });
  console.log(`  MongoDB users with schoolCode=${SCHOOL_CODE}: ${remaining}`);

  const school10001 = await User.find({ schoolId: SCHOOL_ID }).select("userId name role schoolCode").lean();
  console.log(`  MongoDB users with schoolId=${SCHOOL_ID}: ${school10001.length}`);
  school10001.forEach(u => console.log(`    ${u.userId} | ${u.role.padEnd(20)} | ${u.schoolCode} | ${u.name}`));

  await mongoose.disconnect();
  console.log("\nDone. SCH_SCHOOL01 completely removed.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
