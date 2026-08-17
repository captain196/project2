/**
 * FIX TEST SCHOOL LOGIN CODE
 * Repairs loginCode from "3" → "10003" across all 3 databases.
 * Also fixes SCHCODE counter to 10003.
 *
 * Usage: node scripts/fix-test-school-logincode.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const { initFirebase, getFirebaseDb, getFirestore } = require("../src/config/firebase");
const User = require("../src/models/User");
const Counter = require("../src/models/Counter");
const fs = require("fs");
const path = require("path");

initFirebase();
const rtdb = getFirebaseDb();
const firestore = getFirestore();

const SCHOOL_CODE = "SCH0002";
const OLD_LOGIN = "3";
const NEW_LOGIN = "10003";

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  FIX LOGIN CODE: 3 → 10003                                  ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });

  // ═══════════ 1. Fix SCHCODE counter ═══════════
  console.log("1. Fixing SCHCODE counter...");
  await Counter.findOneAndUpdate({ _id: "SCHCODE" }, { $set: { seq: 10003 } }, { upsert: true });
  console.log("   SCHCODE counter → 10003 ✅\n");

  // ═══════════ 2. Fix MongoDB users ═══════════
  console.log("2. Fixing MongoDB users (schoolId '3' → '10003')...");
  const result = await User.updateMany(
    { schoolId: OLD_LOGIN, schoolCode: SCHOOL_CODE },
    { $set: { schoolId: NEW_LOGIN } }
  );
  console.log(`   Updated ${result.modifiedCount} users ✅\n`);

  // Also fix parentDbKey for students
  const stuResult = await User.updateMany(
    { parentDbKey: OLD_LOGIN, schoolCode: SCHOOL_CODE },
    { $set: { parentDbKey: NEW_LOGIN } }
  );
  console.log(`   Fixed parentDbKey for ${stuResult.modifiedCount} students ✅\n`);

  // ═══════════ 3. Fix RTDB — move user paths ═══════════
  console.log("3. Fixing RTDB user paths...");

  // 3a. Users/Teachers/3 → Users/Teachers/10003
  const teachersSnap = await rtdb.ref(`Users/Teachers/${OLD_LOGIN}`).once("value");
  if (teachersSnap.val()) {
    await rtdb.ref(`Users/Teachers/${NEW_LOGIN}`).set(teachersSnap.val());
    await rtdb.ref(`Users/Teachers/${OLD_LOGIN}`).remove();
    console.log(`   Users/Teachers/${OLD_LOGIN} → Users/Teachers/${NEW_LOGIN} (${Object.keys(teachersSnap.val()).length} teachers) ✅`);
  }

  // 3b. Users/Parents/3 → Users/Parents/10003
  const parentsSnap = await rtdb.ref(`Users/Parents/${OLD_LOGIN}`).once("value");
  if (parentsSnap.val()) {
    await rtdb.ref(`Users/Parents/${NEW_LOGIN}`).set(parentsSnap.val());
    await rtdb.ref(`Users/Parents/${OLD_LOGIN}`).remove();
    console.log(`   Users/Parents/${OLD_LOGIN} → Users/Parents/${NEW_LOGIN} (${Object.keys(parentsSnap.val()).length} students) ✅`);
  }

  // 3c. Users/Admin/3 → Users/Admin/10003
  const adminSnap = await rtdb.ref(`Users/Admin/${OLD_LOGIN}`).once("value");
  if (adminSnap.val()) {
    await rtdb.ref(`Users/Admin/${NEW_LOGIN}`).set(adminSnap.val());
    await rtdb.ref(`Users/Admin/${OLD_LOGIN}`).remove();
    console.log(`   Users/Admin/${OLD_LOGIN} → Users/Admin/${NEW_LOGIN} (${Object.keys(adminSnap.val()).length} admins) ✅`);
  }

  // 3d. Fix Indexes/School_codes
  await rtdb.ref(`Indexes/School_codes/${OLD_LOGIN}`).remove();
  await rtdb.ref(`Indexes/School_codes/${NEW_LOGIN}`).set(SCHOOL_CODE);
  console.log(`   Indexes/School_codes/${OLD_LOGIN} → ${NEW_LOGIN} ✅`);

  // 3e. Fix System/Schools/SCH0002/profile/school_code
  await rtdb.ref(`System/Schools/${SCHOOL_CODE}/profile/school_code`).set(NEW_LOGIN);
  console.log(`   System/Schools/${SCHOOL_CODE}/profile/school_code → ${NEW_LOGIN} ✅\n`);

  // ═══════════ 4. Fix Firestore school doc ═══════════
  console.log("4. Fixing Firestore school document...");
  await firestore.collection("schools").doc(SCHOOL_CODE).update({ loginCode: NEW_LOGIN });
  console.log(`   schools/${SCHOOL_CODE}.loginCode → ${NEW_LOGIN} ✅\n`);

  // ═══════════ 5. Fix test-school-ids.json ═══════════
  console.log("5. Fixing test-school-ids.json...");
  const idsPath = path.join(__dirname, "test-school-ids.json");
  const ids = JSON.parse(fs.readFileSync(idsPath, "utf8"));
  ids.school.loginCode = NEW_LOGIN;
  fs.writeFileSync(idsPath, JSON.stringify(ids, null, 2));
  console.log(`   loginCode → ${NEW_LOGIN} ✅\n`);

  // ═══════════ 6. Verify ═══════════
  console.log("═══ VERIFICATION ═══\n");

  // MongoDB
  const mongoCheck = await User.countDocuments({ schoolId: OLD_LOGIN, schoolCode: SCHOOL_CODE });
  console.log(`MongoDB users still with schoolId='${OLD_LOGIN}':`, mongoCheck === 0 ? "0 ✅" : `${mongoCheck} ❌`);

  const mongoNew = await User.countDocuments({ schoolId: NEW_LOGIN, schoolCode: SCHOOL_CODE });
  console.log(`MongoDB users with schoolId='${NEW_LOGIN}':`, mongoNew);

  // RTDB
  const oldTeaCheck = await rtdb.ref(`Users/Teachers/${OLD_LOGIN}`).once("value");
  console.log(`RTDB Users/Teachers/${OLD_LOGIN}:`, oldTeaCheck.val() ? "STILL EXISTS ❌" : "REMOVED ✅");

  const newTeaCheck = await rtdb.ref(`Users/Teachers/${NEW_LOGIN}`).once("value");
  console.log(`RTDB Users/Teachers/${NEW_LOGIN}:`, newTeaCheck.val() ? `${Object.keys(newTeaCheck.val()).length} teachers ✅` : "MISSING ❌");

  const oldParCheck = await rtdb.ref(`Users/Parents/${OLD_LOGIN}`).once("value");
  console.log(`RTDB Users/Parents/${OLD_LOGIN}:`, oldParCheck.val() ? "STILL EXISTS ❌" : "REMOVED ✅");

  const newParCheck = await rtdb.ref(`Users/Parents/${NEW_LOGIN}`).once("value");
  console.log(`RTDB Users/Parents/${NEW_LOGIN}:`, newParCheck.val() ? `${Object.keys(newParCheck.val()).length} students ✅` : "MISSING ❌");

  const indexCheck = await rtdb.ref(`Indexes/School_codes/${NEW_LOGIN}`).once("value");
  console.log(`RTDB Indexes/School_codes/${NEW_LOGIN}:`, indexCheck.val() === SCHOOL_CODE ? `${SCHOOL_CODE} ✅` : `${indexCheck.val()} ❌`);

  // Counter
  const counter = await Counter.findOne({ _id: "SCHCODE" });
  console.log(`SCHCODE counter:`, counter.seq === 10003 ? "10003 ✅" : `${counter.seq} ❌`);

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ✅ LOGIN CODE FIX COMPLETE: 3 → 10003                      ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  await mongoose.disconnect();
  process.exit(0);
}

main().catch(e => { console.error("❌ FAILED:", e.message); console.error(e); process.exit(1); });
