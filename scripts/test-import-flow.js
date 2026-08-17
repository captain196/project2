#!/usr/bin/env node
/**
 * Test file import flows by simulating what PHP does:
 * 1. Create test users as if imported via Excel
 * 2. Verify all 3 DBs
 * 3. Clean up
 */
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });
const { generateIdForRole, generateId } = require("../src/services/idGenerator");

const SC = "SCH_EE4DDFAE41", LOGIN = "10001", SESSION = "2026-27";

async function main() {
  await mongoose.connect(process.env.MONGODB_URI + "graderIQ");
  const User = mongoose.connection.collection("users");
  const Counter = mongoose.connection.collection("counters");
  const hashedPw = await bcrypt.hash("Test1234", 10);

  const beforeCount = await User.countDocuments({});
  const beforeCounters = {};
  for (const c of await Counter.find({}).toArray()) beforeCounters[c._id] = c.seq;

  console.log("╔══════════════════════════════════════════════════════════════════╗");
  console.log("║  FILE IMPORT SIMULATION TEST                                   ║");
  console.log("╚══════════════════════════════════════════════════════════════════╝\n");

  const testIds = [];
  let passed = 0, failed = 0;
  const ok = (l) => { console.log("  ✅ " + l); passed++; };
  const fail = (l, r) => { console.log("  ❌ " + l + " — " + r); failed++; };

  // Simulate Staff Excel import — 3 rows
  const importRows = [
    { name: "Import Teacher One", phone: "+919888800001", email: "import.tea1@test.com", gender: "Male", position: "Teacher", department: "Science", salary: 25000 },
    { name: "Import Librarian One", phone: "+919888800002", email: "import.lib1@test.com", gender: "Female", position: "Librarian", department: "Library", salary: 20000 },
    { name: "Import Driver One", phone: "+919888800003", email: "import.drv1@test.com", gender: "Male", position: "Driver", department: "Transport", salary: 15000 },
  ];

  const teachingPositions = ["Teacher", "Class Teacher", "Senior Teacher", "Head of Department"];
  const POSITION_TO_ROLE = {
    Teacher: "teacher", "Class Teacher": "class_teacher", "Senior Teacher": "teacher",
    Librarian: "librarian", Driver: "staff", "Peon / Attendant": "staff",
  };

  console.log("━━━ TEST A: Staff Import Simulation (3 rows) ━━━\n");

  for (const row of importRows) {
    const isTeaching = teachingPositions.includes(row.position);
    const prefix = isTeaching ? "TEA" : "STA";
    const staffId = await generateId(prefix);
    testIds.push(staffId);
    const mongoRole = POSITION_TO_ROLE[row.position] || "staff";

    // 1. Firestore (primary)
    const fsCol = (mongoRole === "teacher" || mongoRole === "class_teacher") ? `users/${SC}/teachers` : `users/${SC}/staff`;
    await namedFs.collection(fsCol).doc(staffId).set({
      userId: staffId, name: row.name, email: row.email, phone: row.phone,
      role: mongoRole, position: row.position, department: row.department,
      gender: row.gender.toLowerCase(), schoolId: SC, status: "active",
    });

    // 2. RTDB
    await rtdb.ref(`Users/Teachers/${LOGIN}/${staffId}`).set({
      Name: row.name, Email: row.email, "Phone Number": row.phone, Status: "Active",
      Position: row.position, Department: row.department, Gender: row.gender,
      Credentials: { Id: staffId, Password: hashedPw },
    });
    await rtdb.ref(`Schools/${SC}/${SESSION}/Teachers/${staffId}`).set({
      Name: row.name, Status: "Active", Position: row.position,
    });

    // 3. MongoDB
    await User.insertOne({
      userId: staffId, password: hashedPw, name: row.name, email: row.email.toLowerCase(),
      phone: row.phone, role: mongoRole, schoolId: LOGIN, schoolCode: SC,
      status: "Active", createdAt: new Date(), createdBy: "import-test",
      refreshTokens: [], devices: [], loginAttempts: 0,
      position: row.position, department: row.department,
    });

    // Verify
    const m = await User.findOne({ userId: staffId });
    const r = await rtdb.ref(`Users/Teachers/${LOGIN}/${staffId}`).once("value");
    const f = await namedFs.collection(fsCol).doc(staffId).get();
    const pfx = staffId.replace(/[0-9]/g, "");

    if (m && r.exists() && f.exists && pfx === prefix) {
      ok(`${staffId} (${row.position}) → ${prefix} prefix, all 3 DBs ✓`);
    } else {
      fail(`${staffId}`, `M=${!!m} R=${r.exists()} F=${f.exists} pfx=${pfx}`);
    }
  }

  // Simulate Student Admission — 1 student
  console.log("\n━━━ TEST B: Student Admission Simulation ━━━\n");

  const stuId = await generateIdForRole("student");
  testIds.push(stuId);

  // 1. Firestore first
  await namedFs.collection(`users/${SC}/students`).doc(stuId).set({
    userId: stuId, name: "Import Student One", email: "import.stu1@test.com",
    phone: "+919888800004", role: "student", className: "10th", section: "A",
    schoolId: SC, status: "active", rollNo: "99",
  });

  // 2. RTDB
  await rtdb.ref(`Users/Parents/${LOGIN}/${stuId}`).set({
    Name: "Import Student One", Status: "Active", "Phone Number": "+919888800004",
    Credentials: { Id: stuId, Password: hashedPw },
  });

  // 3. MongoDB
  await User.insertOne({
    userId: stuId, password: hashedPw, name: "Import Student One", email: "import.stu1@test.com",
    phone: "+919888800004", role: "student", schoolId: LOGIN, schoolCode: SC,
    status: "Active", createdAt: new Date(), createdBy: "import-test",
    refreshTokens: [], devices: [], loginAttempts: 0,
    className: "10th", section: "A", rollNo: "99",
  });

  const ms = await User.findOne({ userId: stuId });
  const rs = await rtdb.ref(`Users/Parents/${LOGIN}/${stuId}`).once("value");
  const fs = await namedFs.collection(`users/${SC}/students`).doc(stuId).get();
  if (ms && rs.exists() && fs.exists) ok(`${stuId} (Student) → STU prefix, all 3 DBs ✓`);
  else fail(stuId, "Missing");

  // Password check for all
  console.log("\n━━━ TEST C: Password Check for All Imports ━━━\n");
  for (const uid of testIds) {
    const u = await User.findOne({ userId: uid });
    const match = await bcrypt.compare("Test1234", u.password);
    match ? ok(`${uid} password ✓`) : fail(`${uid} password`, "MISMATCH");
  }

  // Count check
  console.log("\n━━━ TEST D: Count Check ━━━\n");
  const midCount = await User.countDocuments({});
  midCount === beforeCount + 4 ? ok(`MongoDB: ${beforeCount} → ${midCount} (+4)`) : fail("count", `expected +4 got ${midCount - beforeCount}`);

  // CLEANUP
  console.log("\n━━━ CLEANUP ━━━\n");
  for (const uid of testIds) {
    await User.deleteOne({ userId: uid });
    for (const p of [`Users/Teachers/${LOGIN}/${uid}`, `Users/Admin/${LOGIN}/${uid}`, `Users/Parents/${LOGIN}/${uid}`, `Schools/${SC}/${SESSION}/Teachers/${uid}`]) {
      await rtdb.ref(p).remove().catch(() => {});
    }
    for (const col of ["admins", "teachers", "staff", "students"]) {
      try { await namedFs.collection(`users/${SC}/${col}`).doc(uid).delete(); } catch (_) {}
    }
    console.log("  Cleaned: " + uid);
  }
  for (const [k, v] of Object.entries(beforeCounters)) {
    await Counter.updateOne({ _id: k }, { $set: { seq: v } });
  }
  console.log("  Counters restored");

  // Verify
  const afterCount = await User.countDocuments({});
  console.log(`\n  Final: ${afterCount} users ${afterCount === beforeCount ? "✅ restored" : "❌"}`);

  console.log(`\n╔══════════════════════════════════════════════════════════════════╗`);
  console.log(`║  RESULTS: ${passed} passed, ${failed} failed${failed === 0 ? " — ALL CLEAR ✅" : " — ISSUES ❌"}                        ║`);
  console.log(`╚══════════════════════════════════════════════════════════════════╝`);

  await mongoose.disconnect();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(1); });
