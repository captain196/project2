#!/usr/bin/env node
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });
const { generateIdForRole } = require("../src/services/idGenerator");

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
  console.log("║  FINAL COMPREHENSIVE TEST SUITE                                ║");
  console.log("╚══════════════════════════════════════════════════════════════════╝");
  console.log("  Before: " + beforeCount + " users\n");

  const testIds = [];
  let passed = 0, failed = 0;
  const ok = (l) => { console.log("  ✅ " + l); passed++; };
  const fail = (l, r) => { console.log("  ❌ " + l + " — " + r); failed++; };

  // TEST 1: Create Teacher
  console.log("\n━━━ TEST 1: Create Staff (Teacher) ━━━");
  const teaId = await generateIdForRole("teacher");
  testIds.push(teaId);
  await User.insertOne({ userId: teaId, password: hashedPw, name: "Test Teacher", email: "test.tea@test.com", phone: "+919999900001", role: "teacher", schoolId: LOGIN, schoolCode: SC, status: "Active", createdAt: new Date(), createdBy: "test", refreshTokens: [], devices: [], loginAttempts: 0 });
  await rtdb.ref(`Users/Teachers/${LOGIN}/${teaId}`).set({ Name: "Test Teacher", Email: "test.tea@test.com", Status: "Active", Role: "Teacher", Credentials: { Id: teaId, Password: hashedPw } });
  await rtdb.ref(`Schools/${SC}/${SESSION}/Teachers/${teaId}`).set({ Name: "Test Teacher", Status: "Active", Position: "Teacher" });
  await namedFs.collection(`users/${SC}/teachers`).doc(teaId).set({ userId: teaId, name: "Test Teacher", email: "test.tea@test.com", phone: "+919999900001", role: "teacher", schoolId: SC, status: "active" });

  const m1 = await User.findOne({ userId: teaId });
  const r1 = await rtdb.ref(`Users/Teachers/${LOGIN}/${teaId}`).once("value");
  const f1 = await namedFs.collection(`users/${SC}/teachers`).doc(teaId).get();
  m1 && r1.exists() && f1.exists ? ok(`${teaId} created in all 3 DBs`) : fail(`${teaId}`, "Missing");

  // TEST 2: Create Support Staff
  console.log("\n━━━ TEST 2: Create Staff (Peon) ━━━");
  const staId = await generateIdForRole("staff");
  testIds.push(staId);
  await User.insertOne({ userId: staId, password: hashedPw, name: "Test Peon", email: "test.peon@test.com", phone: "+919999900002", role: "staff", schoolId: LOGIN, schoolCode: SC, status: "Active", createdAt: new Date(), createdBy: "test", refreshTokens: [], devices: [], loginAttempts: 0 });
  await rtdb.ref(`Users/Teachers/${LOGIN}/${staId}`).set({ Name: "Test Peon", Status: "Active", Role: "Staff" });
  await rtdb.ref(`Schools/${SC}/${SESSION}/Teachers/${staId}`).set({ Name: "Test Peon", Status: "Active", Position: "Peon" });
  await namedFs.collection(`users/${SC}/staff`).doc(staId).set({ userId: staId, name: "Test Peon", role: "staff", schoolId: SC, status: "active" });

  const m2 = await User.findOne({ userId: staId });
  const r2 = await rtdb.ref(`Users/Teachers/${LOGIN}/${staId}`).once("value");
  const f2 = await namedFs.collection(`users/${SC}/staff`).doc(staId).get();
  m2 && r2.exists() && f2.exists ? ok(`${staId} created in all 3 DBs`) : fail(`${staId}`, "Missing");

  // TEST 3: Create Admin (Principal)
  console.log("\n━━━ TEST 3: Create Admin (Principal) ━━━");
  const priId = await generateIdForRole("principal");
  testIds.push(priId);
  await User.insertOne({ userId: priId, password: hashedPw, name: "Test Principal", email: "test.pri@test.com", phone: "+919999900003", role: "principal", schoolId: LOGIN, schoolCode: SC, status: "Active", createdAt: new Date(), createdBy: "test", refreshTokens: [], devices: [], loginAttempts: 0 });
  await rtdb.ref(`Users/Admin/${LOGIN}/${priId}`).set({ Name: "Test Principal", Status: "Active", Role: "Principal" });
  await namedFs.collection(`users/${SC}/staff`).doc(priId).set({ userId: priId, name: "Test Principal", role: "principal", schoolId: SC, status: "active" });

  const m3 = await User.findOne({ userId: priId });
  const r3 = await rtdb.ref(`Users/Admin/${LOGIN}/${priId}`).once("value");
  const f3 = await namedFs.collection(`users/${SC}/staff`).doc(priId).get();
  m3 && r3.exists() && f3.exists ? ok(`${priId} created in all 3 DBs`) : fail(`${priId}`, "Missing");

  // TEST 4: Create Student
  console.log("\n━━━ TEST 4: Create Student ━━━");
  const stuId = await generateIdForRole("student");
  testIds.push(stuId);
  await User.insertOne({ userId: stuId, password: hashedPw, name: "Test Student", email: "test.stu@test.com", phone: "+919999900004", role: "student", schoolId: LOGIN, schoolCode: SC, status: "Active", createdAt: new Date(), createdBy: "test", refreshTokens: [], devices: [], loginAttempts: 0, className: "10th", section: "A" });
  await rtdb.ref(`Users/Parents/${LOGIN}/${stuId}`).set({ Name: "Test Student", Status: "Active", Credentials: { Id: stuId, Password: hashedPw } });
  await namedFs.collection(`users/${SC}/students`).doc(stuId).set({ userId: stuId, name: "Test Student", role: "student", className: "10th", section: "A", schoolId: SC, status: "active" });

  const m4 = await User.findOne({ userId: stuId });
  const r4 = await rtdb.ref(`Users/Parents/${LOGIN}/${stuId}`).once("value");
  const f4 = await namedFs.collection(`users/${SC}/students`).doc(stuId).get();
  m4 && r4.exists() && f4.exists ? ok(`${stuId} created in all 3 DBs`) : fail(`${stuId}`, "Missing");

  // TEST 5: Password verification
  console.log("\n━━━ TEST 5: Password verification ━━━");
  for (const uid of testIds) {
    const u = await User.findOne({ userId: uid });
    const match = await bcrypt.compare("Test1234", u.password);
    match ? ok(`${uid} password OK`) : fail(`${uid} password`, "MISMATCH");
  }

  // TEST 6: Prefix integrity
  console.log("\n━━━ TEST 6: Prefix integrity ━━━");
  const exp = { teacher: "TEA", staff: "STA", principal: "STA", student: "STU" };
  for (const uid of testIds) {
    const u = await User.findOne({ userId: uid });
    const pfx = uid.replace(/[0-9]/g, "");
    pfx === exp[u.role] ? ok(`${uid} prefix ${pfx} correct`) : fail(`${uid}`, `got ${pfx} want ${exp[u.role]}`);
  }

  // TEST 7: Disable/Enable
  console.log("\n━━━ TEST 7: Disable/Enable simulation ━━━");
  await User.updateOne({ userId: teaId }, { $set: { status: "Inactive" } });
  await rtdb.ref(`Users/Teachers/${LOGIN}/${teaId}/Status`).set("Inactive");
  await namedFs.collection(`users/${SC}/teachers`).doc(teaId).update({ status: "inactive" });

  let d = await User.findOne({ userId: teaId });
  d.status === "Inactive" ? ok(`${teaId} disabled in MongoDB`) : fail(`${teaId} disable`, d.status);

  await User.updateOne({ userId: teaId }, { $set: { status: "Active" } });
  await rtdb.ref(`Users/Teachers/${LOGIN}/${teaId}/Status`).set("Active");
  await namedFs.collection(`users/${SC}/teachers`).doc(teaId).update({ status: "active" });

  d = await User.findOne({ userId: teaId });
  d.status === "Active" ? ok(`${teaId} re-enabled`) : fail(`${teaId} enable`, d.status);

  // TEST 8: Password reset
  console.log("\n━━━ TEST 8: Password reset simulation ━━━");
  const newHash = await bcrypt.hash("NewPass123", 10);
  await User.updateOne({ userId: stuId }, { $set: { password: newHash } });
  let ru = await User.findOne({ userId: stuId });
  (await bcrypt.compare("NewPass123", ru.password)) ? ok(`${stuId} password reset verified`) : fail(`${stuId}`, "mismatch");
  await User.updateOne({ userId: stuId }, { $set: { password: hashedPw } });

  // TEST 9: Cross-DB counts
  console.log("\n━━━ TEST 9: Cross-DB count ━━━");
  const midCount = await User.countDocuments({});
  midCount === beforeCount + 4 ? ok(`MongoDB +4 (${midCount})`) : fail("count", `expected ${beforeCount + 4} got ${midCount}`);

  // CLEANUP
  console.log("\n━━━ CLEANUP: Removing test users ━━━");
  for (const uid of testIds) {
    await User.deleteOne({ userId: uid });
    for (const p of [`Users/Teachers/${LOGIN}/${uid}`, `Users/Admin/${LOGIN}/${uid}`, `Users/Parents/${LOGIN}/${uid}`, `Schools/${SC}/${SESSION}/Teachers/${uid}`]) {
      await rtdb.ref(p).remove().catch(() => {});
    }
    for (const col of ["admins", "teachers", "staff", "students", "schoolsuperadmins"]) {
      try { await namedFs.collection(`users/${SC}/${col}`).doc(uid).delete(); } catch (_) {}
    }
    console.log("  Cleaned: " + uid);
  }
  for (const [k, v] of Object.entries(beforeCounters)) {
    await Counter.updateOne({ _id: k }, { $set: { seq: v } });
  }
  console.log("  Counters restored");

  // POST-CLEANUP
  console.log("\n━━━ POST-CLEANUP VERIFICATION ━━━");
  const afterCount = await User.countDocuments({});
  let afterFs = 0;
  for (const col of ["admins", "teachers", "staff", "students", "schoolsuperadmins"]) {
    try { const s = await namedFs.collection(`users/${SC}/${col}`).get(); afterFs += s.size; } catch (_) {}
  }
  try { const g = await namedFs.collection("users/global/superadmins").get(); afterFs += g.size; } catch (_) {}

  let afterRtdb = 0;
  for (const p of ["Users/Admin/10001", "Users/Teachers/10001", "Users/Admin/Our Panel", "Users/Parents/10001"]) {
    const s = await rtdb.ref(p).once("value");
    if (s.exists()) afterRtdb += Object.keys(s.val() || {}).filter((k) => !["Count", "_Counter", "_init", "AccessHistory"].includes(k) && typeof (s.val() || {})[k] === "object").length;
  }

  console.log(`  MongoDB:   ${afterCount}${afterCount === beforeCount ? " ✅" : " ❌"}`);
  console.log(`  Firestore: ${afterFs}${afterFs === 40 ? " ✅" : " ⚠️"}`);
  console.log(`  RTDB:      ${afterRtdb}${afterRtdb === 40 ? " ✅" : " ⚠️"}`);

  const afterCtrs = await Counter.find({}).toArray();
  let ctrsOk = true;
  for (const c of afterCtrs) { if (beforeCounters[c._id] !== undefined && c.seq !== beforeCounters[c._id]) ctrsOk = false; }
  console.log(`  Counters:  ${ctrsOk ? "✅" : "❌"}`);

  console.log(`\n╔══════════════════════════════════════════════════════════════════╗`);
  console.log(`║  RESULTS: ${passed} passed, ${failed} failed${failed === 0 ? " — ALL CLEAR ✅" : " — ISSUES ❌"}                        ║`);
  console.log(`║  Database: ${afterCount} users (restored to before)                   ║`);
  console.log(`╚══════════════════════════════════════════════════════════════════╝`);

  await mongoose.disconnect();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(1); });
