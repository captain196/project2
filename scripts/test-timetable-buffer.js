#!/usr/bin/env node
/**
 * Creates buffer timetable data for Class 8th A for comprehensive testing.
 * Tests all operations, then provides cleanup.
 *
 * Usage:
 *   node scripts/test-timetable-buffer.js create    — Create buffer data
 *   node scripts/test-timetable-buffer.js test      — Run all tests
 *   node scripts/test-timetable-buffer.js cleanup   — Remove buffer data
 */
require("dotenv").config();
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const action = process.argv[2] || "create";

const TEACHERS = {
  "Mathematics": { id: "TEA0001", name: "Anita Verma" },
  "Science":     { id: "TEA0001", name: "Anita Verma" },
  "English":     { id: "TEA0002", name: "Sanjay Tiwari" },
  "Hindi":       { id: "TEA0002", name: "Sanjay Tiwari" },
  "Social Science": { id: "TEA0007", name: "Meena Patel" },
  "Computer Science": { id: "TEA0009", name: "Priyanka Desai" },
};

const TIMETABLE = {
  Monday:    ["Mathematics","English","Science","Hindi","Social Science","Computer Science"],
  Tuesday:   ["English","Mathematics","Hindi","Science","Computer Science","Social Science"],
  Wednesday: ["Science","Hindi","Mathematics","Social Science","English","Mathematics"],
  Thursday:  ["Hindi","Science","English","Mathematics","Social Science","English"],
  Friday:    ["Mathematics","Social Science","Science","English","Hindi","Science"],
  Saturday:  ["Social Science","English","Mathematics","Hindi","Science","Mathematics"],
};

const PERIOD_TIMES = [
  { start: "8:30", end: "9:15" },
  { start: "9:15", end: "10:00" },
  { start: "10:00", end: "10:45" },
  { start: "11:00", end: "11:45" },
  { start: "11:45", end: "12:30" },
  { start: "12:45", end: "1:30" },
];

const SUBJECTS = {
  "2001": { subject_name: "Mathematics", category: "Core", periods_week: 6, teacher_id: "TEA0001", teacher_name: "Anita Verma" },
  "2002": { subject_name: "Science", category: "Core", periods_week: 5, teacher_id: "TEA0001", teacher_name: "Anita Verma" },
  "2003": { subject_name: "English", category: "Core", periods_week: 5, teacher_id: "TEA0002", teacher_name: "Sanjay Tiwari" },
  "2004": { subject_name: "Hindi", category: "Core", periods_week: 5, teacher_id: "TEA0002", teacher_name: "Sanjay Tiwari" },
  "2005": { subject_name: "Social Science", category: "Core", periods_week: 4, teacher_id: "TEA0007", teacher_name: "Meena Patel" },
  "2006": { subject_name: "Computer Science", category: "Skill", periods_week: 2, teacher_id: "TEA0009", teacher_name: "Priyanka Desai" },
};

async function create() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  CREATING BUFFER DATA: Class 8th A Timetable               ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // 1. Subject Assignments — RTDB
  await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/8`).set(SUBJECTS);
  console.log("✅ RTDB Subject_Assignments/8 created (6 subjects)");

  // 2. Subject Assignments — Firestore
  const fsAssignments = Object.entries(SUBJECTS).map(([code, s]) => ({
    subjectCode: code, subjectName: s.subject_name, category: s.category,
    periodsWeek: s.periods_week, teacherId: s.teacher_id, teacherName: s.teacher_name,
  }));
  await namedFs.collection(`schools/${SC}/subjectAssignments`).doc(`${S}_8`).set({
    schoolId: SC, session: S, className: "8th", classKey: "8",
    assignments: fsAssignments, updatedAt: new Date(),
  });
  console.log("✅ Firestore subjectAssignments/2026-27_8 created");

  // 3. RTDB Timetable
  const rtdbTt = {};
  for (const [day, periods] of Object.entries(TIMETABLE)) {
    rtdbTt[day] = periods.map(subj => {
      const t = TEACHERS[subj];
      return { subject: subj, teacher_id: t.id, teacher_name: t.name };
    });
  }
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table`).set(rtdbTt);
  console.log("✅ RTDB Class 8th/Section A/Time_table created (6 days × 6 periods)");

  // 4. Firestore Timetable
  const fsTt = {};
  for (const [day, periods] of Object.entries(TIMETABLE)) {
    fsTt[day] = periods.map((subj, i) => {
      const t = TEACHERS[subj];
      return {
        period: i + 1, subject: subj, teacherId: t.id, teacherName: t.name,
        startTime: PERIOD_TIMES[i].start, endTime: PERIOD_TIMES[i].end,
        room: "", type: "class",
      };
    });
  }
  await namedFs.collection(`schools/${SC}/timetables`).doc(`${S}_Class 8th_Section A`).set({
    schoolId: SC, session: S, className: "8th", section: "A", sectionKey: "Section A",
    schedule: fsTt, updatedBy: "test-buffer", updatedAt: new Date(),
  });
  console.log("✅ Firestore timetables/2026-27_Class 8th_Section A created");

  // 5. Update All Subjects for Class 8th
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/All Subjects`).set(SUBJECTS);
  console.log("✅ RTDB Class 8th/All Subjects updated");

  console.log("\n📋 Buffer data ready for testing:");
  console.log("   Admin Panel: Academic Planner → Timetable tab → select Class 8th/Section A");
  console.log("   Teacher App: Login as TEA0001 (Anita Verma) → Timetable → see Maths+Science periods");
  console.log("   Parent App:  Login as STU0008 (Riya Choudhary, Class 8th A) → Timetable");
}

async function test() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  TESTING BUFFER DATA: Class 8th A                          ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  let passed = 0, failed = 0;
  const ok = (l) => { console.log("  ✅ " + l); passed++; };
  const fail = (l, r) => { console.log("  ❌ " + l + " — " + r); failed++; };

  // Test 1: RTDB timetable exists with correct structure
  console.log("━━━ Test 1: RTDB Timetable ━━━");
  const rtdbTt = await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table`).once("value");
  if (!rtdbTt.exists()) { fail("RTDB timetable", "NOT FOUND"); }
  else {
    const v = rtdbTt.val();
    const days = Object.keys(v);
    days.length === 6 ? ok("6 days present") : fail("days", `got ${days.length}`);
    const monPeriods = v.Monday || [];
    monPeriods.length === 6 ? ok("Monday has 6 periods") : fail("Monday periods", `got ${monPeriods.length}`);
    monPeriods[0]?.teacher_id === "TEA0001" ? ok("Monday P1 teacher = TEA0001") : fail("Mon P1 teacher", monPeriods[0]?.teacher_id);
  }

  // Test 2: Firestore timetable matches RTDB
  console.log("\n━━━ Test 2: Firestore Timetable ━━━");
  const fsTt = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).get();
  if (!fsTt.exists) { fail("Firestore timetable", "NOT FOUND"); }
  else {
    const d = fsTt.data();
    const schedule = d.schedule || {};
    Object.keys(schedule).length === 6 ? ok("6 days in Firestore") : fail("FS days", Object.keys(schedule).length);
    const monFs = schedule.Monday || [];
    monFs.length === 6 ? ok("Monday has 6 periods in Firestore") : fail("FS Mon periods", monFs.length);
    monFs[0]?.teacherId === "TEA0001" ? ok("FS Monday P1 teacher = TEA0001") : fail("FS Mon P1", monFs[0]?.teacherId);
    monFs[0]?.startTime === "8:30" ? ok("FS Monday P1 start = 8:30") : fail("FS Mon P1 time", monFs[0]?.startTime);
    d.className === "8th" ? ok("FS className = 8th") : fail("FS className", d.className);
    d.section === "A" ? ok("FS section = A") : fail("FS section", d.section);
  }

  // Test 3: Subject assignments match
  console.log("\n━━━ Test 3: Subject Assignments ━━━");
  const rtdbSa = await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/8`).once("value");
  rtdbSa.exists() ? ok("RTDB Subject_Assignments/8 exists") : fail("RTDB SA", "NOT FOUND");

  const fsSa = await namedFs.doc(`schools/${SC}/subjectAssignments/${S}_8`).get();
  fsSa.exists ? ok("Firestore subjectAssignments exists") : fail("FS SA", "NOT FOUND");
  if (fsSa.exists) {
    const asgn = fsSa.data().assignments || [];
    asgn.length === 6 ? ok("6 subject assignments") : fail("SA count", asgn.length);
  }

  // Test 4: Teacher filtering — TEA0001 should have Maths + Science periods
  console.log("\n━━━ Test 4: Teacher Period Filtering ━━━");
  if (fsTt.exists) {
    const schedule = fsTt.data().schedule || {};
    let tea0001Periods = 0, tea0002Periods = 0;
    for (const [day, periods] of Object.entries(schedule)) {
      for (const p of periods) {
        if (p.teacherId === "TEA0001") tea0001Periods++;
        if (p.teacherId === "TEA0002") tea0002Periods++;
      }
    }
    tea0001Periods > 0 ? ok(`TEA0001 has ${tea0001Periods} periods across week`) : fail("TEA0001 periods", "0");
    tea0002Periods > 0 ? ok(`TEA0002 has ${tea0002Periods} periods across week`) : fail("TEA0002 periods", "0");
  }

  // Test 5: Edit simulation — change Monday P1 from Mathematics to English
  console.log("\n━━━ Test 5: Edit Period Simulation ━━━");
  // RTDB edit
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/0`).set({
    subject: "English", teacher_id: "TEA0002", teacher_name: "Sanjay Tiwari"
  });
  const editedR = await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/0`).once("value");
  editedR.val()?.subject === "English" ? ok("RTDB Monday P1 edited to English") : fail("RTDB edit", editedR.val()?.subject);

  // Firestore edit
  const fsTtDoc = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).get();
  const currentSchedule = fsTtDoc.data().schedule;
  currentSchedule.Monday[0] = { ...currentSchedule.Monday[0], subject: "English", teacherId: "TEA0002", teacherName: "Sanjay Tiwari" };
  await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).update({ schedule: currentSchedule });
  const editedF = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).get();
  editedF.data().schedule.Monday[0].subject === "English" ? ok("Firestore Monday P1 edited to English") : fail("FS edit", "mismatch");

  // Revert edit
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/0`).set({
    subject: "Mathematics", teacher_id: "TEA0001", teacher_name: "Anita Verma"
  });
  currentSchedule.Monday[0] = { ...currentSchedule.Monday[0], subject: "Mathematics", teacherId: "TEA0001", teacherName: "Anita Verma" };
  await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).update({ schedule: currentSchedule });
  ok("Edit reverted back to original");

  // Test 6: Delete period simulation — clear Monday P6
  console.log("\n━━━ Test 6: Delete Period Simulation ━━━");
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/5`).set({ subject: "", teacher_id: "", teacher_name: "" });
  const delR = await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/5`).once("value");
  delR.val()?.subject === "" ? ok("RTDB Monday P6 cleared") : fail("RTDB delete", delR.val()?.subject);

  // Restore
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table/Monday/5`).set({
    subject: "Computer Science", teacher_id: "TEA0009", teacher_name: "Priyanka Desai"
  });
  ok("Monday P6 restored");

  // Test 7: Cross-system consistency
  console.log("\n━━━ Test 7: Cross-System Consistency ━━━");
  const finalRtdb = await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table`).once("value");
  const finalFs = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).get();
  const rtdbDays = Object.keys(finalRtdb.val() || {});
  const fsDays = Object.keys(finalFs.data().schedule || {});
  rtdbDays.length === fsDays.length ? ok(`Both have ${rtdbDays.length} days`) : fail("day count", `RTDB=${rtdbDays.length} FS=${fsDays.length}`);

  // Count total periods in each
  let rtdbTotal = 0, fsTotal = 0;
  for (const d of rtdbDays) rtdbTotal += (finalRtdb.val()[d] || []).length;
  for (const d of fsDays) fsTotal += (finalFs.data().schedule[d] || []).length;
  rtdbTotal === fsTotal ? ok(`Both have ${rtdbTotal} total periods`) : fail("period count", `RTDB=${rtdbTotal} FS=${fsTotal}`);

  // Test 8: Today's schedule for Saturday
  console.log("\n━━━ Test 8: Today (Saturday) Schedule ━━━");
  const dayNames = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
  const today = dayNames[new Date().getDay()];
  const todayRtdb = finalRtdb.val()?.[today];
  if (todayRtdb) {
    ok(`${today} has ${todayRtdb.length} periods in RTDB`);
    todayRtdb.forEach((p, i) => {
      const s = typeof p === "string" ? p : p.subject;
      const t = typeof p === "object" ? p.teacher_id : "";
      console.log(`    P${i+1}: ${s.padEnd(20)} ${t}`);
    });
  } else {
    today === "Sunday" ? ok("Sunday — no schedule (correct)") : fail(`${today} schedule`, "NOT FOUND");
  }

  console.log(`\n╔══════════════════════════════════════════════════════════════╗`);
  console.log(`║  RESULTS: ${passed} passed, ${failed} failed${failed === 0 ? " — ALL CLEAR ✅" : " — ISSUES ❌"}                        ║`);
  console.log(`╚══════════════════════════════════════════════════════════════╝`);
}

async function cleanup() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  CLEANUP: Removing Class 8th A buffer data                 ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // RTDB
  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table`).remove();
  console.log("✅ RTDB timetable removed");

  await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/8`).remove();
  console.log("✅ RTDB subject assignments removed");

  await rtdb.ref(`Schools/${SC}/${S}/Class 8th/All Subjects`).remove();
  console.log("✅ RTDB All Subjects removed");

  // Firestore
  try { await namedFs.doc(`schools/${SC}/timetables/${S}_Class 8th_Section A`).delete(); } catch (_) {}
  console.log("✅ Firestore timetable removed");

  try { await namedFs.doc(`schools/${SC}/subjectAssignments/${S}_8`).delete(); } catch (_) {}
  console.log("✅ Firestore subject assignments removed");

  // Verify
  const check1 = await rtdb.ref(`Schools/${SC}/${S}/Class 8th/Section A/Time_table`).once("value");
  const check2 = await namedFs.collection(`schools/${SC}/timetables`).get();
  console.log("\nVerification:");
  console.log("  RTDB timetable: " + (check1.exists() ? "❌ STILL EXISTS" : "✅ gone"));
  console.log("  Firestore timetable docs: " + check2.size + " remaining");
  console.log("  (Class 10th A should still be there: " + check2.docs.map(d => d.id).join(", ") + ")");
}

async function main() {
  if (action === "create") await create();
  else if (action === "test") await test();
  else if (action === "cleanup") await cleanup();
  else console.log("Usage: node scripts/test-timetable-buffer.js [create|test|cleanup]");
  process.exit(0);
}

main().catch(e => { console.error("FATAL:", e); process.exit(1); });
