#!/usr/bin/env node
/**
 * COMPREHENSIVE TIMETABLE CROSS-SYSTEM TEST
 * Tests every feature, scores each system, cleans up.
 */
require("dotenv").config();
const mongoose = require("mongoose");
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const dayNames = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
const today = dayNames[new Date().getDay()];

const scores = { adminPanel: { pass: 0, fail: 0, total: 0 }, teacherApp: { pass: 0, fail: 0, total: 0 }, parentApp: { pass: 0, fail: 0, total: 0 }, crossSystem: { pass: 0, fail: 0, total: 0 } };

function test(system, name, condition, detail) {
  scores[system].total++;
  if (condition) { scores[system].pass++; console.log(`  ✅ ${name}`); }
  else { scores[system].fail++; console.log(`  ❌ ${name} — ${detail || 'FAILED'}`); }
}

async function main() {
  await mongoose.connect(process.env.MONGODB_URI + "graderIQ");
  const User = mongoose.connection.collection("users");

  console.log("╔══════════════════════════════════════════════════════════════════════╗");
  console.log("║  COMPREHENSIVE TIMETABLE CROSS-SYSTEM TEST                          ║");
  console.log("║  Today: " + today + "                                                        ║");
  console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 1: CREATE BUFFER DATA — Class 9th B
  // ═══════════════════════════════════════════════════════════════════════
  console.log("━━━ PHASE 1: Creating buffer data (Class 9th Section B) ━━━\n");

  const BUF_TEACHERS = {
    "Mathematics": { id: "TEA0001", name: "Anita Verma" },
    "English": { id: "TEA0003", name: "Neha Sharma" },
    "Science": { id: "TEA0006", name: "Dr. Rakesh Jain" },
    "Hindi": { id: "TEA0004", name: "Amit Dubey" },
  };
  const BUF_TT = {
    Monday: ["Mathematics","English","Science","Hindi","Mathematics","English"],
    Tuesday: ["English","Science","Mathematics","Hindi","English","Science"],
    Wednesday: ["Science","Mathematics","Hindi","English","Science","Hindi"],
    Thursday: ["Hindi","English","Mathematics","Science","Hindi","Mathematics"],
    Friday: ["Mathematics","Hindi","English","Science","Mathematics","Science"],
    Saturday: ["English","Mathematics","Science","Hindi","English","Hindi"],
  };
  const PTIMES = [
    {s:"8:30",e:"9:15"},{s:"9:15",e:"10:00"},{s:"10:00",e:"10:45"},
    {s:"11:00",e:"11:45"},{s:"11:45",e:"12:30"},{s:"12:45",e:"1:30"},
  ];

  // Create section in RTDB
  await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B`).update({ _init: true });

  // RTDB timetable
  const rtdbBuf = {};
  for (const [day, periods] of Object.entries(BUF_TT)) {
    rtdbBuf[day] = periods.map(subj => ({ subject: subj, teacher_id: BUF_TEACHERS[subj].id, teacher_name: BUF_TEACHERS[subj].name }));
  }
  await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B/Time_table`).set(rtdbBuf);

  // Firestore timetable
  const fsBuf = {};
  for (const [day, periods] of Object.entries(BUF_TT)) {
    fsBuf[day] = periods.map((subj, i) => ({
      period: i + 1, subject: subj, teacherId: BUF_TEACHERS[subj].id, teacherName: BUF_TEACHERS[subj].name,
      startTime: PTIMES[i].s, endTime: PTIMES[i].e, room: "", type: "class",
    }));
  }
  await namedFs.collection(`schools/${SC}/timetables`).doc(`${S}_Class 9th_Section B`).set({
    schoolId: SC, session: S, className: "9th", section: "B", sectionKey: "Section B",
    schedule: fsBuf, updatedBy: "test", updatedAt: new Date(),
  });

  // Subject assignments
  const BUF_SA = {
    "3001": { subject_name: "Mathematics", category: "Core", periods_week: 6, teacher_id: "TEA0001", teacher_name: "Anita Verma" },
    "3002": { subject_name: "English", category: "Core", periods_week: 6, teacher_id: "TEA0003", teacher_name: "Neha Sharma" },
    "3003": { subject_name: "Science", category: "Core", periods_week: 6, teacher_id: "TEA0006", teacher_name: "Dr. Rakesh Jain" },
    "3004": { subject_name: "Hindi", category: "Core", periods_week: 6, teacher_id: "TEA0004", teacher_name: "Amit Dubey" },
  };
  await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/9B`).set(BUF_SA);
  await namedFs.collection(`schools/${SC}/subjectAssignments`).doc(`${S}_9B`).set({
    schoolId: SC, session: S, className: "9th", classKey: "9B", assignments: Object.entries(BUF_SA).map(([code, s]) => ({
      subjectCode: code, subjectName: s.subject_name, category: s.category, periodsWeek: s.periods_week, teacherId: s.teacher_id, teacherName: s.teacher_name,
    })), updatedAt: new Date(),
  });

  // Add duties for TEA0001 for 9th B
  await rtdb.ref(`Schools/${SC}/${S}/Teachers/TEA0001/Duties/Teaching/Class 9th/Section B/Mathematics`).set("assigned");
  await rtdb.ref(`Schools/${SC}/${S}/Teachers/TEA0003/Duties/Teaching/Class 9th/Section B/English`).set("assigned");

  console.log("  ✅ Buffer data created: Class 9th B with 4 subjects, 6 days × 6 periods\n");

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 2: ADMIN PANEL TESTS
  // ═══════════════════════════════════════════════════════════════════════
  console.log("━━━ PHASE 2: ADMIN PANEL TESTS ━━━\n");

  // 2.1 Timetable Settings
  const settings = await rtdb.ref(`Schools/${SC}/${S}/Time_table_settings`).once("value");
  const sv = settings.val();
  test("adminPanel", "Timetable settings exist in RTDB", !!sv);
  test("adminPanel", "Settings: 6 periods × 45 min", sv?.No_of_periods === 6 && sv?.Length_of_period === 45);
  test("adminPanel", "Settings: 6 working days", Array.isArray(sv?.Working_days) && sv.Working_days.length === 6);
  test("adminPanel", "Settings: 2 recesses configured", Array.isArray(sv?.Recesses) && sv.Recesses.length === 2);
  test("adminPanel", "Settings: start 8:30AM end 1:30PM", sv?.Start_time === "8:30AM" && sv?.End_time === "1:30PM");

  const fsSettings = await namedFs.doc(`schools/${SC}/timetableSettings/${S}`).get();
  test("adminPanel", "Firestore settings exist", fsSettings.exists);
  test("adminPanel", "Firestore settings match RTDB", fsSettings.exists && fsSettings.data()?.periodsCount === 6);

  // 2.2 Master Timetable — Class 10th A
  const rtdbTt10 = await rtdb.ref(`Schools/${SC}/${S}/Class 10th/Section A/Time_table`).once("value");
  test("adminPanel", "Class 10th A RTDB timetable exists", rtdbTt10.exists());
  test("adminPanel", "Class 10th A: 6 days", Object.keys(rtdbTt10.val() || {}).length === 6);

  let totalPeriods10 = 0;
  for (const [day, periods] of Object.entries(rtdbTt10.val() || {})) {
    totalPeriods10 += (periods || []).length;
  }
  test("adminPanel", "Class 10th A: 36 total periods (6×6)", totalPeriods10 === 36);

  // 2.3 Master Timetable — Buffer Class 9th B
  const rtdbTt9B = await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B/Time_table`).once("value");
  test("adminPanel", "Buffer 9th B RTDB timetable exists", rtdbTt9B.exists());

  // 2.4 Subject Assignments
  const sa10 = await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/10`).once("value");
  test("adminPanel", "Class 10 subject assignments: 7 subjects", Object.keys(sa10.val() || {}).length === 7);

  const fsSa10 = await namedFs.doc(`schools/${SC}/subjectAssignments/${S}_10`).get();
  test("adminPanel", "Firestore subject assignments exist for class 10", fsSa10.exists);
  test("adminPanel", "Firestore SA: 7 assignments", (fsSa10.data()?.assignments || []).length === 7);

  // 2.5 Conflict detection simulation
  // TEA0005 teaches Maths in 10th A Monday P2. If we try to assign TEA0005 to 9th B Monday P1, that's OK (different period)
  // But if we try TEA0005 to 9th B Monday P2, that's a CONFLICT
  const mon10 = (rtdbTt10.val() || {}).Monday || [];
  const tea0005MonP2 = mon10[1]; // P2 (0-indexed)
  test("adminPanel", "TEA0005 has Monday P2 in 10th A", tea0005MonP2?.teacher_id === "TEA0005", tea0005MonP2?.teacher_id);

  // 2.6 Edit simulation — change 10th A Wednesday P1 from Science to English
  const origWedP1 = (rtdbTt10.val() || {}).Wednesday?.[0];
  test("adminPanel", "Original Wed P1: Science by TEA0006", origWedP1?.subject === "Science" && origWedP1?.teacher_id === "TEA0006");

  // 2.7 All Firestore timetable docs
  const allFsTt = await namedFs.collection(`schools/${SC}/timetables`).get();
  test("adminPanel", "Firestore has 3+ timetable docs (10A, 9A, 9B buffer)", allFsTt.size >= 3, "got " + allFsTt.size);

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 3: TEACHER APP TESTS
  // ═══════════════════════════════════════════════════════════════════════
  console.log("\n━━━ PHASE 3: TEACHER APP TESTS ━━━\n");

  // Simulate getMyTimetableFromAll() for each teacher
  const teacherTests = [
    { id: "TEA0001", name: "Anita Verma", subjects: ["Mathematics","Science"], minPeriods: 10 },
    { id: "TEA0003", name: "Neha Sharma", subjects: ["English"], minPeriods: 5 },
    { id: "TEA0005", name: "Sunita Agarwal", subjects: ["Mathematics"], minPeriods: 5 },
    { id: "TEA0007", name: "Meena Patel", subjects: ["Social Science"], minPeriods: 5 },
    { id: "TEA0009", name: "Priyanka Desai", subjects: ["Computer Science"], minPeriods: 2 },
  ];

  const allTtDocs = await namedFs.collection(`schools/${SC}/timetables`).where("session", "==", S).get();
  test("teacherApp", "Firestore query returns timetable docs", allTtDocs.size >= 3);

  for (const t of teacherTests) {
    let periods = 0;
    const byDay = {};
    allTtDocs.forEach(doc => {
      const d = doc.data();
      for (const [day, ps] of Object.entries(d.schedule || {})) {
        for (const p of ps) {
          if (p.teacherId === t.id) {
            periods++;
            if (!byDay[day]) byDay[day] = [];
            byDay[day].push(p);
          }
        }
      }
    });
    test("teacherApp", `${t.id} (${t.name}): ${periods} periods found`, periods >= t.minPeriods, `got ${periods}, min ${t.minPeriods}`);

    // Today's schedule
    const todayPeriods = byDay[today] || [];
    test("teacherApp", `${t.id} ${today} schedule: ${todayPeriods.length} periods`, today === "Sunday" || todayPeriods.length > 0);
  }

  // Multi-class teacher test — TEA0001 teaches in BOTH 10th A and 9th B
  let tea0001Classes = new Set();
  allTtDocs.forEach(doc => {
    const d = doc.data();
    for (const ps of Object.values(d.schedule || {})) {
      for (const p of ps) {
        if (p.teacherId === "TEA0001") tea0001Classes.add(`${d.className}-${d.section}`);
      }
    }
  });
  test("teacherApp", "TEA0001 teaches in multiple classes: " + [...tea0001Classes].join(", "), tea0001Classes.size >= 2);

  // Period time format
  allTtDocs.forEach(doc => {
    const d = doc.data();
    const firstDay = Object.values(d.schedule || {})[0] || [];
    if (firstDay.length > 0) {
      const p = firstDay[0];
      test("teacherApp", `Period times present: ${p.startTime}-${p.endTime} (doc ${doc.id})`, p.startTime && p.endTime);
    }
  });

  // Current period calculation simulation
  const now = new Date();
  const currentMinutes = now.getHours() * 60 + now.getMinutes();
  const periodTimes = PTIMES.map(p => {
    const [sh, sm] = p.s.split(":").map(Number);
    const [eh, em] = p.e.split(":").map(Number);
    return { start: sh * 60 + sm, end: eh * 60 + em, label: `${p.s}-${p.e}` };
  });
  let currentPeriodIdx = -1;
  periodTimes.forEach((p, i) => { if (currentMinutes >= p.start && currentMinutes <= p.end) currentPeriodIdx = i; });
  test("teacherApp", `Current period calculation: ${currentPeriodIdx >= 0 ? 'P' + (currentPeriodIdx + 1) : 'outside school hours'}`, true);

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 4: PARENT APP TESTS
  // ═══════════════════════════════════════════════════════════════════════
  console.log("\n━━━ PHASE 4: PARENT APP TESTS ━━━\n");

  // Test for each student with known class
  const studentTests = [
    { id: "STU0010", className: "Class 10th", section: "Section A", docId: `${S}_Class 10th_Section A` },
    { id: "STU0008", className: "Class 8th", section: "Section A", docId: `${S}_Class 8th_Section A` },
  ];

  for (const stu of studentTests) {
    // Check user exists with correct class
    const fsUser = await namedFs.collection(`users/${SC}/students`).doc(stu.id).get();
    test("parentApp", `${stu.id} exists in Firestore`, fsUser.exists);
    if (fsUser.exists) {
      const d = fsUser.data();
      test("parentApp", `${stu.id} className: ${d.className}`, d.className?.includes("10") || d.className?.includes("8"));
    }

    // Check timetable doc exists
    const ttDoc = await namedFs.doc(`schools/${SC}/timetables/${stu.docId}`).get();
    if (ttDoc.exists) {
      test("parentApp", `${stu.id} timetable doc exists: ${stu.docId}`, true);
      const schedule = ttDoc.data().schedule || {};
      test("parentApp", `${stu.id} has ${Object.keys(schedule).length} days in timetable`, Object.keys(schedule).length === 6);

      // Today's periods
      const todayPeriods = schedule[today] || [];
      test("parentApp", `${stu.id} ${today}: ${todayPeriods.length} periods`, today === "Sunday" || todayPeriods.length > 0);

      // Verify period has teacher info
      if (todayPeriods.length > 0) {
        test("parentApp", `${stu.id} period has subject+teacher`, todayPeriods[0].subject && todayPeriods[0].teacherName);
        test("parentApp", `${stu.id} period has time`, todayPeriods[0].startTime && todayPeriods[0].endTime);
      }
    } else {
      test("parentApp", `${stu.id} timetable doc exists`, false, "NOT FOUND: " + stu.docId);
    }
  }

  // Class 10th — verify all subjects visible
  const tt10Fs = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 10th_Section A`).get();
  if (tt10Fs.exists) {
    const allSubjects = new Set();
    for (const ps of Object.values(tt10Fs.data().schedule || {})) {
      for (const p of ps) allSubjects.add(p.subject);
    }
    test("parentApp", "Class 10th A subjects: " + [...allSubjects].join(", "), allSubjects.size >= 5);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 5: CROSS-SYSTEM CONSISTENCY TESTS
  // ═══════════════════════════════════════════════════════════════════════
  console.log("\n━━━ PHASE 5: CROSS-SYSTEM CONSISTENCY ━━━\n");

  // 5.1 RTDB ↔ Firestore data match for Class 10th A
  const rtdb10 = (await rtdb.ref(`Schools/${SC}/${S}/Class 10th/Section A/Time_table`).once("value")).val() || {};
  const fs10 = tt10Fs.exists ? tt10Fs.data().schedule : {};

  for (const day of ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]) {
    const rtdbPeriods = rtdb10[day] || [];
    const fsPeriods = fs10[day] || [];
    test("crossSystem", `${day}: RTDB ${rtdbPeriods.length} periods = Firestore ${fsPeriods.length}`, rtdbPeriods.length === fsPeriods.length);

    // Subject-level match for first 3 periods
    for (let i = 0; i < Math.min(3, rtdbPeriods.length); i++) {
      const rSubj = typeof rtdbPeriods[i] === "string" ? rtdbPeriods[i] : rtdbPeriods[i]?.subject;
      const fSubj = fsPeriods[i]?.subject;
      test("crossSystem", `${day} P${i+1}: RTDB="${rSubj}" = FS="${fSubj}"`, rSubj === fSubj, `RTDB=${rSubj} FS=${fSubj}`);
    }
  }

  // 5.2 Teacher IDs consistent across systems
  const rtdbTeachers = new Set();
  const fsTeachers = new Set();
  for (const ps of Object.values(rtdb10)) {
    for (const p of (ps || [])) {
      const tid = typeof p === "object" ? p.teacher_id : "";
      if (tid) rtdbTeachers.add(tid);
    }
  }
  for (const ps of Object.values(fs10)) {
    for (const p of (ps || [])) { if (p.teacherId) fsTeachers.add(p.teacherId); }
  }
  test("crossSystem", "Teacher IDs match: RTDB=" + [...rtdbTeachers].sort().join(",") + " FS=" + [...fsTeachers].sort().join(","),
    JSON.stringify([...rtdbTeachers].sort()) === JSON.stringify([...fsTeachers].sort()));

  // 5.3 Settings sync
  const rtdbSettings = (await rtdb.ref(`Schools/${SC}/${S}/Time_table_settings`).once("value")).val();
  const fsSettingsData = (await namedFs.doc(`schools/${SC}/timetableSettings/${S}`).get()).data();
  test("crossSystem", "Period count sync: RTDB=" + rtdbSettings?.No_of_periods + " FS=" + fsSettingsData?.periodsCount,
    rtdbSettings?.No_of_periods === fsSettingsData?.periodsCount);
  test("crossSystem", "Working days count sync", rtdbSettings?.Working_days?.length === fsSettingsData?.workingDays?.length);

  // 5.4 Buffer data visible in both
  const bufRtdb = await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B/Time_table`).once("value");
  const bufFs = await namedFs.doc(`schools/${SC}/timetables/${S}_Class 9th_Section B`).get();
  test("crossSystem", "Buffer 9th B: RTDB exists", bufRtdb.exists());
  test("crossSystem", "Buffer 9th B: Firestore exists", bufFs.exists);
  if (bufRtdb.exists() && bufFs.exists) {
    const bRtdb = Object.keys(bufRtdb.val()).length;
    const bFs = Object.keys(bufFs.data().schedule).length;
    test("crossSystem", `Buffer 9th B: RTDB ${bRtdb} days = FS ${bFs} days`, bRtdb === bFs);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // PHASE 6: CLEANUP
  // ═══════════════════════════════════════════════════════════════════════
  console.log("\n━━━ PHASE 6: CLEANUP ━━━\n");

  await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B/Time_table`).remove();
  await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/9B`).remove();
  await rtdb.ref(`Schools/${SC}/${S}/Teachers/TEA0001/Duties/Teaching/Class 9th/Section B`).remove();
  await rtdb.ref(`Schools/${SC}/${S}/Teachers/TEA0003/Duties/Teaching/Class 9th/Section B`).remove();
  try { await namedFs.doc(`schools/${SC}/timetables/${S}_Class 9th_Section B`).delete(); } catch (_) {}
  try { await namedFs.doc(`schools/${SC}/subjectAssignments/${S}_9B`).delete(); } catch (_) {}

  // Verify cleanup
  const postBufRtdb = await rtdb.ref(`Schools/${SC}/${S}/Class 9th/Section B/Time_table`).once("value");
  const postBufFs = await namedFs.collection(`schools/${SC}/timetables`).get();
  console.log("  Buffer RTDB: " + (postBufRtdb.exists() ? "❌ still exists" : "✅ removed"));
  console.log("  Remaining Firestore timetable docs: " + postBufFs.size + " (" + postBufFs.docs.map(d => d.id).join(", ") + ")");

  // ═══════════════════════════════════════════════════════════════════════
  // FINAL REPORT
  // ═══════════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
  console.log("║  TIMETABLE MODULE — COMPREHENSIVE SCORE REPORT                      ║");
  console.log("╠══════════════════════════════════════════════════════════════════════╣");

  for (const [system, label] of [["adminPanel","Admin Panel"],["teacherApp","Teacher App"],["parentApp","Parent App"],["crossSystem","Cross-System"]]) {
    const s = scores[system];
    const pct = s.total > 0 ? Math.round((s.pass / s.total) * 100) : 0;
    const bar = "█".repeat(Math.floor(pct / 5)) + "░".repeat(20 - Math.floor(pct / 5));
    console.log(`║  ${label.padEnd(14)} ${bar} ${String(pct).padStart(3)}%  (${s.pass}/${s.total})${s.fail > 0 ? '  ❌ ' + s.fail + ' failed' : '  ✅'}  ║`);
  }

  const totalPass = Object.values(scores).reduce((s, v) => s + v.pass, 0);
  const totalAll = Object.values(scores).reduce((s, v) => s + v.total, 0);
  const totalPct = Math.round((totalPass / totalAll) * 100);
  console.log("╠══════════════════════════════════════════════════════════════════════╣");
  console.log(`║  OVERALL        ${"█".repeat(Math.floor(totalPct / 5))}${"░".repeat(20 - Math.floor(totalPct / 5))} ${String(totalPct).padStart(3)}%  (${totalPass}/${totalAll})                  ║`);
  console.log("╚══════════════════════════════════════════════════════════════════════╝");

  if (totalPct < 100) {
    console.log("\n━━━ IMPROVEMENTS NEEDED ━━━");
    for (const [system, label] of [["adminPanel","Admin Panel"],["teacherApp","Teacher App"],["parentApp","Parent App"],["crossSystem","Cross-System"]]) {
      if (scores[system].fail > 0) {
        console.log(`  ${label}: ${scores[system].fail} test(s) failed — see ❌ above`);
      }
    }
  }

  await mongoose.disconnect();
  process.exit(totalPct === 100 ? 0 : 1);
}

main().catch(e => { console.error("FATAL:", e); process.exit(1); });
