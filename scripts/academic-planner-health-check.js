#!/usr/bin/env node
/**
 * COMPREHENSIVE HEALTH CHECK: Academic Planner Module
 * Tests every feature across Admin Panel data, Teacher App data, Parent App data
 */
require("dotenv").config();
const admin = require("firebase-admin");
const mongoose = require("mongoose");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];

const scores = {};
function section(name) { scores[name] = { pass: 0, fail: 0, total: 0 }; return name; }
function test(sec, name, condition, detail) {
  scores[sec].total++;
  if (condition) { scores[sec].pass++; console.log(`  ✅ ${name}`); }
  else { scores[sec].fail++; console.log(`  ❌ ${name}${detail ? " — " + detail : ""}`); }
}

async function main() {
  await mongoose.connect(process.env.MONGODB_URI + "graderIQ");
  const User = mongoose.connection.collection("users");

  console.log("╔══════════════════════════════════════════════════════════════════════╗");
  console.log("║  ACADEMIC PLANNER — COMPREHENSIVE HEALTH CHECK                      ║");
  console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

  // ═══════════════════════════════════════════════════════════════
  const s1 = section("Timetable Settings");
  console.log("━━━ 1. TIMETABLE SETTINGS ━━━");
  // ═══════════════════════════════════════════════════════════════

  const rtdbSettings = (await rtdb.ref(`Schools/${SC}/${S}/Time_table_settings`).once("value")).val();
  test(s1, "RTDB settings exist", !!rtdbSettings);
  test(s1, "6 periods configured", rtdbSettings?.No_of_periods === 6);
  test(s1, "45 min period length", rtdbSettings?.Length_of_period === 45);
  test(s1, "6 working days", Array.isArray(rtdbSettings?.Working_days) && rtdbSettings.Working_days.length === 6);
  test(s1, "2 recesses configured", Array.isArray(rtdbSettings?.Recesses) && rtdbSettings.Recesses.length === 2);
  test(s1, "Start time 8:30AM", rtdbSettings?.Start_time === "8:30AM");
  test(s1, "End time 1:30PM", rtdbSettings?.End_time === "1:30PM");

  const fsSettings = await namedFs.doc(`schools/${SC}/timetableSettings/${S}`).get();
  test(s1, "Firestore settings exist", fsSettings.exists);
  test(s1, "Firestore periods match RTDB", fsSettings.exists && fsSettings.data()?.periodsCount === 6);
  test(s1, "Firestore period length match", fsSettings.exists && fsSettings.data()?.periodLength === 45);

  // ═══════════════════════════════════════════════════════════════
  const s2 = section("Subject Assignments");
  console.log("\n━━━ 2. SUBJECT ASSIGNMENTS ━━━");
  // ═══════════════════════════════════════════════════════════════

  const rtdbSa = (await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments`).once("value")).val() || {};
  const fsSaDocs = await namedFs.collection(`schools/${SC}/subjectAssignments`).get();
  const fsAssignments = {};
  fsSaDocs.docs.forEach(d => { fsAssignments[d.data().classKey] = d.data(); });

  for (const classKey of ["7", "8", "9", "10"]) {
    const rtdbCount = Object.keys(rtdbSa[classKey] || {}).length;
    const fsCount = (fsAssignments[classKey]?.assignments || []).length;
    test(s2, `Class ${classKey}: RTDB has ${rtdbCount} subjects`, rtdbCount >= 6);
    test(s2, `Class ${classKey}: Firestore has ${fsCount} subjects`, fsCount >= 6);
    test(s2, `Class ${classKey}: RTDB = Firestore count`, rtdbCount === fsCount, `RTDB=${rtdbCount} FS=${fsCount}`);

    // Every subject has a teacher assigned
    const rtdbSubs = rtdbSa[classKey] || {};
    let allHaveTeacher = true;
    for (const [code, sub] of Object.entries(rtdbSubs)) {
      if (!sub.teacher_id) { allHaveTeacher = false; break; }
    }
    test(s2, `Class ${classKey}: All subjects have teacher assigned`, allHaveTeacher);
  }

  // ═══════════════════════════════════════════════════════════════
  const s3 = section("Master Timetable");
  console.log("\n━━━ 3. MASTER TIMETABLE ━━━");
  // ═══════════════════════════════════════════════════════════════

  const ttDocs = await namedFs.collection(`schools/${SC}/timetables`).get();
  test(s3, "6 timetable documents exist", ttDocs.size === 6, `got ${ttDocs.size}`);

  // Per-timetable checks
  for (const doc of ttDocs.docs) {
    const data = doc.data();
    const label = `${data.className} ${data.sectionKey || data.section}`;
    const schedule = data.schedule || {};
    const dayCount = Object.keys(schedule).length;
    test(s3, `${label}: 6 days`, dayCount === 6, `got ${dayCount}`);

    // Check period structure
    let validPeriods = true;
    let totalTeaching = 0;
    for (const [day, periods] of Object.entries(schedule)) {
      if (!Array.isArray(periods) || periods.length !== 6) { validPeriods = false; break; }
      for (const p of periods) {
        if (!p.startTime || !p.endTime || p.period === undefined) { validPeriods = false; break; }
        if (p.subject && p.subject !== "Free Period") totalTeaching++;
      }
    }
    test(s3, `${label}: Valid period structure`, validPeriods);
    test(s3, `${label}: ${totalTeaching} teaching periods`, totalTeaching >= 28, `got ${totalTeaching}`);

    // RTDB match
    const rtdbPath = `Schools/${SC}/${S}/${data.className ? "Class " + data.className : ""}/${data.sectionKey || "Section " + data.section}/Time_table`;
    const rtdbTt = (await rtdb.ref(rtdbPath).once("value")).val();
    test(s3, `${label}: RTDB timetable exists`, !!rtdbTt);
  }

  // ═══════════════════════════════════════════════════════════════
  const s4 = section("Conflict Detection");
  console.log("\n━━━ 4. CONFLICT DETECTION ━━━");
  // ═══════════════════════════════════════════════════════════════

  let teacherConflicts = 0;
  let duplicateWarnings = 0;

  for (const day of DAYS) {
    for (let p = 0; p < 6; p++) {
      const busy = {};
      ttDocs.docs.forEach(d => {
        const per = ((d.data().schedule || {})[day] || [])[p];
        if (per?.teacherId && per.subject !== "Free Period") {
          if (!busy[per.teacherId]) busy[per.teacherId] = [];
          busy[per.teacherId].push(d.id);
        }
      });
      for (const [tid, cls] of Object.entries(busy)) {
        if (cls.length > 1) teacherConflicts++;
      }
    }
  }
  test(s4, "Zero teacher double-bookings", teacherConflicts === 0, `${teacherConflicts} conflicts`);

  for (const doc of ttDocs.docs) {
    const data = doc.data();
    for (const [day, periods] of Object.entries(data.schedule || {})) {
      const sc = {};
      periods.forEach(p => { if (p.subject && p.subject !== "Free Period") sc[p.subject] = (sc[p.subject] || 0) + 1; });
      for (const [subj, count] of Object.entries(sc)) {
        if (count > 2) duplicateWarnings++;
      }
    }
  }
  test(s4, "No subject 3+ times in single day", duplicateWarnings === 0, `${duplicateWarnings} warnings`);

  // ═══════════════════════════════════════════════════════════════
  const s5 = section("Teacher Duties Sync");
  console.log("\n━━━ 5. TEACHER DUTIES SYNC ━━━");
  // ═══════════════════════════════════════════════════════════════

  const teacherIds = ["TEA0001","TEA0002","TEA0003","TEA0004","TEA0005","TEA0006","TEA0007","TEA0008","TEA0009"];
  for (const tid of teacherIds) {
    const duties = (await rtdb.ref(`Schools/${SC}/${S}/Teachers/${tid}/Duties/Teaching`).once("value")).val();
    test(s5, `${tid} has Duties`, !!duties);

    // Check duty matches timetable
    if (duties) {
      let dutySubjects = new Set();
      for (const [cls, secs] of Object.entries(duties)) {
        for (const [sec, subs] of Object.entries(secs || {})) {
          for (const sub of Object.keys(subs || {})) dutySubjects.add(`${cls}/${sec}/${sub}`);
        }
      }
      test(s5, `${tid}: ${dutySubjects.size} duty entries`, dutySubjects.size > 0);
    }
  }

  // Cross-check: every timetable teacher has Duty
  let missingDuties = 0;
  for (const doc of ttDocs.docs) {
    const data = doc.data();
    for (const periods of Object.values(data.schedule || {})) {
      for (const p of periods) {
        if (!p.teacherId || p.subject === "Free Period") continue;
        const cls = "Class " + data.className;
        const sec = data.sectionKey || ("Section " + data.section);
        const duty = (await rtdb.ref(`Schools/${SC}/${S}/Teachers/${p.teacherId}/Duties/Teaching/${cls}/${sec}/${p.subject}`).once("value")).val();
        if (!duty) missingDuties++;
      }
    }
  }
  test(s5, "All timetable teachers have matching Duties", missingDuties === 0, `${missingDuties} missing`);

  // ═══════════════════════════════════════════════════════════════
  const s6 = section("Curriculum");
  console.log("\n━━━ 6. CURRICULUM ━━━");
  // ═══════════════════════════════════════════════════════════════

  const curDocs = await namedFs.collection(`schools/${SC}/curriculum`).get();
  test(s6, "Curriculum docs exist", curDocs.size > 0, `got ${curDocs.size}`);
  let validCur = 0;
  curDocs.docs.forEach(d => {
    const data = d.data();
    if (Array.isArray(data.topics) && data.topics.length > 0) validCur++;
  });
  test(s6, `${validCur}/${curDocs.size} docs have topics`, validCur > 0);

  // RTDB curriculum match
  const rtdbCur = (await rtdb.ref(`Schools/${SC}/${S}/Academic/Curriculum`).once("value")).val();
  test(s6, "RTDB curriculum exists", !!rtdbCur);

  // ═══════════════════════════════════════════════════════════════
  const s7 = section("Academic Calendar");
  console.log("\n━━━ 7. ACADEMIC CALENDAR ━━━");
  // ═══════════════════════════════════════════════════════════════

  const calDocs = await namedFs.collection(`schools/${SC}/academicCalendar`).get();
  test(s7, "Calendar events exist", calDocs.size > 0, `got ${calDocs.size}`);

  let holidays = 0, exams = 0, events = 0;
  calDocs.docs.forEach(d => {
    const type = d.data().eventType;
    if (type === "holiday") holidays++;
    else if (type === "exam") exams++;
    else events++;
  });
  test(s7, `Holidays: ${holidays}`, holidays >= 5);
  test(s7, `Exams: ${exams}`, exams >= 3);
  test(s7, `Events/activities: ${events}`, events >= 2);

  const rtdbCal = (await rtdb.ref(`Schools/${SC}/${S}/Academic/Calendar`).once("value")).val();
  test(s7, "RTDB calendar exists", !!rtdbCal);
  test(s7, "RTDB ↔ Firestore count match", Object.keys(rtdbCal || {}).length === calDocs.size, `RTDB=${Object.keys(rtdbCal||{}).length} FS=${calDocs.size}`);

  // ═══════════════════════════════════════════════════════════════
  const s8 = section("Teacher App Data Flow");
  console.log("\n━━━ 8. TEACHER APP DATA FLOW ━━━");
  // ═══════════════════════════════════════════════════════════════

  // Simulate getMyTimetableFromAll() for each teacher
  for (const tid of teacherIds) {
    let periods = 0;
    const classes = new Set();
    ttDocs.docs.forEach(d => {
      const data = d.data();
      for (const ps of Object.values(data.schedule || {})) {
        for (const p of ps) {
          if (p.teacherId === tid) { periods++; classes.add(`${data.className}${data.section}`); }
        }
      }
    });
    test(s8, `${tid}: ${periods} periods in ${classes.size} classes`, periods > 0);
  }

  // Simulate getAssignedClasses() from Duties
  for (const tid of ["TEA0003", "TEA0005"]) {
    const duties = (await rtdb.ref(`Schools/${SC}/${S}/Teachers/${tid}/Duties/Teaching`).once("value")).val() || {};
    const classSections = [];
    for (const [cls, secs] of Object.entries(duties)) {
      for (const sec of Object.keys(secs || {})) classSections.push(`${cls}/${sec}`);
    }
    test(s8, `${tid} getAssignedClasses: ${classSections.length} class-sections`, classSections.length > 0);
  }

  // ═══════════════════════════════════════════════════════════════
  const s9 = section("Parent App Data Flow");
  console.log("\n━━━ 9. PARENT APP DATA FLOW ━━━");
  // ═══════════════════════════════════════════════════════════════

  // Simulate student → timetable lookup
  for (const stuId of ["STU0008", "STU0010"]) {
    const stuDoc = await namedFs.collection(`users/${SC}/students`).doc(stuId).get();
    if (!stuDoc.exists) { test(s9, `${stuId} exists in Firestore`, false); continue; }
    const stuData = stuDoc.data();
    const className = stuData.className || "";
    const section = stuData.section || "";
    test(s9, `${stuId}: class=${className} section=${section}`, className && section);

    // Build timetable doc ID
    const cls = className.startsWith("Class ") ? className : "Class " + className;
    const sec = section.startsWith("Section ") ? section : "Section " + section;
    const docId = `${S}_${cls}_${sec}`;
    const ttDoc = await namedFs.doc(`schools/${SC}/timetables/${docId}`).get();
    test(s9, `${stuId} timetable doc: ${docId}`, ttDoc.exists);
    if (ttDoc.exists) {
      const days = Object.keys(ttDoc.data().schedule || {});
      test(s9, `${stuId} timetable has ${days.length} days`, days.length === 6);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  const s10 = section("MongoDB Teacher Data");
  console.log("\n━━━ 10. MONGODB TEACHER DATA ━━━");
  // ═══════════════════════════════════════════════════════════════

  for (const tid of ["TEA0003", "TEA0005", "TEA0007"]) {
    const user = await User.findOne({ userId: tid });
    test(s10, `${tid} exists in MongoDB`, !!user);
    if (user) {
      test(s10, `${tid} has classesAssigned`, Array.isArray(user.classesAssigned) && user.classesAssigned.length > 0, `got ${(user.classesAssigned||[]).length}`);
      test(s10, `${tid} has subjects`, Array.isArray(user.subjects) && user.subjects.length > 0, `got ${(user.subjects||[]).length}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // FINAL REPORT
  // ═══════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
  console.log("║  ACADEMIC PLANNER — HEALTH CHECK SCORE REPORT                       ║");
  console.log("╠══════════════════════════════════════════════════════════════════════╣");

  let totalPass = 0, totalAll = 0;
  for (const [name, s] of Object.entries(scores)) {
    const pct = s.total > 0 ? Math.round((s.pass / s.total) * 100) : 0;
    const bar = "█".repeat(Math.floor(pct / 5)) + "░".repeat(20 - Math.floor(pct / 5));
    totalPass += s.pass; totalAll += s.total;
    console.log(`║  ${name.padEnd(22)} ${bar} ${String(pct).padStart(3)}%  (${s.pass}/${s.total})${s.fail > 0 ? "  ❌ " + s.fail : "  ✅"}  ║`);
  }

  const totalPct = Math.round((totalPass / totalAll) * 100);
  console.log("╠══════════════════════════════════════════════════════════════════════╣");
  console.log(`║  OVERALL                 ${"█".repeat(Math.floor(totalPct / 5))}${"░".repeat(20 - Math.floor(totalPct / 5))} ${String(totalPct).padStart(3)}%  (${totalPass}/${totalAll})                    ║`);
  console.log("╚══════════════════════════════════════════════════════════════════════╝");

  await mongoose.disconnect();
  process.exit(totalPct === 100 ? 0 : 1);
}

main().catch(e => { console.error("FATAL:", e); process.exit(1); });
