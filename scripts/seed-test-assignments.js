/**
 * SEED TEST ASSIGNMENTS — Subject Assignments + Timetable for SchoolSync Test Academy
 * Creates subject assignments (THE BRIDGE) and timetable for test school.
 * Follows: Firestore FIRST → RTDB → MongoDB
 *
 * Usage: node scripts/seed-test-assignments.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const { initFirebase, getFirebaseDb, getFirestore } = require("../src/config/firebase");
const User = require("../src/models/User");
const fs = require("fs");
const path = require("path");

initFirebase();
const rtdb = getFirebaseDb();
const firestore = getFirestore();

// Load test school IDs
const ids = JSON.parse(fs.readFileSync(path.join(__dirname, "test-school-ids.json"), "utf8"));
const SCHOOL_CODE = ids.school.code;        // SCH0002
const LOGIN_CODE = ids.school.loginCode;     // 3
const SESSION = ids.school.session;          // 2026-27
const TEACHERS = ids.teachers;               // [{id, name, subjects}, ...]

// ─── Assignment Map: class → section → [{subject, teacherId, teacherName, periodsWeek}] ──

const ASSIGNMENTS = {
  "Class 8th": {
    "Section A": [
      { code: "801", name: "Mathematics",       teacherId: TEACHERS[0].id, teacherName: TEACHERS[0].name, periodsWeek: 6 },
      { code: "802", name: "English",           teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 5 },
      { code: "803", name: "Science",           teacherId: TEACHERS[0].id, teacherName: TEACHERS[0].name, periodsWeek: 5 },
      { code: "804", name: "Social Studies",    teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 4 },
      { code: "805", name: "Hindi",             teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 5 },
      { code: "806", name: "Computer Science",  teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 3 },
      { code: "807", name: "Physical Education",teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 2 },
      { code: "808", name: "Art",               teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 2 },
    ],
    "Section B": [
      { code: "801", name: "Mathematics",       teacherId: TEACHERS[0].id, teacherName: TEACHERS[0].name, periodsWeek: 6 },
      { code: "802", name: "English",           teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 5 },
      { code: "803", name: "Science",           teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 5 },
      { code: "804", name: "Social Studies",    teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 4 },
      { code: "805", name: "Hindi",             teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 5 },
      { code: "806", name: "Computer Science",  teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 3 },
      { code: "807", name: "Physical Education",teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 2 },
      { code: "808", name: "Art",               teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 2 },
    ],
  },
  "Class 9th": {
    "Section A": [
      { code: "901", name: "Mathematics",       teacherId: TEACHERS[0].id, teacherName: TEACHERS[0].name, periodsWeek: 6 },
      { code: "902", name: "English",           teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 5 },
      { code: "903", name: "Physics",           teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 4 },
      { code: "904", name: "Chemistry",         teacherId: TEACHERS[0].id, teacherName: TEACHERS[0].name, periodsWeek: 4 },
      { code: "905", name: "Biology",           teacherId: TEACHERS[3].id, teacherName: TEACHERS[3].name, periodsWeek: 4 },
      { code: "906", name: "Social Studies",    teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 4 },
      { code: "907", name: "Hindi",             teacherId: TEACHERS[1].id, teacherName: TEACHERS[1].name, periodsWeek: 3 },
      { code: "908", name: "Computer Science",  teacherId: TEACHERS[2].id, teacherName: TEACHERS[2].name, periodsWeek: 2 },
    ],
  },
};

// ─── Timetable Settings ──────────────────────────────────────────────────────

const TIMETABLE_SETTINGS = {
  periodsPerDay: 8,
  workingDays: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"],
  periods: [
    { number: 1, start: "08:00", end: "08:45", label: "Period 1" },
    { number: 2, start: "08:45", end: "09:30", label: "Period 2" },
    { number: 3, start: "09:30", end: "10:15", label: "Period 3" },
    { number: 4, start: "10:15", end: "11:00", label: "Period 4" },
    { number: "Break_1", start: "11:00", end: "11:20", label: "Recess", isBreak: true },
    { number: 5, start: "11:20", end: "12:05", label: "Period 5" },
    { number: 6, start: "12:05", end: "12:50", label: "Period 6" },
    { number: "Lunch", start: "12:50", end: "13:30", label: "Lunch Break", isBreak: true },
    { number: 7, start: "13:30", end: "14:15", label: "Period 7" },
    { number: 8, start: "14:15", end: "15:00", label: "Period 8" },
  ],
};

// ─── Simple Timetable Generator (no conflicts) ──────────────────────────────

function generateTimetable(className, section, assignments) {
  const days = TIMETABLE_SETTINGS.workingDays;
  const periodsPerDay = TIMETABLE_SETTINGS.periodsPerDay;
  const timetable = {};

  // Build a pool: repeat each subject by its periodsWeek
  const pool = [];
  for (const a of assignments) {
    for (let i = 0; i < a.periodsWeek; i++) {
      pool.push({ subject: a.name, teacher: a.teacherName, teacherId: a.teacherId, code: a.code });
    }
  }

  // Shuffle for variety
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }

  let poolIdx = 0;
  for (const day of days) {
    const periods = [];
    for (let p = 1; p <= periodsPerDay; p++) {
      if (poolIdx < pool.length) {
        const slot = pool[poolIdx++];
        periods.push({
          periodNumber: p,
          subject: slot.subject,
          subjectCode: slot.code,
          teacher: slot.teacher,
          teacherId: slot.teacherId,
          startTime: TIMETABLE_SETTINGS.periods.find(x => x.number === p)?.start || "",
          endTime: TIMETABLE_SETTINGS.periods.find(x => x.number === p)?.end || "",
          room: `Room ${className.replace("Class ", "").replace(/\w+$/, "")}${section.replace("Section ", "")}`,
        });
      } else {
        // Wrap around if pool exhausted
        const slot = pool[poolIdx % pool.length];
        poolIdx++;
        periods.push({
          periodNumber: p,
          subject: slot.subject,
          subjectCode: slot.code,
          teacher: slot.teacher,
          teacherId: slot.teacherId,
          startTime: TIMETABLE_SETTINGS.periods.find(x => x.number === p)?.start || "",
          endTime: TIMETABLE_SETTINGS.periods.find(x => x.number === p)?.end || "",
          room: `Room ${className.replace("Class ", "").replace(/\w+$/, "")}${section.replace("Section ", "")}`,
        });
      }
    }
    timetable[day] = periods;
  }
  return timetable;
}

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  SEED ASSIGNMENTS + TIMETABLE — SchoolSync Test Academy     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("✅ MongoDB connected\n");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: SUBJECT ASSIGNMENTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("📋 STEP 1: Subject Assignments...\n");

  const teacherDuties = {}; // teacherId → { classes: Set, subjects: Set }

  for (const [className, sections] of Object.entries(ASSIGNMENTS)) {
    const classKey = className.replace(/\s+/g, "_"); // Class_8th

    for (const [section, subjects] of Object.entries(sections)) {
      const sectionKey = `${className}/${section}`;
      console.log(`   ${sectionKey}:`);

      // Build assignment data
      const rtdbData = {};
      const fsList = [];

      for (const s of subjects) {
        rtdbData[s.code] = {
          name: s.name,
          category: "Core",
          periods_week: s.periodsWeek,
          teacher_id: s.teacherId,
          teacher_name: s.teacherName,
        };

        fsList.push({
          subjectCode: s.code,
          subjectName: s.name,
          category: "Core",
          periodsWeek: s.periodsWeek,
          teacherId: s.teacherId,
          teacherName: s.teacherName,
        });

        // Track teacher duties
        if (!teacherDuties[s.teacherId]) {
          teacherDuties[s.teacherId] = { classes: new Set(), subjects: new Set(), name: s.teacherName };
        }
        teacherDuties[s.teacherId].classes.add(sectionKey);
        teacherDuties[s.teacherId].subjects.add(s.name);

        console.log(`     ${s.name} → ${s.teacherName} (${s.periodsWeek} per/wk)`);
      }

      // 1a. FIRESTORE FIRST — subject assignments
      const fsDocId = `${SESSION}_${classKey}_${section.replace(/\s+/g, "_")}`;
      await firestore.collection("schools").doc(SCHOOL_CODE).collection("subjectAssignments").doc(fsDocId).set({
        schoolId: SCHOOL_CODE,
        session: SESSION,
        className,
        classKey,
        section,
        sectionKey,
        assignments: fsList,
        updatedAt: new Date(),
      });

      // 1b. RTDB — Academic/Subject_Assignments
      await rtdb.ref(`Schools/${SCHOOL_CODE}/${SESSION}/Academic/Subject_Assignments/${className}`).set(rtdbData);

      // 1c. RTDB — Teacher Duties/Teaching
      for (const s of subjects) {
        await rtdb.ref(
          `Schools/${SCHOOL_CODE}/${SESSION}/Teachers/${s.teacherId}/Duties/Teaching/${className}/${section}/${s.name}`
        ).set("assigned");
      }
    }
    console.log("");
  }

  // 1d. Sync classesAssigned + subjects to MongoDB for each teacher
  console.log("   Syncing teacher MongoDB profiles...");
  for (const [teacherId, duties] of Object.entries(teacherDuties)) {
    const classesArr = Array.from(duties.classes);
    const subjectsArr = Array.from(duties.subjects);

    await User.findOneAndUpdate(
      { userId: teacherId },
      { $set: { classesAssigned: classesArr, subjects: subjectsArr } }
    );

    // Also update Firestore teacher profile
    await firestore.collection("users").doc(SCHOOL_CODE).collection("teachers").doc(teacherId).update({
      classesAssigned: classesArr,
      subjects: subjectsArr,
    });

    console.log(`   ${teacherId} (${duties.name}): ${classesArr.length} classes, ${subjectsArr.length} subjects`);
  }
  console.log("");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: TIMETABLE SETTINGS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("⏰ STEP 2: Timetable Settings...\n");

  // Firestore FIRST
  await firestore.collection("schools").doc(SCHOOL_CODE).collection("timetableSettings").doc(SESSION).set({
    schoolId: SCHOOL_CODE,
    session: SESSION,
    ...TIMETABLE_SETTINGS,
    updatedAt: new Date(),
  });
  console.log("   ✅ Firestore: timetableSettings");

  // RTDB
  await rtdb.ref(`Schools/${SCHOOL_CODE}/${SESSION}/Time_table_settings`).set(TIMETABLE_SETTINGS);
  console.log("   ✅ RTDB: Time_table_settings\n");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: GENERATE TIMETABLES
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("📅 STEP 3: Generating Timetables...\n");

  for (const [className, sections] of Object.entries(ASSIGNMENTS)) {
    const classKey = className.replace(/\s+/g, "_");

    for (const [section, assignments] of Object.entries(sections)) {
      const timetable = generateTimetable(className, section, assignments);
      const sectionKey = `${className}/${section}`;

      // Firestore FIRST
      const ttDocId = `${SESSION}_${classKey}_${section.replace(/\s+/g, "_")}`;
      await firestore.collection("schools").doc(SCHOOL_CODE).collection("timetables").doc(ttDocId).set({
        schoolId: SCHOOL_CODE,
        session: SESSION,
        className,
        section,
        sectionKey,
        days: timetable,
        updatedAt: new Date(),
      });

      // RTDB
      for (const [day, periods] of Object.entries(timetable)) {
        await rtdb.ref(`Schools/${SCHOOL_CODE}/${SESSION}/${className}/${section}/Time_table/${day}`).set(periods);
      }

      const totalPeriods = Object.values(timetable).reduce((a, d) => a + d.length, 0);
      console.log(`   ${sectionKey}: ${Object.keys(timetable).length} days × ${assignments[0] ? timetable.Monday?.length : 0} periods = ${totalPeriods} slots`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DONE
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ✅ ASSIGNMENTS + TIMETABLE CREATED                         ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");

  for (const [tid, d] of Object.entries(teacherDuties)) {
    console.log(`║  ${tid} — ${d.name.padEnd(20)} ${Array.from(d.classes).length} classes, ${Array.from(d.subjects).length} subjects ║`);
  }

  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  Timetable: 8 periods/day, Mon-Sat, 2 breaks               ║");
  console.log("║  Assignments + Duties + MongoDB sync — ALL DONE             ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  await mongoose.disconnect();
  process.exit(0);
}

main().catch(e => { console.error("❌ FAILED:", e.message); console.error(e); process.exit(1); });
