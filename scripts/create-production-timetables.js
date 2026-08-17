#!/usr/bin/env node
/**
 * Creates production-level timetable data for Class 7A, 8A, 8B, 9A, 9B
 * with realistic CBSE Indian school schedule.
 */
require("dotenv").config();
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const PT = [
  { s: "8:30", e: "9:15" }, { s: "9:15", e: "10:00" }, { s: "10:00", e: "10:45" },
  { s: "11:00", e: "11:45" }, { s: "11:45", e: "12:30" }, { s: "12:45", e: "1:30" },
];

// Teacher roster — realistic CBSE school allocation
const T = {
  // Core subject teachers (teach across multiple classes)
  "TEA0001": { name: "Anita Verma",      subjects: ["Mathematics", "Science"] },
  "TEA0002": { name: "Sanjay Tiwari",    subjects: ["English", "Hindi"] },
  "TEA0003": { name: "Neha Sharma",      subjects: ["English"] },
  "TEA0004": { name: "Amit Dubey",       subjects: ["Hindi", "Sanskrit"] },
  "TEA0005": { name: "Sunita Agarwal",   subjects: ["Mathematics"] },
  "TEA0006": { name: "Dr. Rakesh Jain",  subjects: ["Science"] },
  "TEA0007": { name: "Meena Patel",      subjects: ["Social Science"] },
  "TEA0008": { name: "Vikas Rathore",    subjects: ["Physical Education"] },
  "TEA0009": { name: "Priyanka Desai",   subjects: ["Computer Science"] },
};

// Realistic teacher-subject-class allocation (one teacher teaches same subject across classes)
const CLASSES = {
  "7A": {
    classLabel: "Class 7th", section: "Section A", classKey: "7", classTeacher: "TEA0002",
    subjects: {
      "English":          { tid: "TEA0003", pw: 6 },
      "Hindi":            { tid: "TEA0004", pw: 5 },
      "Sanskrit":         { tid: "TEA0004", pw: 3 },
      "Mathematics":      { tid: "TEA0005", pw: 6 },
      "Science":          { tid: "TEA0006", pw: 5 },
      "Social Science":   { tid: "TEA0007", pw: 5 },
      "Computer Science": { tid: "TEA0009", pw: 2 },
      "Physical Education":{ tid: "TEA0008", pw: 2 },
      "Art Education":    { tid: "TEA0002", pw: 2 },
    },
    timetable: {
      Monday:    ["Mathematics","English","Science","Hindi","Social Science","Computer Science"],
      Tuesday:   ["English","Mathematics","Hindi","Science","Sanskrit","Physical Education"],
      Wednesday: ["Science","Hindi","Mathematics","Social Science","English","Art Education"],
      Thursday:  ["Hindi","Science","Social Science","English","Mathematics","Sanskrit"],
      Friday:    ["Mathematics","Social Science","English","Science","Hindi","Art Education"],
      Saturday:  ["Social Science","Mathematics","Science","Sanskrit","English","Physical Education"],
    }
  },
  "8A": {
    classLabel: "Class 8th", section: "Section A", classKey: "8", classTeacher: "TEA0001",
    subjects: {
      "English":          { tid: "TEA0002", pw: 5 },
      "Hindi":            { tid: "TEA0004", pw: 5 },
      "Mathematics":      { tid: "TEA0001", pw: 6 },
      "Science":          { tid: "TEA0001", pw: 5 },
      "Social Science":   { tid: "TEA0007", pw: 5 },
      "Computer Science": { tid: "TEA0009", pw: 2 },
      "Sanskrit":         { tid: "TEA0004", pw: 2 },
      "Physical Education":{ tid: "TEA0008", pw: 2 },
    },
    timetable: {
      Monday:    ["Mathematics","English","Science","Hindi","Social Science","Computer Science"],
      Tuesday:   ["English","Science","Mathematics","Hindi","Computer Science","Social Science"],
      Wednesday: ["Science","Mathematics","Hindi","Social Science","English","Physical Education"],
      Thursday:  ["Hindi","English","Science","Mathematics","Social Science","Sanskrit"],
      Friday:    ["Mathematics","Hindi","English","Science","Mathematics","Physical Education"],
      Saturday:  ["Social Science","Science","Hindi","English","Sanskrit","Mathematics"],
    }
  },
  "8B": {
    classLabel: "Class 8th", section: "Section B", classKey: "8", classTeacher: "TEA0002",
    subjects: {
      "English":          { tid: "TEA0003", pw: 5 },
      "Hindi":            { tid: "TEA0002", pw: 5 },
      "Mathematics":      { tid: "TEA0005", pw: 6 },
      "Science":          { tid: "TEA0006", pw: 5 },
      "Social Science":   { tid: "TEA0007", pw: 5 },
      "Computer Science": { tid: "TEA0009", pw: 2 },
      "Sanskrit":         { tid: "TEA0004", pw: 2 },
      "Physical Education":{ tid: "TEA0008", pw: 2 },
    },
    timetable: {
      Monday:    ["English","Mathematics","Science","Social Science","Hindi","Sanskrit"],
      Tuesday:   ["Mathematics","Hindi","English","Science","Computer Science","Physical Education"],
      Wednesday: ["Science","English","Mathematics","Hindi","Social Science","Computer Science"],
      Thursday:  ["Hindi","Science","Social Science","English","Mathematics","Physical Education"],
      Friday:    ["Mathematics","Social Science","Hindi","Science","English","Sanskrit"],
      Saturday:  ["Social Science","Mathematics","English","Hindi","Science","Mathematics"],
    }
  },
  "9A": {
    classLabel: "Class 9th", section: "Section A", classKey: "9", classTeacher: "TEA0005",
    subjects: {
      "English":          { tid: "TEA0003", pw: 6 },
      "Hindi":            { tid: "TEA0004", pw: 5 },
      "Mathematics":      { tid: "TEA0005", pw: 6 },
      "Science":          { tid: "TEA0006", pw: 6 },
      "Social Science":   { tid: "TEA0007", pw: 5 },
      "Sanskrit":         { tid: "TEA0004", pw: 2 },
      "Computer Science": { tid: "TEA0009", pw: 2 },
      "Physical Education":{ tid: "TEA0008", pw: 2 },
    },
    timetable: {
      Monday:    ["Mathematics","Science","English","Hindi","Social Science","Computer Science"],
      Tuesday:   ["Science","English","Mathematics","Social Science","Hindi","Physical Education"],
      Wednesday: ["English","Mathematics","Science","Hindi","Sanskrit","Social Science"],
      Thursday:  ["Hindi","Science","Mathematics","English","Social Science","Sanskrit"],
      Friday:    ["Mathematics","Hindi","Science","English","Mathematics","Physical Education"],
      Saturday:  ["Social Science","Science","English","Mathematics","Hindi","Computer Science"],
    }
  },
  "9B": {
    classLabel: "Class 9th", section: "Section B", classKey: "9", classTeacher: "TEA0006",
    subjects: {
      "English":          { tid: "TEA0002", pw: 6 },
      "Hindi":            { tid: "TEA0004", pw: 5 },
      "Mathematics":      { tid: "TEA0001", pw: 6 },
      "Science":          { tid: "TEA0006", pw: 6 },
      "Social Science":   { tid: "TEA0007", pw: 5 },
      "Sanskrit":         { tid: "TEA0004", pw: 2 },
      "Computer Science": { tid: "TEA0009", pw: 2 },
      "Physical Education":{ tid: "TEA0008", pw: 2 },
    },
    timetable: {
      Monday:    ["Science","Mathematics","English","Social Science","Hindi","Sanskrit"],
      Tuesday:   ["Mathematics","English","Science","Hindi","Social Science","Computer Science"],
      Wednesday: ["English","Science","Hindi","Mathematics","Sanskrit","Physical Education"],
      Thursday:  ["Hindi","Mathematics","Social Science","Science","English","Physical Education"],
      Friday:    ["Science","Hindi","Mathematics","English","Social Science","Computer Science"],
      Saturday:  ["Mathematics","Social Science","English","Science","Hindi","Mathematics"],
    }
  },
};

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  CREATING PRODUCTION TIMETABLES — 5 Classes                ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  for (const [key, cls] of Object.entries(CLASSES)) {
    console.log(`━━━ ${cls.classLabel} / ${cls.section} (${key}) ━━━`);

    // 1. Subject Assignments — RTDB + Firestore
    const saData = {};
    const fsAssignments = [];
    let code = parseInt(cls.classKey) * 1000;
    for (const [subj, info] of Object.entries(cls.subjects)) {
      code++;
      saData[code] = {
        name: subj, category: ["Sanskrit","Computer Science","Physical Education","Art Education"].includes(subj) ? "Skill" : "Core",
        periods_week: info.pw, teacher_id: info.tid, teacher_name: T[info.tid].name,
      };
      fsAssignments.push({
        subjectCode: String(code), subjectName: subj,
        category: saData[code].category, periodsWeek: info.pw,
        teacherId: info.tid, teacherName: T[info.tid].name,
      });
    }

    // Only write subject assignments if this is section A (assignments are per-class, not per-section)
    if (cls.section === "Section A") {
      await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/${cls.classKey}`).set(saData);
      await namedFs.collection(`schools/${SC}/subjectAssignments`).doc(`${S}_${cls.classKey}`).set({
        schoolId: SC, session: S, className: cls.classKey + "th", classKey: cls.classKey,
        assignments: fsAssignments, updatedAt: new Date(),
      });
      console.log(`  ✅ Subject assignments: ${Object.keys(saData).length} subjects`);
    }

    // 2. Timetable — RTDB
    const rtdbTt = {};
    for (const [day, periods] of Object.entries(cls.timetable)) {
      rtdbTt[day] = periods.map(subj => {
        const info = cls.subjects[subj];
        return { subject: subj, teacher_id: info.tid, teacher_name: T[info.tid].name };
      });
    }
    await rtdb.ref(`Schools/${SC}/${S}/${cls.classLabel}/${cls.section}/Time_table`).set(rtdbTt);

    // 3. Timetable — Firestore
    const fsTt = {};
    for (const [day, periods] of Object.entries(cls.timetable)) {
      fsTt[day] = periods.map((subj, i) => {
        const info = cls.subjects[subj];
        return {
          period: i + 1, subject: subj, teacherId: info.tid, teacherName: T[info.tid].name,
          startTime: PT[i].s, endTime: PT[i].e, room: "", type: "class",
        };
      });
    }
    const secLetter = cls.section.replace("Section ", "");
    await namedFs.collection(`schools/${SC}/timetables`).doc(`${S}_${cls.classLabel}_${cls.section}`).set({
      schoolId: SC, session: S, className: cls.classKey + "th", section: secLetter, sectionKey: cls.section,
      schedule: fsTt, updatedBy: "production-setup", updatedAt: new Date(),
    });

    // 4. Teacher Duties — RTDB (for each teacher in this class+section)
    for (const [subj, info] of Object.entries(cls.subjects)) {
      await rtdb.ref(`Schools/${SC}/${S}/Teachers/${info.tid}/Duties/Teaching/${cls.classLabel}/${cls.section}/${subj}`).set("assigned");
    }

    console.log(`  ✅ Timetable: 6 days × 6 periods`);
    console.log(`  ✅ Duties: ${Object.keys(cls.subjects).length} teacher assignments`);
    console.log("");
  }

  // Verify
  console.log("━━━ VERIFICATION ━━━\n");
  const ttDocs = await namedFs.collection(`schools/${SC}/timetables`).get();
  console.log("Firestore timetable docs: " + ttDocs.size);
  ttDocs.docs.forEach(d => {
    const data = d.data();
    const totalP = Object.values(data.schedule || {}).reduce((s, ps) => s + ps.length, 0);
    console.log("  " + d.id + ": " + totalP + " periods");
  });

  // Teacher workload summary
  console.log("\n━━━ TEACHER WORKLOAD ━━━\n");
  for (const [tid, info] of Object.entries(T)) {
    let total = 0;
    const classes = new Set();
    ttDocs.docs.forEach(d => {
      const data = d.data();
      for (const ps of Object.values(data.schedule || {})) {
        for (const p of ps) {
          if (p.teacherId === tid) { total++; classes.add(data.className + " " + data.section); }
        }
      }
    });
    if (total > 0) {
      console.log(`  ${tid} ${info.name.padEnd(20)} ${total} periods/week across ${[...classes].join(", ")}`);
    }
  }

  process.exit(0);
}

main().catch(e => { console.error("FATAL:", e); process.exit(1); });
