#!/usr/bin/env node
/**
 * Creates CONFLICT-FREE timetables for 6 classes.
 * No teacher is ever scheduled in 2 classes at the same time.
 */
require("dotenv").config();
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
const PERIODS = 6;
const PT = [
  { s: "8:30", e: "9:15" }, { s: "9:15", e: "10:00" }, { s: "10:00", e: "10:45" },
  { s: "11:00", e: "11:45" }, { s: "11:45", e: "12:30" }, { s: "12:45", e: "1:30" },
];

const T = {
  "TEA0001": "Anita Verma",
  "TEA0002": "Sanjay Tiwari",
  "TEA0003": "Neha Sharma",
  "TEA0004": "Amit Dubey",
  "TEA0005": "Sunita Agarwal",
  "TEA0006": "Dr. Rakesh Jain",
  "TEA0007": "Meena Patel",
  "TEA0008": "Vikas Rathore",
  "TEA0009": "Priyanka Desai",
};

// 6 classes, each needs 36 slots (6 days × 6 periods)
// Key constraint: same teacher can't be in 2 classes at the same day+period
const CLASSES = [
  { id: "7A",  label: "Class 7th",  sec: "Section A", key: "7",  subjects: [
    { name: "English",          tid: "TEA0003", pw: 6 },
    { name: "Hindi",            tid: "TEA0004", pw: 6 },
    { name: "Mathematics",      tid: "TEA0005", pw: 6 },
    { name: "Science",          tid: "TEA0006", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 6 },
    { name: "Sanskrit",         tid: "TEA0004", pw: 2 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
  ]},
  { id: "8A",  label: "Class 8th",  sec: "Section A", key: "8",  subjects: [
    { name: "English",          tid: "TEA0002", pw: 6 },
    { name: "Hindi",            tid: "TEA0004", pw: 4 },
    { name: "Mathematics",      tid: "TEA0001", pw: 6 },
    { name: "Science",          tid: "TEA0006", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 4 },
    { name: "Sanskrit",         tid: "TEA0004", pw: 2 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
    { name: "Art Education",    tid: "TEA0002", pw: 2 },
    { name: "Moral Science",    tid: "TEA0007", pw: 2 },
  ]},
  { id: "8B",  label: "Class 8th",  sec: "Section B", key: "8",  subjects: [
    { name: "English",          tid: "TEA0003", pw: 6 },
    { name: "Hindi",            tid: "TEA0002", pw: 4 },
    { name: "Mathematics",      tid: "TEA0005", pw: 6 },
    { name: "Science",          tid: "TEA0001", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 4 },
    { name: "Sanskrit",         tid: "TEA0004", pw: 2 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
    { name: "Art Education",    tid: "TEA0003", pw: 2 },
    { name: "General Knowledge",tid: "TEA0002", pw: 2 },
  ]},
  { id: "9A",  label: "Class 9th",  sec: "Section A", key: "9",  subjects: [
    { name: "English",          tid: "TEA0003", pw: 6 },
    { name: "Hindi",            tid: "TEA0004", pw: 6 },
    { name: "Mathematics",      tid: "TEA0005", pw: 6 },
    { name: "Science",          tid: "TEA0006", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 6 },
    { name: "Sanskrit",         tid: "TEA0004", pw: 2 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
  ]},
  { id: "9B",  label: "Class 9th",  sec: "Section B", key: "9",  subjects: [
    { name: "English",          tid: "TEA0002", pw: 6 },
    { name: "Hindi",            tid: "TEA0004", pw: 6 },
    { name: "Mathematics",      tid: "TEA0001", pw: 6 },
    { name: "Science",          tid: "TEA0006", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 6 },
    { name: "Sanskrit",         tid: "TEA0004", pw: 2 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
  ]},
  { id: "10A", label: "Class 10th", sec: "Section A", key: "10", subjects: [
    { name: "English",          tid: "TEA0003", pw: 6 },
    { name: "Hindi",            tid: "TEA0004", pw: 6 },
    { name: "Mathematics",      tid: "TEA0005", pw: 6 },
    { name: "Science",          tid: "TEA0006", pw: 6 },
    { name: "Social Science",   tid: "TEA0007", pw: 4 },
    { name: "Computer Science", tid: "TEA0009", pw: 2 },
    { name: "Physical Education",tid:"TEA0008", pw: 2 },
  ]},
];

function schedule() {
  // grid[day][period] = { teacherId → classId }
  const grid = {};
  for (const d of DAYS) {
    grid[d] = [];
    for (let p = 0; p < PERIODS; p++) grid[d].push({});
  }

  const result = {}; // classId → { day: [subject, subject, ...] }
  for (const cls of CLASSES) result[cls.id] = {};
  for (const cls of CLASSES) for (const d of DAYS) result[cls.id][d] = new Array(PERIODS).fill(null);

  // Build subject pool for each class: expand pw into individual lesson slots
  const pools = {};
  for (const cls of CLASSES) {
    pools[cls.id] = [];
    for (const sub of cls.subjects) {
      for (let i = 0; i < sub.pw; i++) pools[cls.id].push(sub);
    }
    // Shuffle for variety
    pools[cls.id].sort(() => Math.random() - 0.5);
  }

  // Assign slots: iterate day by day, period by period
  // For each slot, try each class in order
  for (const day of DAYS) {
    for (let p = 0; p < PERIODS; p++) {
      for (const cls of CLASSES) {
        if (result[cls.id][day][p] !== null) continue; // already filled
        if (pools[cls.id].length === 0) continue; // no more subjects

        // Find a subject whose teacher is FREE at this day+period
        let placed = false;
        for (let si = 0; si < pools[cls.id].length; si++) {
          const sub = pools[cls.id][si];
          if (!grid[day][p][sub.tid]) {
            // Teacher is free — place it
            grid[day][p][sub.tid] = cls.id;
            result[cls.id][day][p] = sub;
            pools[cls.id].splice(si, 1);
            placed = true;
            break;
          }
        }
        if (!placed) {
          // Couldn't place anything for this class at this slot — skip (will be filled in retry)
        }
      }
    }
  }

  // Second pass: fill remaining empty slots
  for (const cls of CLASSES) {
    for (const day of DAYS) {
      for (let p = 0; p < PERIODS; p++) {
        if (result[cls.id][day][p] !== null) continue;
        if (pools[cls.id].length === 0) continue;
        for (let si = 0; si < pools[cls.id].length; si++) {
          const sub = pools[cls.id][si];
          if (!grid[day][p][sub.tid]) {
            grid[day][p][sub.tid] = cls.id;
            result[cls.id][day][p] = sub;
            pools[cls.id].splice(si, 1);
            break;
          }
        }
      }
    }
  }

  // Check for unfilled
  let unfilled = 0;
  for (const cls of CLASSES) {
    const remaining = pools[cls.id].length;
    if (remaining > 0) {
      console.log(`  ⚠️  ${cls.id}: ${remaining} subjects couldn't be placed`);
      unfilled += remaining;
    }
  }

  // Verify zero conflicts
  let conflicts = 0;
  for (const day of DAYS) {
    for (let p = 0; p < PERIODS; p++) {
      const teacherCount = {};
      for (const cls of CLASSES) {
        const sub = result[cls.id][day][p];
        if (sub) {
          if (!teacherCount[sub.tid]) teacherCount[sub.tid] = [];
          teacherCount[sub.tid].push(cls.id);
        }
      }
      for (const [tid, classes] of Object.entries(teacherCount)) {
        if (classes.length > 1) {
          conflicts++;
          console.log(`  ❌ ${day} P${p+1}: ${tid} in ${classes.join(", ")}`);
        }
      }
    }
  }

  return { result, conflicts, unfilled };
}

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  CONFLICT-FREE TIMETABLE GENERATOR                        ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // Try multiple times to get a conflict-free schedule
  let best = null;
  for (let attempt = 1; attempt <= 50; attempt++) {
    const r = schedule();
    if (r.conflicts === 0 && r.unfilled === 0) {
      console.log(`✅ Perfect schedule found on attempt ${attempt}\n`);
      best = r;
      break;
    }
    if (!best || (r.conflicts + r.unfilled) < (best.conflicts + best.unfilled)) best = r;
  }

  if (!best || best.conflicts > 0 || best.unfilled > 0) {
    console.log(`⚠️  Best result: ${best.conflicts} conflicts, ${best.unfilled} unfilled`);
    if (best.conflicts > 0) { console.log("Cannot proceed with conflicts."); process.exit(1); }
  }

  // Write to databases
  for (const cls of CLASSES) {
    const tt = best.result[cls.id];
    console.log(`━━━ ${cls.label} / ${cls.sec} ━━━`);

    // Build RTDB + Firestore format
    const rtdbTt = {};
    const fsTt = {};
    for (const day of DAYS) {
      rtdbTt[day] = [];
      fsTt[day] = [];
      for (let p = 0; p < PERIODS; p++) {
        const sub = tt[day][p];
        if (sub) {
          rtdbTt[day].push({ subject: sub.name, teacher_id: sub.tid, teacher_name: T[sub.tid] });
          fsTt[day].push({ period: p+1, subject: sub.name, teacherId: sub.tid, teacherName: T[sub.tid], startTime: PT[p].s, endTime: PT[p].e, room: "", type: "class" });
        } else {
          rtdbTt[day].push({ subject: "", teacher_id: "", teacher_name: "" });
          fsTt[day].push({ period: p+1, subject: "", teacherId: "", teacherName: "", startTime: PT[p].s, endTime: PT[p].e, room: "", type: "class" });
        }
      }
    }

    await rtdb.ref(`Schools/${SC}/${S}/${cls.label}/${cls.sec}/Time_table`).set(rtdbTt);
    const secLetter = cls.sec.replace("Section ", "");
    await namedFs.collection(`schools/${SC}/timetables`).doc(`${S}_${cls.label}_${cls.sec}`).set({
      schoolId: SC, session: S, className: cls.key + "th", section: secLetter, sectionKey: cls.sec,
      schedule: fsTt, updatedBy: "auto-scheduler", updatedAt: new Date(),
    });

    // Subject assignments (only for Section A — per-class)
    if (cls.sec === "Section A") {
      const saData = {};
      const fsAsgn = [];
      let code = parseInt(cls.key) * 1000;
      for (const sub of cls.subjects) {
        code++;
        saData[code] = { name: sub.name, category: ["Sanskrit","Computer Science","Physical Education","Art Education","Moral Science","General Knowledge"].includes(sub.name) ? "Skill" : "Core", periods_week: sub.pw, teacher_id: sub.tid, teacher_name: T[sub.tid] };
        fsAsgn.push({ subjectCode: String(code), subjectName: sub.name, category: saData[code].category, periodsWeek: sub.pw, teacherId: sub.tid, teacherName: T[sub.tid] });
      }
      await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/${cls.key}`).set(saData);
      await namedFs.collection(`schools/${SC}/subjectAssignments`).doc(`${S}_${cls.key}`).set({
        schoolId: SC, session: S, className: cls.key + "th", classKey: cls.key, assignments: fsAsgn, updatedAt: new Date(),
      });
    }

    // Duties
    for (const sub of cls.subjects) {
      await rtdb.ref(`Schools/${SC}/${S}/Teachers/${sub.tid}/Duties/Teaching/${cls.label}/${cls.sec}/${sub.name}`).set("assigned");
    }

    // Print schedule
    for (const day of DAYS) {
      const row = tt[day].map((s, i) => s ? (s.name.substring(0,5) + "(" + s.tid.replace("TEA","T") + ")") : "-----").join(" | ");
      console.log("  " + day.substring(0,3) + ": " + row);
    }
    console.log("");
  }

  // Final conflict check
  console.log("━━━ FINAL CONFLICT CHECK ━━━");
  const allDocs = await namedFs.collection(`schools/${SC}/timetables`).get();
  let finalConflicts = 0;
  for (const day of DAYS) {
    for (let p = 0; p < PERIODS; p++) {
      const tc = {};
      allDocs.docs.forEach(d => {
        const periods = (d.data().schedule || {})[day] || [];
        if (periods[p]?.teacherId) {
          if (!tc[periods[p].teacherId]) tc[periods[p].teacherId] = [];
          tc[periods[p].teacherId].push(d.id);
        }
      });
      for (const [tid, cls] of Object.entries(tc)) {
        if (cls.length > 1) { finalConflicts++; console.log(`  ❌ ${day} P${p+1}: ${tid} in ${cls.join(", ")}`); }
      }
    }
  }
  console.log(finalConflicts === 0 ? "\n✅ ZERO CONFLICTS — All timetables are valid!" : `\n❌ ${finalConflicts} conflicts remain`);

  process.exit(0);
}

main().catch(e => { console.error("FATAL:", e); process.exit(1); });
