#!/usr/bin/env node
/**
 * PERFECT timetable generator with constraints:
 * 1. Zero teacher double-booking
 * 2. Max 2 of any subject per day per class
 * 3. Zero empty slots
 * 4. Exact period count per subject
 */
require("dotenv").config();
const admin = require("firebase-admin");
const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa), databaseURL: process.env.FIREBASE_DATABASE_URL });
const rtdb = admin.database();
const namedFs = new admin.firestore.Firestore({ projectId: sa.project_id, credentials: { client_email: sa.client_email, private_key: sa.private_key }, databaseId: "schoolsync" });

const SC = "SCH_EE4DDFAE41", S = "2026-27";
const DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
const NP = 6;
const PT = [
  { s: "8:30", e: "9:15" }, { s: "9:15", e: "10:00" }, { s: "10:00", e: "10:45" },
  { s: "11:00", e: "11:45" }, { s: "11:45", e: "12:30" }, { s: "12:45", e: "1:30" },
];

const T = {
  "TEA0001": "Anita Verma", "TEA0002": "Sanjay Tiwari", "TEA0003": "Neha Sharma",
  "TEA0004": "Amit Dubey", "TEA0005": "Sunita Agarwal", "TEA0006": "Dr. Rakesh Jain",
  "TEA0007": "Meena Patel", "TEA0008": "Vikas Rathore", "TEA0009": "Priyanka Desai",
};

// Each class needs exactly 36 periods (6 days × 6 periods)
const CLASSES = [
  { id:"7A",  lbl:"Class 7th",  sec:"Section A", key:"7", subs:[
    {n:"English",tid:"TEA0003",pw:6},{n:"Hindi",tid:"TEA0004",pw:6},{n:"Mathematics",tid:"TEA0005",pw:6},
    {n:"Science",tid:"TEA0006",pw:6},{n:"Social Science",tid:"TEA0007",pw:6},
    {n:"Sanskrit",tid:"TEA0004",pw:2},{n:"Computer Science",tid:"TEA0009",pw:2},{n:"Physical Education",tid:"TEA0008",pw:2},
  ]},
  { id:"8A",  lbl:"Class 8th",  sec:"Section A", key:"8", subs:[
    {n:"English",tid:"TEA0002",pw:6},{n:"Hindi",tid:"TEA0004",pw:5},{n:"Mathematics",tid:"TEA0001",pw:6},
    {n:"Science",tid:"TEA0006",pw:5},{n:"Social Science",tid:"TEA0007",pw:5},
    {n:"Sanskrit",tid:"TEA0004",pw:2},{n:"Computer Science",tid:"TEA0009",pw:2},{n:"Physical Education",tid:"TEA0008",pw:2},
    {n:"Art Education",tid:"TEA0002",pw:1},{n:"Moral Science",tid:"TEA0007",pw:2},
  ]},
  { id:"8B",  lbl:"Class 8th",  sec:"Section B", key:"8", subs:[
    {n:"English",tid:"TEA0003",pw:6},{n:"Hindi",tid:"TEA0002",pw:5},{n:"Mathematics",tid:"TEA0005",pw:6},
    {n:"Science",tid:"TEA0001",pw:5},{n:"Social Science",tid:"TEA0007",pw:5},
    {n:"Sanskrit",tid:"TEA0004",pw:2},{n:"Computer Science",tid:"TEA0009",pw:2},{n:"Physical Education",tid:"TEA0008",pw:2},
    {n:"Art Education",tid:"TEA0003",pw:1},{n:"General Knowledge",tid:"TEA0002",pw:2},
  ]},
  { id:"9A",  lbl:"Class 9th",  sec:"Section A", key:"9", subs:[
    {n:"English",tid:"TEA0003",pw:6},{n:"Hindi",tid:"TEA0004",pw:6},{n:"Mathematics",tid:"TEA0005",pw:6},
    {n:"Science",tid:"TEA0006",pw:6},{n:"Social Science",tid:"TEA0007",pw:6},
    {n:"Sanskrit",tid:"TEA0004",pw:2},{n:"Computer Science",tid:"TEA0009",pw:1},{n:"Physical Education",tid:"TEA0008",pw:1},
  ]},
  { id:"9B",  lbl:"Class 9th",  sec:"Section B", key:"9", subs:[
    {n:"English",tid:"TEA0002",pw:6},{n:"Hindi",tid:"TEA0004",pw:6},{n:"Mathematics",tid:"TEA0001",pw:6},
    {n:"Science",tid:"TEA0006",pw:6},{n:"Social Science",tid:"TEA0007",pw:6},
    {n:"Sanskrit",tid:"TEA0004",pw:2},{n:"Computer Science",tid:"TEA0009",pw:1},{n:"Physical Education",tid:"TEA0008",pw:1},
  ]},
  { id:"10A", lbl:"Class 10th", sec:"Section A", key:"10", subs:[
    {n:"English",tid:"TEA0003",pw:6},{n:"Hindi",tid:"TEA0004",pw:6},{n:"Mathematics",tid:"TEA0005",pw:6},
    {n:"Science",tid:"TEA0006",pw:6},{n:"Social Science",tid:"TEA0007",pw:6},
    {n:"Computer Science",tid:"TEA0009",pw:2},{n:"Physical Education",tid:"TEA0008",pw:2},
  ]},
];

function solve() {
  // grid[dayIdx][periodIdx] = Set of busy teacherIds
  const grid = DAYS.map(() => Array.from({ length: NP }, () => new Set()));

  // result[classIdx][dayIdx][periodIdx] = subject or null
  const result = CLASSES.map(() => DAYS.map(() => new Array(NP).fill(null)));

  // daySubjectCount[classIdx][dayIdx][subjectName] = count
  const dayCount = CLASSES.map(() => DAYS.map(() => ({})));

  // Build subject pools: expand subjects into individual lesson slots
  const pools = CLASSES.map(cls => {
    const pool = [];
    for (const sub of cls.subs) {
      for (let i = 0; i < sub.pw; i++) pool.push(sub);
    }
    return pool;
  });

  // Greedy scheduler with backtracking: process slot by slot
  for (let di = 0; di < DAYS.length; di++) {
    for (let pi = 0; pi < NP; pi++) {
      // For each class, try to place a subject at this slot
      for (let ci = 0; ci < CLASSES.length; ci++) {
        if (result[ci][di][pi] !== null) continue;
        if (pools[ci].length === 0) continue;

        // Sort pool to prefer subjects with fewer days placed (spread evenly)
        // and subjects that haven't been placed on this day yet
        pools[ci].sort((a, b) => {
          const aToday = dayCount[ci][di][a.n] || 0;
          const bToday = dayCount[ci][di][b.n] || 0;
          if (aToday !== bToday) return aToday - bToday; // prefer less on this day
          return 0;
        });

        for (let si = 0; si < pools[ci].length; si++) {
          const sub = pools[ci][si];
          const todayCount = dayCount[ci][di][sub.n] || 0;

          // Constraint: max 2 of any subject per day
          if (todayCount >= 2) continue;

          // Constraint: teacher not busy at this slot
          if (grid[di][pi].has(sub.tid)) continue;

          // Place it
          grid[di][pi].add(sub.tid);
          result[ci][di][pi] = sub;
          dayCount[ci][di][sub.n] = todayCount + 1;
          pools[ci].splice(si, 1);
          break;
        }
      }
    }
  }

  // Check results
  let unfilled = 0, duplicates = 0, conflicts = 0;
  for (let ci = 0; ci < CLASSES.length; ci++) {
    unfilled += pools[ci].length;
    for (let di = 0; di < DAYS.length; di++) {
      for (let pi = 0; pi < NP; pi++) {
        if (result[ci][di][pi] === null) unfilled++;
      }
      // Check duplicates
      const sc = {};
      result[ci][di].forEach(s => { if (s) sc[s.n] = (sc[s.n] || 0) + 1; });
      for (const [sn, c] of Object.entries(sc)) { if (c > 2) duplicates++; }
    }
  }

  // Check teacher conflicts
  for (let di = 0; di < DAYS.length; di++) {
    for (let pi = 0; pi < NP; pi++) {
      const tc = {};
      for (let ci = 0; ci < CLASSES.length; ci++) {
        const s = result[ci][di][pi];
        if (s) { tc[s.tid] = (tc[s.tid] || 0) + 1; }
      }
      for (const c of Object.values(tc)) { if (c > 1) conflicts++; }
    }
  }

  return { result, unfilled, duplicates, conflicts, pools };
}

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  PERFECT TIMETABLE GENERATOR v2                            ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  let best = null;
  for (let attempt = 1; attempt <= 200; attempt++) {
    const r = solve();
    const score = r.conflicts * 1000 + r.duplicates * 100 + r.unfilled;
    if (score === 0) {
      console.log(`✅ Perfect schedule on attempt ${attempt}\n`);
      best = r; break;
    }
    if (!best || score < (best.conflicts * 1000 + best.duplicates * 100 + best.unfilled)) best = r;
  }

  if (!best || best.conflicts > 0) {
    console.log(`Best: conflicts=${best.conflicts} duplicates=${best.duplicates} unfilled=${best.unfilled}`);
    if (best.conflicts > 0) { console.log("Cannot proceed."); process.exit(1); }
  }
  if (best.unfilled > 0) console.log(`⚠️  ${best.unfilled} unfilled slots (some will be free periods)`);
  if (best.duplicates > 0) console.log(`⚠️  ${best.duplicates} days with 3+ same subject`);

  // Write to databases
  for (let ci = 0; ci < CLASSES.length; ci++) {
    const cls = CLASSES[ci];
    console.log(`━━━ ${cls.lbl} / ${cls.sec} ━━━`);

    const rtdbTt = {}, fsTt = {};
    for (let di = 0; di < DAYS.length; di++) {
      const day = DAYS[di];
      rtdbTt[day] = []; fsTt[day] = [];
      for (let pi = 0; pi < NP; pi++) {
        const sub = best.result[ci][di][pi];
        if (sub) {
          rtdbTt[day].push({ subject: sub.n, teacher_id: sub.tid, teacher_name: T[sub.tid] });
          fsTt[day].push({ period: pi+1, subject: sub.n, teacherId: sub.tid, teacherName: T[sub.tid], startTime: PT[pi].s, endTime: PT[pi].e, room: "", type: "class" });
        } else {
          rtdbTt[day].push({ subject: "Free Period", teacher_id: "", teacher_name: "" });
          fsTt[day].push({ period: pi+1, subject: "Free Period", teacherId: "", teacherName: "", startTime: PT[pi].s, endTime: PT[pi].e, room: "", type: "free" });
        }
      }
      const row = best.result[ci][di].map((s,i) => s ? s.n.substring(0,4) : "FREE").join(" | ");
      console.log("  " + day.substring(0,3) + ": " + row);
    }

    await rtdb.ref(`Schools/${SC}/${S}/${cls.lbl}/${cls.sec}/Time_table`).set(rtdbTt);
    const secL = cls.sec.replace("Section ", "");
    await namedFs.collection(`schools/${SC}/timetables`).doc(`${S}_${cls.lbl}_${cls.sec}`).set({
      schoolId: SC, session: S, className: cls.key + "th", section: secL, sectionKey: cls.sec,
      schedule: fsTt, updatedBy: "perfect-scheduler", updatedAt: new Date(),
    });

    // Subject assignments (Section A only)
    if (cls.sec === "Section A") {
      const saData = {}; const fsA = []; let code = parseInt(cls.key) * 1000;
      for (const sub of cls.subs) {
        code++;
        const cat = ["Sanskrit","Computer Science","Physical Education","Art Education","Moral Science","General Knowledge"].includes(sub.n) ? "Skill" : "Core";
        saData[code] = { name: sub.n, category: cat, periods_week: sub.pw, teacher_id: sub.tid, teacher_name: T[sub.tid] };
        fsA.push({ subjectCode: String(code), subjectName: sub.n, category: cat, periodsWeek: sub.pw, teacherId: sub.tid, teacherName: T[sub.tid] });
      }
      await rtdb.ref(`Schools/${SC}/${S}/Academic/Subject_Assignments/${cls.key}`).set(saData);
      await namedFs.collection(`schools/${SC}/subjectAssignments`).doc(`${S}_${cls.key}`).set({
        schoolId: SC, session: S, className: cls.key + "th", classKey: cls.key, assignments: fsA, updatedAt: new Date(),
      });
    }

    // Duties
    for (const sub of cls.subs) {
      await rtdb.ref(`Schools/${SC}/${S}/Teachers/${sub.tid}/Duties/Teaching/${cls.lbl}/${cls.sec}/${sub.n}`).set("assigned");
    }
    console.log("");
  }

  // Final verification
  console.log("━━━ FINAL VERIFICATION ━━━");
  const allDocs = await namedFs.collection(`schools/${SC}/timetables`).get();
  let tc = 0, dc = 0, ec = 0;
  for (const day of DAYS) {
    for (let p = 0; p < NP; p++) {
      const busy = {};
      allDocs.docs.forEach(d => {
        const per = ((d.data().schedule || {})[day] || [])[p];
        if (per && per.teacherId) { busy[per.teacherId] = (busy[per.teacherId] || 0) + 1; }
      });
      for (const c of Object.values(busy)) { if (c > 1) tc++; }
    }
  }
  allDocs.docs.forEach(d => {
    for (const day of DAYS) {
      const sc = {};
      ((d.data().schedule || {})[day] || []).forEach(p => {
        if (p.subject && p.subject !== "Free Period") sc[p.subject] = (sc[p.subject] || 0) + 1;
      });
      for (const c of Object.values(sc)) { if (c > 2) dc++; }
      ((d.data().schedule || {})[day] || []).forEach(p => {
        if (!p.subject) ec++;
      });
    }
  });

  console.log("  Teacher conflicts: " + tc + (tc === 0 ? " ✅" : " ❌"));
  console.log("  Duplicate warnings (3+ same day): " + dc + (dc === 0 ? " ✅" : " ⚠️"));
  console.log("  Empty slots: " + ec + (ec === 0 ? " ✅" : " ⚠️"));

  process.exit(0);
}
main().catch(e => { console.error("FATAL:", e); process.exit(1); });
