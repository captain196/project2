/**
 * FRESH SETUP SCRIPT v2
 * Cleans ALL data across MongoDB + Firebase RTDB + Firestore.
 * Creates 3 schools with EVERY role, realistic events, and proper structure.
 * Password for all: Test1234
 *
 * Usage: node scripts/fresh-setup.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const { initFirebase, getFirebaseDb, getFirestore, admin } = require("../src/config/firebase");
const { hashPassword } = require("../src/utils/hash");
const User = require("../src/models/User");
const Otp = require("../src/models/Otp");
const Counter = require("../src/models/Counter");

initFirebase();
const rtdb = getFirebaseDb();
const fs = getFirestore();

const PW = "Test1234";

const ALL_FEATURES = [
  "Student Management", "Staff Management", "Class Management",
  "Fees Management", "Exam Management", "Notice and Announcement",
  "Account Management", "School Management"
];

const CLASSES = ["Class 1st","Class 2nd","Class 3rd","Class 4th","Class 5th",
  "Class 6th","Class 7th","Class 8th","Class 9th","Class 10th"];
const SECTIONS = ["Section A", "Section B"];
const SUBJECTS = ["Mathematics","Science","English","Hindi","Social Studies","Computer Science"];

const SCHOOLS = [
  { code: "SCH_SCHOOL01", login: "10001", name: "Delhi Public School", addr: "Sector 24, Gurugram, Haryana", board: "CBSE", phone: "+911234567890" },
  { code: "SCH_SCHOOL02", login: "10002", name: "St. Mary's Convent School", addr: "Civil Lines, Jabalpur, MP", board: "CBSE", phone: "+919876543210" },
  { code: "SCH_SCHOOL03", login: "10003", name: "Greenfield International Academy", addr: "Whitefield, Bangalore, Karnataka", board: "ICSE", phone: "+918765432190" },
];

const SESSION = "2025-2026";

// Per-school user templates (index 0=school1, 1=school2, 2=school3)
const STAFF_NAMES = [
  { ssa:"Rajesh Gupta", admin:"Shivam Rathore", principal:"Dr. Anand Sharma", vp:"Kavita Joshi", ac:"Deepak Pandey", hr:"Ritu Agarwal", accountant:"Ramesh Gupta", fo:"Pooja Mishra", librarian:"Manoj Tiwari", transport:"Dinesh Yadav", hostel:"Geeta Rawat", tea1:"Ravindra Jadeja", tea2:"Sunita Devi" },
  { ssa:"Fr. Joseph DSouza", admin:"Meera Sharma", principal:"Sr. Mary Thomas", vp:"Arvind Mathur", ac:"Prerna Saxena", hr:"Vinod Khatri", accountant:"Lakshmi Narayan", fo:"Sonal Mehra", librarian:"Suresh Choudhary", transport:"Kailash Meena", hostel:"Pushpa Devi", tea1:"Rakesh Sharma", tea2:"Anita Bhatt" },
  { ssa:"Vikram Singh", admin:"Nandini Rathore", principal:"Dr. Sunil Verma", vp:"Priya Patel", ac:"Amit Kumar", hr:"Neha Gupta", accountant:"Rohit Saxena", fo:"Divya Mehra", librarian:"Kiran Tiwari", transport:"Suresh Yadav", hostel:"Anita Rawat", tea1:"Mahendra Singh", tea2:"Preeti Bhatt" },
];

const STUDENT_NAMES = [
  ["Aarav Sharma","Ishita Gupta","Rohan Tiwari","Priya Singh","Arjun Patel","Kavya Verma","Vikash Yadav","Ananya Mishra"],
  ["Riya Choudhary","Sahil Meena","Tanvi Joshi","Aditya Rajput","Nisha Agarwal","Karan Mathur","Divya Saxena","Harsh Khatri"],
  ["Yuvraj Singh","Ankit Sharma","Priya Patel","Rahul Kumar","Neha Gupta","Amit Verma","Kavita Devi","Rohan Joshi"],
];

const EVENTS_TEMPLATE = [
  { title:"Annual Sports Day 2026", desc:"Inter-house sports competition featuring track and field, cricket, football, and basketball. All students Class 5th-10th participate. Parents welcome.", cat:"sports", loc:"School Playground", start:"2026-04-10", end:"2026-04-11", status:"scheduled", max:200 },
  { title:"Science Exhibition", desc:"Students showcase science projects and working models. External judges evaluate. Best 3 represent school at state level.", cat:"academic", loc:"School Auditorium", start:"2026-04-05", end:"2026-04-05", status:"scheduled", max:100 },
  { title:"Parent-Teacher Meeting", desc:"Quarterly PTM for Class 8th and 9th. Teachers discuss academic progress, attendance, and behavior. Report cards distributed.", cat:"academic", loc:"Respective Classrooms", start:"2026-03-28", end:"2026-03-28", status:"scheduled", max:0 },
  { title:"Cultural Fest - Rang Tarang", desc:"Annual cultural festival with dance, music, drama, and art. Theme: Heritage of India. Students perform in house groups.", cat:"cultural", loc:"School Auditorium & Open Ground", start:"2026-04-15", end:"2026-04-16", status:"scheduled", max:300 },
  { title:"Republic Day Celebration", desc:"Flag hoisting ceremony with patriotic songs, speeches, and NCC march past. Chief guest: District Education Officer.", cat:"event", loc:"Assembly Ground", start:"2026-01-26", end:"2026-01-26", status:"completed", max:0 },
  { title:"Annual Day Ceremony", desc:"Prize distribution, cultural performances, and chief guest address. Parents invited.", cat:"cultural", loc:"School Auditorium", start:"2026-03-15", end:"2026-03-15", status:"completed", max:500 },
  { title:"Inter-School Quiz Competition", desc:"Teams of 3 from each house compete in GK, science, math, and current affairs rounds.", cat:"academic", loc:"Conference Hall", start:"2026-04-20", end:"2026-04-20", status:"scheduled", max:50 },
];

function fbPath(role, schoolLogin, userId) {
  if (role === "super_admin") return `Users/Admin/Our Panel/${userId}`;
  if (role === "teacher") return `Users/Teachers/${schoolLogin}/${userId}`;
  if (role === "student") return `Users/Parents/${schoolLogin}/${userId}`;
  return `Users/Admin/${schoolLogin}/${userId}`;
}

async function main() {
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║  FRESH SETUP v2 — FULL NUCLEAR RESET            ║");
  console.log("╚══════════════════════════════════════════════════╝\n");

  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("✅ MongoDB connected (graderIQ)\n");

  const hashedPw = await hashPassword(PW);

  // ═══════════ PHASE 1: NUKE EVERYTHING ═══════════
  console.log("🗑️  PHASE 1: Nuking all data...\n");

  const delUsers = await User.countDocuments();
  await User.deleteMany({});
  await Otp.deleteMany({});
  await Counter.deleteMany({});
  console.log(`   MongoDB: ${delUsers} users, all OTPs, all counters — DELETED`);

  for (const p of ["Users","Presence","NotifBadge","Indexes"]) {
    await rtdb.ref(p).remove().catch(() => {});
    console.log(`   RTDB: ${p} — DELETED`);
  }
  // Delete ALL schools (old + new)
  const schoolSnap = await rtdb.ref("Schools").once("value");
  if (schoolSnap.val()) {
    for (const k of Object.keys(schoolSnap.val())) {
      await rtdb.ref(`Schools/${k}`).remove();
      console.log(`   RTDB: Schools/${k} — DELETED`);
    }
  }
  const sysSnap = await rtdb.ref("System/Schools").once("value");
  if (sysSnap.val()) {
    for (const k of Object.keys(sysSnap.val())) {
      await rtdb.ref(`System/Schools/${k}`).remove();
      console.log(`   RTDB: System/Schools/${k} — DELETED`);
    }
  }

  // Firestore — clean everything
  for (const col of ["users","staff","students","parents","events","stories","galleryAlbums","galleryMedia","attendance","attendanceSummary","homework","submissions","circulars","notifications","marks","results","exams","examSchedule","feeStructures","feeDemands","feeDefaulters","feeReceipts","leaveApplications","timetables","sections"]) {
    try {
      let snap = await fs.collection(col).limit(500).get();
      while (snap.size > 0) {
        const batch = fs.batch();
        snap.docs.forEach(d => batch.delete(d.ref));
        await batch.commit();
        console.log(`   Firestore: ${col} — ${snap.size} docs deleted`);
        snap = await fs.collection(col).limit(500).get();
      }
    } catch (_) {}
  }

  console.log("\n   ✅ Everything nuked.\n");

  // ═══════════ PHASE 2: SUPER ADMIN ═══════════
  console.log("👑 PHASE 2: Super Admin...\n");
  await createUser({ userId:"SUP0001", name:"Yugant Verma", email:"yugant196@gmail.com", phone:"+919131879380", role:"super_admin", schoolId:null, schoolCode:null }, hashedPw);
  await rtdb.ref("Users/Admin/Our Panel/SUP0001").set(fbProfile("SUP0001","Yugant Verma","yugant196@gmail.com","super_admin",hashedPw));
  console.log("   SUP0001 — Yugant Verma (Super Admin)\n");

  // ═══════════ PHASE 3: SCHOOLS ═══════════
  console.log("🏫 PHASE 3: Creating 3 schools...\n");

  const idCounters = { SSA:0, STA:0, TEA:0, STU:0 };
  const allUsers = [];

  for (let si = 0; si < SCHOOLS.length; si++) {
    const s = SCHOOLS[si];
    const names = STAFF_NAMES[si];
    const stuNames = STUDENT_NAMES[si];

    // System/Schools
    await rtdb.ref(`System/Schools/${s.code}`).set({
      profile: { school_name: s.name, address: s.addr, board: s.board, phone: s.phone, status: "Active" },
      subscription: { status: "Active", plan: "Premium", expiry_date: "2027-03-31", grace_end: "2027-04-30", features: ALL_FEATURES },
    });

    // Schools structure
    await rtdb.ref(`Schools/${s.code}`).update({
      Sessions: [SESSION], Config: { ActiveSession: SESSION },
      Classes: CLASSES.reduce((a,c)=>({...a,[c]:true}),{}),
      Sections: SECTIONS.reduce((a,sec)=>({...a,[sec]:true}),{}),
      Subjects: SUBJECTS.reduce((a,sub)=>({...a,[sub]:true}),{}),
    });

    // Class/Section structure
    for (const cls of CLASSES) {
      for (const sec of SECTIONS) {
        await rtdb.ref(`Schools/${s.code}/${SESSION}/${cls}/${sec}`).update({ _init: true });
      }
    }

    // Index
    await rtdb.ref(`Indexes/School_codes/${s.login}`).set(s.code);

    console.log(`   ${s.code} — ${s.name} (${s.board}) — Login: ${s.login}`);

    // ── Create ALL roles ──
    const roles = [
      { prefix:"SSA", role:"school_super_admin", name:names.ssa, pos:"School Super Admin", dept:"Administration" },
      { prefix:"STA", role:"admin", name:names.admin, pos:"Admin", dept:"Administration" },
      { prefix:"STA", role:"principal", name:names.principal, pos:"Principal", dept:"Administration", adminRole:"Principal" },
      { prefix:"STA", role:"vice_principal", name:names.vp, pos:"Vice Principal", dept:"Administration", adminRole:"Vice Principal" },
      { prefix:"STA", role:"academic_coordinator", name:names.ac, pos:"Academic Coordinator", dept:"Academics", adminRole:"Academic Coordinator" },
      { prefix:"STA", role:"hr_manager", name:names.hr, pos:"HR Manager", dept:"HR", adminRole:"HR Manager" },
      { prefix:"STA", role:"accountant", name:names.accountant, pos:"Accountant", dept:"Finance", adminRole:"Accountant" },
      { prefix:"STA", role:"front_office", name:names.fo, pos:"Front Office", dept:"Administration", adminRole:"Front Office" },
      { prefix:"STA", role:"librarian", name:names.librarian, pos:"Librarian", dept:"Library", adminRole:"Librarian" },
      { prefix:"STA", role:"transport_manager", name:names.transport, pos:"Transport Manager", dept:"Transport", adminRole:"Transport Manager" },
      { prefix:"STA", role:"hostel_warden", name:names.hostel, pos:"Hostel Warden", dept:"Hostel", adminRole:"Hostel Warden" },
      { prefix:"TEA", role:"teacher", name:names.tea1, pos:"Class Teacher", dept:"Academics", classes:["Class 8th/Section A"], subjects:["Mathematics","Science"] },
      { prefix:"TEA", role:"teacher", name:names.tea2, pos:"Subject Teacher", dept:"Academics", classes:["Class 9th/Section A"], subjects:["English","Hindi"] },
    ];

    for (const r of roles) {
      idCounters[r.prefix] = (idCounters[r.prefix] || 0) + 1;
      const uid = r.prefix + String(idCounters[r.prefix]).padStart(4, "0");
      const email = uid.toLowerCase() + "@schoolsync.test";

      await createUser({
        userId: uid, name: r.name, email, phone: `+9190000${String(si+1)}${String(idCounters[r.prefix]).padStart(3,"0")}`,
        role: r.role, schoolId: s.login, schoolCode: s.code,
        position: r.pos, department: r.dept, classesAssigned: r.classes, subjects: r.subjects,
      }, hashedPw);

      const fp = fbPath(r.role, s.login, uid);
      const displayRole = r.adminRole || (r.role === "school_super_admin" ? "School Super Admin" : r.role === "teacher" ? "Teacher" : "Admin");
      await rtdb.ref(fp).set(fbProfile(uid, r.name, email, displayRole, hashedPw, r.pos, r.dept));

      // Firestore staff
      await fs.collection("staff").doc(uid).set({ userId:uid, name:r.name, email, role:r.adminRole||r.role, schoolId:s.code, position:r.pos, department:r.dept, status:"Active" }, {merge:true});
      await fs.collection("users").doc(uid).set({ userId:uid, name:r.name, email, role:r.adminRole||r.role, schoolId:s.code, status:"Active" }, {merge:true});

      // Teachers path for dashboard
      if (r.role === "teacher") {
        await rtdb.ref(`Schools/${s.code}/${SESSION}/Teachers/${uid}`).set({ Name:r.name, Status:"Active" });
        await rtdb.ref(`Users/Teachers/${s.login}/${uid}`).set(fbProfile(uid, r.name, email, "Teacher", hashedPw, r.pos, r.dept));
      }

      allUsers.push({ uid, name:r.name, role:r.adminRole||r.role, school:s.name, system: r.role==="teacher"?"Teacher App":"Admin Panel" });
      console.log(`     ${uid} — ${r.name} (${r.adminRole||r.role})`);
    }

    // ── Students ──
    const classAssign = ["Class 8th","Class 8th","Class 8th","Class 8th","Class 9th","Class 9th","Class 9th","Class 9th"];
    const sectionAssign = ["Section A","Section A","Section B","Section B","Section A","Section A","Section B","Section B"];
    const genders = ["Male","Female","Male","Female","Male","Female","Male","Female"];

    for (let j = 0; j < stuNames.length; j++) {
      idCounters.STU = (idCounters.STU || 0) + 1;
      const uid = "STU" + String(idCounters.STU).padStart(4, "0");
      const email = `parent${idCounters.STU}@schoolsync.test`;
      const cls = classAssign[j], sec = sectionAssign[j], roll = String((j%4)+1).padStart(2,"0");

      await createUser({
        userId:uid, name:stuNames[j], email, phone:`+9190000${si+1}${String(50+j)}`,
        role:"student", schoolId:s.login, schoolCode:s.code,
        className:cls, section:sec, rollNo:roll,
        fatherName:`Father of ${stuNames[j].split(" ")[0]}`, motherName:`Mother of ${stuNames[j].split(" ")[0]}`,
        gender:genders[j], parentDbKey:s.login,
      }, hashedPw);

      const fp = fbPath("student", s.login, uid);
      await rtdb.ref(fp).set({...fbProfile(uid, stuNames[j], email, "Student", hashedPw), Profile:{name:stuNames[j],email,className:cls,section:sec,rollNo:roll,gender:genders[j]}});

      // SIS index
      await rtdb.ref(`Schools/${s.code}/SIS/Students_Index/${uid}`).set({ name:stuNames[j], class:cls, section:sec, rollNo:roll, gender:genders[j], status:"Active" });

      // Class structure
      await rtdb.ref(`Schools/${s.code}/${SESSION}/${cls}/${sec}/Students/${uid}`).set({ Name:stuNames[j], RollNo:roll, Status:"Active" });

      // Firestore
      await fs.collection("students").doc(uid).set({ userId:uid, name:stuNames[j], email, role:"student", schoolId:s.code, className:cls, section:sec, rollNo:roll, gender:genders[j], status:"Active" }, {merge:true});
      await fs.collection("users").doc(uid).set({ userId:uid, name:stuNames[j], email, role:"student", schoolId:s.code, status:"Active" }, {merge:true});

      allUsers.push({ uid, name:stuNames[j], role:"Student ("+cls+"/"+sec+")", school:s.name, system:"Parent App" });
      console.log(`     ${uid} — ${stuNames[j]} (${cls} ${sec})`);
    }

    // ── Events ──
    const now = new Date().toISOString();
    await rtdb.ref(`Schools/${s.code}/Events/Counters/Event`).set(EVENTS_TEMPLATE.length);
    for (let ei = 0; ei < EVENTS_TEMPLATE.length; ei++) {
      const e = EVENTS_TEMPLATE[ei];
      const eid = "EVT" + String(ei+1).padStart(4,"0");
      await rtdb.ref(`Schools/${s.code}/Events/List/${eid}`).set({
        title:e.title, description:e.desc, category:e.cat, location:e.loc,
        start_date:e.start, end_date:e.end, organizer:"Administration",
        max_participants:e.max, status:e.status, created_at:now, updated_at:now,
        created_by:"STA0001", created_by_name:"Admin",
      });
      await fs.collection("events").doc(`${eid}_${s.code}`).set({
        schoolId:s.code, session:SESSION, title:e.title, description:e.desc,
        category:e.cat, startDate:e.start, endDate:e.end, location:e.loc,
        status:e.status, mediaUrls:[], createdBy:"STA0001", createdAt:new Date(),
      });
    }
    console.log(`     ${EVENTS_TEMPLATE.length} events created\n`);
  }

  // ═══════════ PHASE 4: COUNTERS ═══════════
  console.log("🔢 PHASE 4: Counters...\n");
  for (const [p, v] of Object.entries({SUP:1, ...idCounters})) {
    await Counter.findOneAndUpdate({ _id: p }, { seq: v }, { upsert: true });
    console.log(`   ${p} → ${v}`);
  }

  // ═══════════ DONE ═══════════
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ALL DONE — Password: Test1234 for everyone                 ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  SCHOOLS                                                    ║");
  SCHOOLS.forEach(s => console.log(`║  ${s.code} — ${s.name.padEnd(35)} ${s.login} ║`));
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  USERS (" + (allUsers.length+1) + " total)                                         ║");
  console.log("║  SUP0001      Super Admin              Admin Panel          ║");
  allUsers.forEach(u => console.log(`║  ${u.uid.padEnd(12)}  ${u.role.padEnd(24)} ${u.system.padEnd(14)}║`));
  console.log("╚══════════════════════════════════════════════════════════════╝");

  await mongoose.disconnect();
  process.exit(0);
}

async function createUser(data, hashedPw) {
  await User.create({
    userId:data.userId, name:data.name, email:(data.email||"").toLowerCase(), phone:data.phone||null,
    role:data.role, schoolId:data.schoolId, schoolCode:data.schoolCode||null,
    password:hashedPw, status:"Active", createdAt:new Date(), createdBy:"fresh-setup",
    refreshTokens:[], devices:[], loginAttempts:0, lockedUntil:null,
    ...(data.className ? {className:data.className,section:data.section,rollNo:data.rollNo,fatherName:data.fatherName,motherName:data.motherName,gender:data.gender,parentDbKey:data.parentDbKey} : {}),
    ...(data.position ? {position:data.position,department:data.department} : {}),
    ...(data.classesAssigned ? {classesAssigned:data.classesAssigned} : {}),
    ...(data.subjects ? {subjects:data.subjects} : {}),
  });
}

function fbProfile(uid, name, email, role, hashedPw, pos, dept) {
  return {
    Status:"Active", Name:name, Email:email, Role:role,
    Credentials:{Id:uid, Password:hashedPw},
    Profile:{name, email, role, ...(pos?{position:pos}:{}), ...(dept?{department:dept}:{})},
    AccessHistory:{SA_LastLogin:null, LoginAttempts:0},
  };
}

main().catch(e => { console.error("❌ FAILED:", e); process.exit(1); });
