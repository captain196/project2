/**
 * FRESH SETUP SCRIPT
 *
 * Cleans ALL existing data and creates 3 new schools with full user hierarchy.
 * Standard password for all users: Test1234
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

// Initialize Firebase before anything else
initFirebase();
const rtdb = getFirebaseDb();
const firestoreDb = getFirestore();

const STANDARD_PASSWORD = "Test1234";

// ── School definitions ──────────────────────────────────────────

const SCHOOLS = [
  {
    code: "SCH_SCHOOL01",
    loginCode: "10001",
    name: "Delhi Public School",
    address: "Sector 24, Gurugram, Haryana",
    board: "CBSE",
    phone: "+911234567890",
    session: "2025-2026",
    classes: ["Class 1st", "Class 2nd", "Class 3rd", "Class 4th", "Class 5th",
              "Class 6th", "Class 7th", "Class 8th", "Class 9th", "Class 10th"],
    sections: ["Section A", "Section B"],
  },
  {
    code: "SCH_SCHOOL02",
    loginCode: "10002",
    name: "St. Mary's Convent School",
    address: "Civil Lines, Jabalpur, MP",
    board: "CBSE",
    phone: "+919876543210",
    session: "2025-2026",
    classes: ["Class 1st", "Class 2nd", "Class 3rd", "Class 4th", "Class 5th",
              "Class 6th", "Class 7th", "Class 8th", "Class 9th", "Class 10th"],
    sections: ["Section A", "Section B"],
  },
  {
    code: "SCH_SCHOOL03",
    loginCode: "10003",
    name: "Greenfield International Academy",
    address: "Whitefield, Bangalore, Karnataka",
    board: "ICSE",
    phone: "+918765432190",
    session: "2025-2026",
    classes: ["Class 1st", "Class 2nd", "Class 3rd", "Class 4th", "Class 5th",
              "Class 6th", "Class 7th", "Class 8th", "Class 9th", "Class 10th"],
    sections: ["Section A", "Section B"],
  },
];

// ── User definitions per school ─────────────────────────────────

function buildUsers(school, startIdx) {
  const s = startIdx;
  return [
    // School Super Admin
    {
      userId: `SSA${String(s).padStart(4, "0")}`,
      name: `${school.name.split(" ")[0]} Super Admin`,
      email: `ssa${s}@schoolsync.test`,
      phone: `+9190000000${s}0`,
      role: "school_super_admin",
      schoolId: school.loginCode,
      schoolCode: school.code,
      system: "Admin Panel",
    },
    // Admin
    {
      userId: `ADM${String(s).padStart(4, "0")}`,
      name: `${school.name.split(" ")[0]} Admin`,
      email: `adm${s}@schoolsync.test`,
      phone: `+9190000000${s}1`,
      role: "admin",
      schoolId: school.loginCode,
      schoolCode: school.code,
      system: "Admin Panel",
    },
    // Teachers (2 per school)
    {
      userId: `TEA${String(s * 2 - 1).padStart(4, "0")}`,
      name: `Teacher ${school.name.split(" ")[0]} A`,
      email: `tea${s * 2 - 1}@schoolsync.test`,
      phone: `+9190000000${s}2`,
      role: "teacher",
      schoolId: school.loginCode,
      schoolCode: school.code,
      position: "Class Teacher",
      department: "Academics",
      classesAssigned: ["Class 8th/Section A"],
      subjects: ["Mathematics", "Science"],
      system: "Teacher App",
    },
    {
      userId: `TEA${String(s * 2).padStart(4, "0")}`,
      name: `Teacher ${school.name.split(" ")[0]} B`,
      email: `tea${s * 2}@schoolsync.test`,
      phone: `+9190000000${s}3`,
      role: "teacher",
      schoolId: school.loginCode,
      schoolCode: school.code,
      position: "Subject Teacher",
      department: "Academics",
      classesAssigned: ["Class 9th/Section A"],
      subjects: ["English", "Hindi"],
      system: "Teacher App",
    },
    // Students (3 per school)
    {
      userId: `STU${String(s * 3 - 2).padStart(4, "0")}`,
      name: `Student ${school.name.split(" ")[0]} Alpha`,
      email: `parent${s * 3 - 2}@schoolsync.test`,
      phone: `+9190000000${s}4`,
      role: "student",
      schoolId: school.loginCode,
      schoolCode: school.code,
      className: "Class 8th",
      section: "Section A",
      rollNo: "01",
      fatherName: `Father of Alpha ${s}`,
      motherName: `Mother of Alpha ${s}`,
      gender: "Male",
      parentDbKey: school.loginCode,
      system: "Parent App",
    },
    {
      userId: `STU${String(s * 3 - 1).padStart(4, "0")}`,
      name: `Student ${school.name.split(" ")[0]} Beta`,
      email: `parent${s * 3 - 1}@schoolsync.test`,
      phone: `+9190000000${s}5`,
      role: "student",
      schoolId: school.loginCode,
      schoolCode: school.code,
      className: "Class 8th",
      section: "Section A",
      rollNo: "02",
      fatherName: `Father of Beta ${s}`,
      motherName: `Mother of Beta ${s}`,
      gender: "Female",
      parentDbKey: school.loginCode,
      system: "Parent App",
    },
    {
      userId: `STU${String(s * 3).padStart(4, "0")}`,
      name: `Student ${school.name.split(" ")[0]} Gamma`,
      email: `parent${s * 3}@schoolsync.test`,
      phone: `+9190000000${s}6`,
      role: "student",
      schoolId: school.loginCode,
      schoolCode: school.code,
      className: "Class 9th",
      section: "Section A",
      rollNo: "01",
      fatherName: `Father of Gamma ${s}`,
      motherName: `Mother of Gamma ${s}`,
      gender: "Male",
      parentDbKey: school.loginCode,
      system: "Parent App",
    },
  ];
}

// ── Firebase path builder ───────────────────────────────────────

function getFbPath(role, schoolId, userId) {
  if (role === "super_admin") return `Users/Admin/Our Panel/${userId}`;
  if (role === "teacher") return `Users/Teachers/${schoolId}/${userId}`;
  if (role === "student") return `Users/Parents/${schoolId}/${userId}`;
  return `Users/Admin/${schoolId}/${userId}`;
}

// ── Main ────────────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║  SCHOOLSYNC FRESH SETUP — FULL DATA RESET   ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  // ── Connect MongoDB (must use same dbName as server: graderIQ) ──
  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("✅ Connected to MongoDB (graderIQ)\n");

  // ── PHASE 1: CLEAN EVERYTHING ──
  console.log("🗑️  PHASE 1: Cleaning all existing data...\n");

  // MongoDB
  const userCount = await User.countDocuments();
  const otpCount = await Otp.countDocuments();
  await User.deleteMany({});
  await Otp.deleteMany({});
  await Counter.deleteMany({});
  console.log(`   MongoDB: Deleted ${userCount} users, ${otpCount} OTPs, all counters`);

  // Firebase RTDB — clean user paths
  const pathsToClean = [
    "Users/Admin",
    "Users/Teachers",
    "Users/Parents",
    "Presence",
    "NotifBadge",
    "Indexes/School_codes",
  ];
  for (const path of pathsToClean) {
    try {
      await rtdb.ref(path).remove();
      console.log(`   Firebase RTDB: Cleaned ${path}`);
    } catch (e) {
      console.log(`   Firebase RTDB: ${path} — ${e.message}`);
    }
  }

  // Clean school data for our 3 schools
  for (const school of SCHOOLS) {
    try {
      await rtdb.ref(`Schools/${school.code}`).remove();
      await rtdb.ref(`System/Schools/${school.code}`).remove();
      console.log(`   Firebase RTDB: Cleaned Schools/${school.code}`);
    } catch (e) {
      console.log(`   Firebase RTDB: ${school.code} — ${e.message}`);
    }
  }

  // Firestore — clean user-related collections
  const fsCollections = ["users", "staff", "students", "parents"];
  for (const col of fsCollections) {
    try {
      const snap = await firestoreDb.collection(col).limit(500).get();
      const batch = firestoreDb.batch();
      snap.docs.forEach((doc) => batch.delete(doc.ref));
      if (snap.size > 0) {
        await batch.commit();
        console.log(`   Firestore: Cleaned ${snap.size} docs from ${col}`);
      }
    } catch (e) {
      console.log(`   Firestore: ${col} — ${e.message}`);
    }
  }

  console.log("\n   ✅ All data cleaned.\n");

  // ── PHASE 2: CREATE SUPER ADMIN ──
  console.log("👑 PHASE 2: Creating Super Admin...\n");

  const hashedPw = await hashPassword(STANDARD_PASSWORD);

  const superAdmin = {
    userId: "SUP0001",
    name: "Yugant Verma",
    email: "yugant196@gmail.com",
    phone: "+919131879380",
    role: "super_admin",
    schoolId: null,
    schoolCode: null,
    password: hashedPw,
    status: "Active",
    createdAt: new Date(),
    createdBy: "system",
    refreshTokens: [],
    devices: [],
    loginAttempts: 0,
    lockedUntil: null,
  };

  await User.create(superAdmin);
  await rtdb.ref(`Users/Admin/Our Panel/SUP0001`).set({
    Status: "Active",
    Name: superAdmin.name,
    Email: superAdmin.email,
    Role: "Super Admin",
    Credentials: { Id: "SUP0001", Password: hashedPw },
    Profile: { name: superAdmin.name, email: superAdmin.email, phone: superAdmin.phone, role: "super_admin" },
    AccessHistory: { SA_LastLogin: null, LoginAttempts: 0 },
    is_primary: true,
  });

  console.log(`   SUP0001 — ${superAdmin.name} (Super Admin) → Admin Panel\n`);

  // ── PHASE 3: CREATE SCHOOLS ──
  console.log("🏫 PHASE 3: Creating 3 schools...\n");

  for (const school of SCHOOLS) {
    // System/Schools/{code} — subscription + profile
    await rtdb.ref(`System/Schools/${school.code}`).set({
      profile: {
        school_name: school.name,
        address: school.address,
        board: school.board,
        phone: school.phone,
        status: "Active",
      },
      subscription: {
        status: "Active",
        plan: "Premium",
        expiry_date: "2027-03-31",
        grace_end: "2027-04-30",
        features: ["attendance", "fees", "marks", "homework", "communication", "transport", "gallery", "stories", "events"],
      },
      stats_cache: { student_count: 3, teacher_count: 2, admin_count: 2 },
    });

    // Schools/{code} — main school data
    await rtdb.ref(`Schools/${school.code}`).set({
      Sessions: [school.session],
      Config: { ActiveSession: school.session },
      Classes: school.classes.reduce((acc, c) => { acc[c] = true; return acc; }, {}),
      Sections: school.sections.reduce((acc, s) => { acc[s] = true; return acc; }, {}),
    });

    // Create class/section structure
    for (const cls of school.classes) {
      for (const sec of school.sections) {
        await rtdb.ref(`Schools/${school.code}/${school.session}/${cls}/${sec}`).set({ _placeholder: true });
      }
    }

    // Index: School_codes/{loginCode} → school code
    await rtdb.ref(`Indexes/School_codes/${school.loginCode}`).set(school.code);

    console.log(`   ${school.code} — ${school.name} (${school.board}) — Login: ${school.loginCode}`);
  }

  // ── PHASE 4: CREATE ALL USERS ──
  console.log("\n👥 PHASE 4: Creating users for all schools...\n");

  const allUsers = [];
  const counterState = { SSA: 0, ADM: 0, TEA: 0, STU: 0 };

  for (let i = 0; i < SCHOOLS.length; i++) {
    const school = SCHOOLS[i];
    const users = buildUsers(school, i + 1);
    console.log(`   ── ${school.name} ──`);

    for (const u of users) {
      // MongoDB
      const mongoDoc = {
        userId: u.userId,
        name: u.name,
        email: u.email.toLowerCase(),
        phone: u.phone,
        role: u.role,
        schoolId: u.schoolId,
        schoolCode: u.schoolCode,
        password: hashedPw,
        status: "Active",
        createdAt: new Date(),
        createdBy: "fresh-setup",
        refreshTokens: [],
        devices: [],
        loginAttempts: 0,
        lockedUntil: null,
        ...(u.className ? { className: u.className } : {}),
        ...(u.section ? { section: u.section } : {}),
        ...(u.rollNo ? { rollNo: u.rollNo } : {}),
        ...(u.fatherName ? { fatherName: u.fatherName } : {}),
        ...(u.motherName ? { motherName: u.motherName } : {}),
        ...(u.gender ? { gender: u.gender } : {}),
        ...(u.parentDbKey ? { parentDbKey: u.parentDbKey } : {}),
        ...(u.position ? { position: u.position } : {}),
        ...(u.department ? { department: u.department } : {}),
        ...(u.classesAssigned ? { classesAssigned: u.classesAssigned } : {}),
        ...(u.subjects ? { subjects: u.subjects } : {}),
      };

      await User.create(mongoDoc);

      // Firebase RTDB
      const fbPath = getFbPath(u.role, u.schoolId, u.userId);
      const fbData = {
        Status: "Active",
        Name: u.name,
        Email: u.email,
        Role: u.role === "school_super_admin" ? "School Super Admin" :
              u.role === "admin" ? "Admin" :
              u.role === "teacher" ? "Teacher" : "Student",
        Credentials: { Id: u.userId, Password: hashedPw },
        Profile: {
          name: u.name, email: u.email, phone: u.phone, role: u.role,
          ...(u.className ? { className: u.className, section: u.section, rollNo: u.rollNo } : {}),
          ...(u.position ? { position: u.position, department: u.department } : {}),
        },
        AccessHistory: { SA_LastLogin: null, LoginAttempts: 0 },
      };
      await rtdb.ref(fbPath).set(fbData);

      // Firestore sync
      try {
        const fsCollection = (u.role === "teacher") ? "staff" :
                            (u.role === "student") ? "students" : "staff";
        await firestoreDb.collection(fsCollection).doc(u.userId).set({
          userId: u.userId,
          name: u.name,
          email: u.email,
          role: u.role,
          schoolId: u.schoolCode,
          status: "Active",
          ...(u.className ? { className: u.className, section: u.section } : {}),
          ...(u.position ? { position: u.position, department: u.department } : {}),
        }, { merge: true });

        await firestoreDb.collection("users").doc(u.userId).set({
          userId: u.userId, name: u.name, email: u.email,
          role: u.role, schoolId: u.schoolCode, status: "Active",
        }, { merge: true });
      } catch (_) {}

      // For students, also place in school structure
      if (u.role === "student" && u.className && u.section) {
        await rtdb.ref(`Schools/${u.schoolCode}/${school.session}/${u.className}/${u.section}/Students/${u.userId}`)
          .set({ Name: u.name, RollNo: u.rollNo, Status: "Active" });
      }

      const prefix = u.userId.substring(0, 3);
      const num = parseInt(u.userId.substring(3));
      if (num > (counterState[prefix] || 0)) counterState[prefix] = num;

      console.log(`   ${u.userId.padEnd(8)} — ${u.name.padEnd(35)} (${u.role.padEnd(20)}) → ${u.system}`);
      allUsers.push(u);
    }
    console.log();
  }

  // ── PHASE 5: SET COUNTERS ──
  console.log("🔢 PHASE 5: Setting ID counters...\n");
  const counterPrefixes = { SUP: 1, SSA: counterState.SSA, ADM: counterState.ADM, TEA: counterState.TEA, STU: counterState.STU };
  for (const [prefix, seq] of Object.entries(counterPrefixes)) {
    await Counter.findOneAndUpdate({ _id: prefix }, { seq }, { upsert: true });
    console.log(`   ${prefix} counter → ${seq}`);
  }

  // ── SUMMARY ──
  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║                    SETUP COMPLETE                            ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  Password for ALL users: Test1234                            ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  SCHOOLS:                                                    ║");
  for (const s of SCHOOLS) {
    console.log(`║  ${s.code} — ${s.name.padEnd(35)} Login: ${s.loginCode}  ║`);
  }
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log("║  USERS:                                                      ║");
  console.log(`║  SUP0001      — Super Admin               → Admin Panel      ║`);
  for (const u of allUsers) {
    console.log(`║  ${u.userId.padEnd(12)} — ${u.role.padEnd(22)} → ${u.system.padEnd(14)}║`);
  }
  console.log("╚══════════════════════════════════════════════════════════════╝");

  await mongoose.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error("❌ Setup failed:", err);
  process.exit(1);
});
