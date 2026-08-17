/**
 * SEED TEST SCHOOL — SchoolSync Test Academy
 * Creates a new isolated test school WITHOUT touching existing data.
 * Follows correct architecture: Firestore PRIMARY → RTDB cache → MongoDB auth
 *
 * Password for all test users: Test1234
 *
 * Usage: node scripts/seed-test-school.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const { initFirebase, getFirebaseDb, getFirestore } = require("../src/config/firebase");
const { hashPassword } = require("../src/utils/hash");
const User = require("../src/models/User");
const Counter = require("../src/models/Counter");

initFirebase();
const rtdb = getFirebaseDb();
const firestore = getFirestore();

const PW = "Test1234";

// ─── Test School Config ──────────────────────────────────────────────────────

const SCHOOL = {
  name: "SchoolSync Test Academy",
  city: "Bangalore",
  address: "100 MG Road, Indiranagar, Bangalore, Karnataka",
  board: "CBSE",
  phone: "+919999900000",
  email: "admin@schoolsynctest.edu",
};

const SESSION = "2026-27";

const CLASSES = [
  "Class 1st", "Class 2nd", "Class 3rd", "Class 4th", "Class 5th",
  "Class 6th", "Class 7th", "Class 8th", "Class 9th", "Class 10th",
];

// Only create sections for classes we'll actively test
const SECTIONS_MAP = {
  "Class 8th": ["Section A", "Section B"],
  "Class 9th": ["Section A", "Section B"],
  "Class 10th": ["Section A"],
};

const SUBJECT_CATALOG = {
  "Class 8th": [
    { code: "801", name: "Mathematics", category: "Core" },
    { code: "802", name: "English", category: "Core" },
    { code: "803", name: "Science", category: "Core" },
    { code: "804", name: "Social Studies", category: "Core" },
    { code: "805", name: "Hindi", category: "Core" },
    { code: "806", name: "Computer Science", category: "Core" },
    { code: "807", name: "Physical Education", category: "Core" },
    { code: "808", name: "Art", category: "Elective" },
  ],
  "Class 9th": [
    { code: "901", name: "Mathematics", category: "Core" },
    { code: "902", name: "English", category: "Core" },
    { code: "903", name: "Physics", category: "Core" },
    { code: "904", name: "Chemistry", category: "Core" },
    { code: "905", name: "Biology", category: "Core" },
    { code: "906", name: "Social Studies", category: "Core" },
    { code: "907", name: "Hindi", category: "Core" },
    { code: "908", name: "Computer Science", category: "Core" },
  ],
  "Class 10th": [
    { code: "1001", name: "Mathematics", category: "Core" },
    { code: "1002", name: "English", category: "Core" },
    { code: "1003", name: "Physics", category: "Core" },
    { code: "1004", name: "Chemistry", category: "Core" },
    { code: "1005", name: "Biology", category: "Core" },
    { code: "1006", name: "Social Studies", category: "Core" },
    { code: "1007", name: "Hindi", category: "Core" },
    { code: "1008", name: "Computer Science", category: "Core" },
  ],
};

const TEACHERS = [
  { name: "Rajesh Kumar",   email: "rajesh.test@schoolsync.test",   phone: "+919900010001", dept: "Mathematics", subjects: ["Mathematics", "Science"] },
  { name: "Priya Sharma",   email: "priya.test@schoolsync.test",    phone: "+919900010002", dept: "Languages",   subjects: ["English", "Hindi"] },
  { name: "Amit Verma",     email: "amit.test@schoolsync.test",     phone: "+919900010003", dept: "Social",      subjects: ["Social Studies", "Computer Science"] },
  { name: "Neha Singh",     email: "neha.test@schoolsync.test",     phone: "+919900010004", dept: "Science",     subjects: ["Science", "Physical Education", "Art"] },
];

const STAFF = [
  { name: "Suresh Accountant", email: "suresh.test@schoolsync.test", phone: "+919900010005", role: "accountant", dept: "Finance", pos: "Accountant" },
  { name: "Kavita Librarian",  email: "kavita.test@schoolsync.test", phone: "+919900010006", role: "librarian",  dept: "Library",  pos: "Librarian" },
];

const STUDENTS_CLASS_8A = [
  { name: "Aarav Sharma",     father: "Vikram Sharma",   mother: "Sunita Sharma",   gender: "Male",   dob: "2013-05-15", roll: "01" },
  { name: "Ishita Gupta",     father: "Rajesh Gupta",    mother: "Priya Gupta",     gender: "Female", dob: "2013-08-22", roll: "02" },
  { name: "Rohan Tiwari",     father: "Dinesh Tiwari",   mother: "Meera Tiwari",    gender: "Male",   dob: "2013-03-10", roll: "03" },
  { name: "Kavya Verma",      father: "Sunil Verma",     mother: "Geeta Verma",     gender: "Female", dob: "2013-11-05", roll: "04" },
  { name: "Arjun Patel",      father: "Mahesh Patel",    mother: "Radha Patel",     gender: "Male",   dob: "2013-07-18", roll: "05" },
];

const STUDENTS_CLASS_8B = [
  { name: "Ananya Mishra",    father: "Prakash Mishra",  mother: "Rekha Mishra",    gender: "Female", dob: "2013-04-12", roll: "01" },
  { name: "Vikash Yadav",     father: "Ramesh Yadav",    mother: "Kamla Yadav",     gender: "Male",   dob: "2013-09-25", roll: "02" },
  { name: "Riya Choudhary",   father: "Deepak Choudhary",mother: "Savita Choudhary",gender: "Female", dob: "2013-01-30", roll: "03" },
  { name: "Sahil Meena",      father: "Lokesh Meena",    mother: "Pushpa Meena",    gender: "Male",   dob: "2013-06-08", roll: "04" },
  { name: "Tanvi Joshi",      father: "Amit Joshi",      mother: "Nidhi Joshi",     gender: "Female", dob: "2013-12-20", roll: "05" },
];

const STUDENTS_CLASS_9A = [
  { name: "Aditya Rajput",    father: "Suraj Rajput",    mother: "Laxmi Rajput",    gender: "Male",   dob: "2012-02-14", roll: "01" },
  { name: "Nisha Agarwal",    father: "Vivek Agarwal",   mother: "Seema Agarwal",   gender: "Female", dob: "2012-10-03", roll: "02" },
  { name: "Karan Mathur",     father: "Ravi Mathur",     mother: "Anjali Mathur",   gender: "Male",   dob: "2012-04-28", roll: "03" },
  { name: "Divya Saxena",     father: "Alok Saxena",     mother: "Rani Saxena",     gender: "Female", dob: "2012-07-16", roll: "04" },
  { name: "Harsh Khatri",     father: "Manoj Khatri",    mother: "Sita Khatri",     gender: "Male",   dob: "2012-11-09", roll: "05" },
];

// ─── Helper: Generate next ID from MongoDB counter ──────────────────────────

async function nextId(prefix) {
  const counter = await Counter.findOneAndUpdate(
    { _id: prefix },
    { $inc: { seq: 1 } },
    { upsert: true, new: true, returnDocument: "after" }
  );
  if (prefix === "SCHCODE") return String(counter.seq);
  return prefix + String(counter.seq).padStart(4, "0");
}

// ─── Helper: Firestore user collection path (role-aware) ────────────────────

function firestoreUserPath(role, schoolCode) {
  const map = {
    super_admin: `users/global/superadmins`,
    school_super_admin: `users/${schoolCode}/schoolsuperadmins`,
    admin: `users/${schoolCode}/admins`,
    principal: `users/${schoolCode}/staff`,
    vice_principal: `users/${schoolCode}/staff`,
    academic_coordinator: `users/${schoolCode}/staff`,
    hr_manager: `users/${schoolCode}/staff`,
    accountant: `users/${schoolCode}/staff`,
    front_office: `users/${schoolCode}/staff`,
    librarian: `users/${schoolCode}/staff`,
    transport_manager: `users/${schoolCode}/staff`,
    hostel_warden: `users/${schoolCode}/staff`,
    class_teacher: `users/${schoolCode}/teachers`,
    teacher: `users/${schoolCode}/teachers`,
    student: `users/${schoolCode}/students`,
    staff: `users/${schoolCode}/staff`,
  };
  return map[role] || `users/${schoolCode}/staff`;
}

// ─── Helper: RTDB user path ─────────────────────────────────────────────────

function rtdbUserPath(role, schoolLogin, userId) {
  if (role === "super_admin") return `Users/Admin/Our Panel/${userId}`;
  if (role === "teacher" || role === "class_teacher") return `Users/Teachers/${schoolLogin}/${userId}`;
  if (role === "student") return `Users/Parents/${schoolLogin}/${userId}`;
  return `Users/Admin/${schoolLogin}/${userId}`;
}

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  SEED TEST SCHOOL — SchoolSync Test Academy                 ║");
  console.log("║  Firestore PRIMARY → RTDB cache → MongoDB auth              ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("✅ MongoDB connected\n");

  const hashedPw = await hashPassword(PW);
  const created = { school: {}, users: [] };

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: CREATE SCHOOL
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("🏫 STEP 1: Creating school...\n");

  const schoolCode = await nextId("SCH");   // e.g., SCH0002
  const loginCode  = await nextId("SCHCODE"); // e.g., 10003
  const now = new Date().toISOString();

  created.school = { schoolCode, loginCode, name: SCHOOL.name };

  // 1a. FIRESTORE FIRST — school document under schools/{schoolCode}/
  const schoolRef = firestore.collection("schools").doc(schoolCode);
  await schoolRef.set({
    schoolCode,
    loginCode,
    schoolName: SCHOOL.name,
    address: SCHOOL.address,
    city: SCHOOL.city,
    board: SCHOOL.board,
    phone: SCHOOL.phone,
    email: SCHOOL.email,
    status: "Active",
    plan: "trial",
    createdAt: new Date(),
  });
  console.log(`   ✅ Firestore: schools/${schoolCode} — CREATED`);

  // 1b. RTDB — System/Schools/{schoolCode}/
  await rtdb.ref(`System/Schools/${schoolCode}`).set({
    profile: {
      school_name: SCHOOL.name, name: SCHOOL.name, school_id: schoolCode,
      school_code: loginCode, city: SCHOOL.city, address: SCHOOL.address,
      email: SCHOOL.email, phone: SCHOOL.phone, board: SCHOOL.board,
      firebase_key: schoolCode, status: "Active",
      created_at: now,
    },
    subscription: {
      status: "Active", plan_id: "trial", plan_name: "Trial",
      expiry_date: "2027-03-31", grace_end: "2027-04-30",
      features: ["Student Management", "Staff Management", "Class Management", "Fees Management", "Exam Management"],
    },
    stats_cache: { total_students: 0, total_staff: 0, last_updated: now },
  });
  console.log(`   ✅ RTDB: System/Schools/${schoolCode} — CREATED`);

  // 1c. RTDB — Schools/{schoolCode} base structure
  await rtdb.ref(`Schools/${schoolCode}`).update({
    Sessions: { [SESSION]: true },
    Config: { ActiveSession: SESSION },
  });

  // 1d. RTDB — Index login code → school code
  await rtdb.ref(`Indexes/School_codes/${loginCode}`).set(schoolCode);

  console.log(`   School: ${SCHOOL.name}`);
  console.log(`   Code: ${schoolCode} | Login: ${loginCode}\n`);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: SESSION + CLASSES + SECTIONS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("📚 STEP 2: Session, Classes, Sections...\n");

  // 2a. Firestore sessions
  await firestore.collection("schools").doc(schoolCode).collection("sessions").doc(SESSION).set({
    session: SESSION, status: "Active", startDate: "2026-04-01", endDate: "2027-03-31", createdAt: new Date(),
  });

  // 2b. Classes in Firestore + RTDB
  for (const cls of CLASSES) {
    const classKey = cls.replace(/\s+/g, "_"); // "Class_8th" for doc ID only

    // Firestore
    await firestore.collection("schools").doc(schoolCode).collection("classes").doc(classKey).set({
      className: cls, classKey, status: "Active", createdAt: new Date(),
    });

    // RTDB
    await rtdb.ref(`Schools/${schoolCode}/Config/Classes/${cls}`).set(true);
  }
  console.log(`   ✅ ${CLASSES.length} classes created`);

  // 2c. Sections in Firestore + RTDB
  let sectionCount = 0;
  for (const [cls, sections] of Object.entries(SECTIONS_MAP)) {
    for (const sec of sections) {
      const sectionKey = `${cls}/${sec}`; // "Class 8th/Section A"
      const sectionDocId = sectionKey.replace(/[\s\/]/g, "_"); // "Class_8th_Section_A" for Firestore doc ID

      // Firestore — under schools/{schoolCode}/sections/
      await firestore.collection("schools").doc(schoolCode).collection("sections").doc(sectionDocId).set({
        className: cls, section: sec, sectionKey, studentCount: 0, maxStrength: 40,
        schoolId: schoolCode, session: SESSION, status: "Active", createdAt: new Date(),
      });

      // RTDB
      await rtdb.ref(`Schools/${schoolCode}/${SESSION}/${cls}/${sec}`).update({ _init: true });
      sectionCount++;
    }
  }
  console.log(`   ✅ ${sectionCount} sections created\n`);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: SUBJECT CATALOG
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("📖 STEP 3: Subject catalog...\n");

  for (const [cls, subjects] of Object.entries(SUBJECT_CATALOG)) {
    const classKey = cls.replace(/\s+/g, "_");

    // Firestore — under schools/{schoolCode}/subjects/{classKey}
    await firestore.collection("schools").doc(schoolCode).collection("subjects").doc(classKey).set({
      className: cls, classKey, session: SESSION,
      list: subjects.map(s => ({ code: s.code, name: s.name, category: s.category })),
      createdAt: new Date(),
    });

    // RTDB — Schools/{schoolCode}/Subject_list/{classKey}/
    const rtdbSubjects = {};
    subjects.forEach(s => { rtdbSubjects[s.code] = { name: s.name, category: s.category }; });
    await rtdb.ref(`Schools/${schoolCode}/Subject_list/${cls}`).set(rtdbSubjects);

    console.log(`   ${cls}: ${subjects.map(s => s.name).join(", ")}`);
  }
  console.log("");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: SCHOOL SUPER ADMIN + ADMIN
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("👤 STEP 4: SSA + Admin...\n");

  // SSA
  const ssaId = await nextId("SSA");
  await createUserFull({
    userId: ssaId, name: "Test SSA", email: "ssa.test@schoolsync.test",
    phone: "+919900020001", role: "school_super_admin",
    schoolId: loginCode, schoolCode, position: "School Super Admin", department: "Administration",
  }, hashedPw, schoolCode, loginCode);
  console.log(`   ${ssaId} — Test SSA (School Super Admin)`);

  // Admin
  const adminId = await nextId("STA");
  await createUserFull({
    userId: adminId, name: "Test Admin", email: "admin.test@schoolsync.test",
    phone: "+919900020002", role: "admin",
    schoolId: loginCode, schoolCode, position: "Admin", department: "Administration",
  }, hashedPw, schoolCode, loginCode);
  console.log(`   ${adminId} — Test Admin (Admin)\n`);

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 5: TEACHERS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("👨‍🏫 STEP 5: Teachers...\n");

  const teacherIds = [];
  for (const t of TEACHERS) {
    const teacherId = await nextId("TEA");
    teacherIds.push(teacherId);

    await createUserFull({
      userId: teacherId, name: t.name, email: t.email, phone: t.phone,
      role: "teacher", schoolId: loginCode, schoolCode,
      position: "Teacher", department: t.dept,
      classesAssigned: [], subjects: [],
    }, hashedPw, schoolCode, loginCode);

    // Session roster in RTDB
    await rtdb.ref(`Schools/${schoolCode}/${SESSION}/Teachers/${teacherId}`).set({
      Name: t.name, Status: "Active",
    });

    console.log(`   ${teacherId} — ${t.name} (${t.dept})`);
  }
  console.log("");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 6: NON-TEACHING STAFF
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("👥 STEP 6: Staff...\n");

  for (const s of STAFF) {
    const staffId = await nextId("STA");
    await createUserFull({
      userId: staffId, name: s.name, email: s.email, phone: s.phone,
      role: s.role, schoolId: loginCode, schoolCode,
      position: s.pos, department: s.dept,
    }, hashedPw, schoolCode, loginCode);
    console.log(`   ${staffId} — ${s.name} (${s.role})`);
  }
  console.log("");

  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 7: STUDENTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("🎓 STEP 7: Students...\n");

  const allStudents = [
    { list: STUDENTS_CLASS_8A, cls: "Class 8th", sec: "Section A" },
    { list: STUDENTS_CLASS_8B, cls: "Class 8th", sec: "Section B" },
    { list: STUDENTS_CLASS_9A, cls: "Class 9th", sec: "Section A" },
  ];

  for (const group of allStudents) {
    for (const stu of group.list) {
      const studentId = await nextId("STU");

      // MongoDB
      await User.create({
        userId: studentId, name: stu.name, email: `${studentId.toLowerCase()}@schoolsync.test`,
        phone: `+9199000${studentId.replace("STU", "")}`, role: "student",
        schoolId: loginCode, schoolCode, password: hashedPw,
        className: group.cls, section: group.sec, rollNo: stu.roll,
        fatherName: stu.father, motherName: stu.mother,
        gender: stu.gender, dob: stu.dob,
        parentDbKey: loginCode,
        status: "Active", createdAt: new Date(), createdBy: "seed-test-school",
        refreshTokens: [], devices: [], loginAttempts: 0, lockedUntil: null,
      });

      // Firestore — schools/{schoolCode}/students/ (PRIMARY student data)
      await firestore.collection("schools").doc(schoolCode).collection("students").doc(studentId).set({
        userId: studentId, name: stu.name, email: `${studentId.toLowerCase()}@schoolsync.test`,
        phone: `+9199000${studentId.replace("STU", "")}`,
        className: group.cls, section: group.sec, rollNo: stu.roll,
        fatherName: stu.father, motherName: stu.mother,
        gender: stu.gender, dob: stu.dob,
        schoolId: schoolCode, session: SESSION,
        profilePicUrl: "", status: "Active", createdAt: new Date(),
      });

      // Firestore — users/{schoolCode}/students/ (auth profile)
      await firestore.collection("users").doc(schoolCode).collection("students").doc(studentId).set({
        userId: studentId, name: stu.name, email: `${studentId.toLowerCase()}@schoolsync.test`,
        role: "student", schoolId: schoolCode, status: "Active", createdAt: new Date(),
      });

      // RTDB — Users/Parents/{loginCode}/{studentId}
      await rtdb.ref(`Users/Parents/${loginCode}/${studentId}`).set({
        Status: "Active", Name: stu.name, Email: `${studentId.toLowerCase()}@schoolsync.test`,
        Role: "Student",
        Credentials: { Id: studentId, Password: hashedPw },
        Profile: {
          name: stu.name, email: `${studentId.toLowerCase()}@schoolsync.test`,
          className: group.cls, section: group.sec, rollNo: stu.roll,
          gender: stu.gender, fatherName: stu.father, motherName: stu.mother,
        },
      });

      // RTDB — Class roster
      await rtdb.ref(`Schools/${schoolCode}/${SESSION}/${group.cls}/${group.sec}/Students/${studentId}`).set({
        Name: stu.name, RollNo: stu.roll, Status: "Active",
      });

      // RTDB — SIS index
      await rtdb.ref(`Schools/${schoolCode}/SIS/Students_Index/${studentId}`).set({
        name: stu.name, class: group.cls, section: group.sec, rollNo: stu.roll,
        gender: stu.gender, status: "Active",
      });

      console.log(`   ${studentId} — ${stu.name} (${group.cls} ${group.sec})`);
    }

    // Update section student count in Firestore
    const sectionDocId = `${group.cls}/${group.sec}`.replace(/[\s\/]/g, "_");
    await firestore.collection("schools").doc(schoolCode).collection("sections").doc(sectionDocId).update({
      studentCount: group.list.length,
    });
  }
  console.log("");

  // ═══════════════════════════════════════════════════════════════════════════
  // DONE
  // ═══════════════════════════════════════════════════════════════════════════
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  ✅ TEST SCHOOL CREATED SUCCESSFULLY                        ║");
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║  School: ${SCHOOL.name.padEnd(48)} ║`);
  console.log(`║  Code:   ${schoolCode.padEnd(48)} ║`);
  console.log(`║  Login:  ${loginCode.padEnd(48)} ║`);
  console.log(`║  Session: ${SESSION.padEnd(47)} ║`);
  console.log(`║  Password: Test1234 (all users)                              ║`);
  console.log("╠══════════════════════════════════════════════════════════════╣");
  console.log(`║  SSA: ${ssaId}  |  Admin: ${adminId}                              ║`);
  console.log(`║  Teachers: ${teacherIds.join(", ").padEnd(46)} ║`);
  console.log(`║  Students: ${allStudents.reduce((a, g) => a + g.list.length, 0)} total across ${allStudents.length} sections                       ║`);
  console.log(`║  Classes: ${CLASSES.length}  |  Sections: ${sectionCount}  |  Subject groups: ${Object.keys(SUBJECT_CATALOG).length}        ║`);
  console.log("╚══════════════════════════════════════════════════════════════╝");

  // Save IDs to a file for easy reference
  const summary = {
    school: { name: SCHOOL.name, code: schoolCode, loginCode, session: SESSION },
    ssa: ssaId,
    admin: adminId,
    teachers: teacherIds.map((id, i) => ({ id, name: TEACHERS[i].name, subjects: TEACHERS[i].subjects })),
    studentCount: allStudents.reduce((a, g) => a + g.list.length, 0),
    password: PW,
  };
  require("fs").writeFileSync(
    require("path").join(__dirname, "test-school-ids.json"),
    JSON.stringify(summary, null, 2)
  );
  console.log("\n📝 IDs saved to scripts/test-school-ids.json");

  await mongoose.disconnect();
  process.exit(0);
}

// ─── Create user in all 3 databases (Firestore FIRST) ───────────────────────

async function createUserFull(data, hashedPw, schoolCode, loginCode) {
  const { userId, name, email, phone, role, schoolId, position, department,
          classesAssigned, subjects } = data;

  // 1. FIRESTORE FIRST — hierarchical user subcollection
  const fsCollection = firestoreUserPath(role, schoolCode);
  await firestore.collection(fsCollection).doc(userId).set({
    userId, name, email: (email || "").toLowerCase(), phone: phone || null,
    role, schoolId: schoolCode, position: position || null,
    department: department || null, status: "Active",
    classesAssigned: classesAssigned || [], subjects: subjects || [],
    createdAt: new Date(),
  });

  // 2. RTDB — cache/real-time path
  const rtdbPath = rtdbUserPath(role, loginCode, userId);
  await rtdb.ref(rtdbPath).set({
    Status: "Active", Name: name, Email: (email || "").toLowerCase(),
    Role: role === "school_super_admin" ? "School Super Admin" :
          role === "class_teacher" ? "Class Teacher" :
          role.charAt(0).toUpperCase() + role.slice(1).replace(/_/g, " "),
    Credentials: { Id: userId, Password: hashedPw },
    Profile: {
      name, email: (email || "").toLowerCase(), role,
      ...(position ? { position } : {}),
      ...(department ? { department } : {}),
    },
    AccessHistory: { SA_LastLogin: null, LoginAttempts: 0 },
  });

  // 3. MongoDB — auth record
  await User.create({
    userId, name, email: (email || "").toLowerCase(), phone: phone || null,
    role, schoolId, schoolCode: schoolCode || null,
    password: hashedPw, status: "Active",
    position: position || null, department: department || null,
    classesAssigned: classesAssigned || [], subjects: subjects || [],
    createdAt: new Date(), createdBy: "seed-test-school",
    refreshTokens: [], devices: [], loginAttempts: 0, lockedUntil: null,
  });
}

main().catch(e => { console.error("❌ FAILED:", e.message); console.error(e); process.exit(1); });
