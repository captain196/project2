#!/usr/bin/env node
/**
 * Migration Script: RTDB → Firestore (schoolsync database)
 *
 * Reads all existing data from Firebase Realtime Database and writes
 * to the Firestore 'schoolsync' database. Idempotent — safe to re-run.
 *
 * Usage: node scripts/migrate-to-firestore.js
 */

require("dotenv").config();
const { initFirebase, getFirebaseDb, getFirestore } = require("../src/config/firebase");

initFirebase();
const rtdb = getFirebaseDb();
const fs = getFirestore();

let stats = { schools: 0, staff: 0, students: 0, parents: 0, sections: 0, users: 0, attendance: 0, attSummary: 0, homework: 0, submissions: 0, leaves: 0, errors: 0 };

// ── Helpers ────────────────────────────────────────────────────────

async function rtdbGet(path) {
  const snap = await rtdb.ref(path).once("value");
  return snap.val();
}

async function batchSet(docs) {
  // Firestore batch limit = 500
  for (let i = 0; i < docs.length; i += 500) {
    const batch = fs.batch();
    const chunk = docs.slice(i, i + 500);
    for (const { collection, docId, data } of chunk) {
      batch.set(fs.collection(collection).doc(docId), data, { merge: true });
    }
    await batch.commit();
  }
}

function timestamp() {
  const { Timestamp } = require("firebase-admin/firestore");
  return Timestamp.now();
}

function cleanString(val) {
  if (val === null || val === undefined) return "";
  return String(val).trim();
}

// ── Migrate Schools ────────────────────────────────────────────────

async function migrateSchool(loginCode, schoolCode) {
  console.log(`  📦 School: ${schoolCode} (login: ${loginCode})`);

  const profile = (await rtdbGet(`Schools/${schoolCode}/Config/Profile`)) || {};
  const board = (await rtdbGet(`Schools/${schoolCode}/Config/Board`)) || {};
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  const subscription = (await rtdbGet(`System/Schools/${schoolCode}/subscription`)) || {};

  const schoolDoc = {
    schoolId: schoolCode,
    loginCode: loginCode,
    name: cleanString(profile.display_name),
    schoolCode: schoolCode,
    address: cleanString(profile.address),
    city: cleanString(profile.city),
    state: cleanString(profile.state),
    pincode: cleanString(profile.pincode),
    email: cleanString(profile.email),
    phone: cleanString(profile.phone),
    website: cleanString(profile.website),
    principalName: cleanString(profile.principal_name),
    establishedYear: cleanString(profile.established_year),
    affiliationBoard: cleanString(profile.affiliation_board || board.type),
    affiliationNo: cleanString(profile.affiliation_no),
    logoUrl: cleanString(profile.logo_url),
    currentSession: cleanString(activeSession),
    subscription: {
      plan: cleanString(subscription.plan || "free"),
      status: cleanString(subscription.status || "active"),
      expiryDate: cleanString(subscription.expiry_date || ""),
    },
    status: "active",
    migratedAt: timestamp(),
    migratedFrom: "rtdb",
  };

  await fs.collection("schools").doc(schoolCode).set(schoolDoc, { merge: true });
  stats.schools++;
}

// ── Migrate Staff ──────────────────────────────────────────────────

async function migrateStaff(schoolCode, loginCode) {
  const teachers = (await rtdbGet(`Users/Teachers/${schoolCode}`)) || {};
  const docs = [];

  for (const [staffId, data] of Object.entries(teachers)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "staff",
      docId: staffId,
      data: {
        userId: staffId,
        name: cleanString(data.name),
        email: cleanString(data.email),
        phone: cleanString(data.phone),
        role: "teacher",
        schoolId: schoolCode,
        loginCode: loginCode,
        department: cleanString(data.department),
        position: cleanString(data.position),
        qualification: cleanString(data.qualification || ""),
        subjects: [],
        classesAssigned: [],
        gender: cleanString(data.gender || ""),
        dob: cleanString(data.dob || ""),
        joiningDate: cleanString(data.joining_date || ""),
        profilePic: cleanString(data.profilePic || data.profile_pic || ""),
        status: cleanString(data.status || "Active"),
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });

    // Also create thin user doc
    docs.push({
      collection: "users",
      docId: staffId,
      data: {
        userId: staffId,
        name: cleanString(data.name),
        email: cleanString(data.email),
        role: "teacher",
        schoolId: schoolCode,
        profilePic: cleanString(data.profilePic || data.profile_pic || ""),
        status: cleanString(data.status || "Active"),
        migratedAt: timestamp(),
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.staff += Object.keys(teachers).length;
    stats.users += Object.keys(teachers).length;
    console.log(`    👨‍🏫 Staff: ${Object.keys(teachers).length} migrated`);
  }
}

// ── Migrate Students & Parents ─────────────────────────────────────

async function migrateStudents(schoolCode, loginCode) {
  const index = (await rtdbGet(`Schools/${schoolCode}/SIS/Students_Index`)) || {};
  const parentProfiles = (await rtdbGet(`Users/Parents/${schoolCode}`)) || {};
  const session = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);

  const studentDocs = [];
  const parentMap = {}; // parentDbKey → { children, profile }

  for (const [studentId, indexData] of Object.entries(index)) {
    if (!indexData || typeof indexData !== "object") continue;

    const profile = parentProfiles[studentId] || {};
    const className = cleanString(indexData.class || profile.className || "").replace("Class ", "");
    const section = cleanString(indexData.section || profile.section || "").replace("Section ", "");

    const studentDoc = {
      userId: studentId,
      name: cleanString(indexData.name || profile.name || profile.Name || ""),
      email: cleanString(profile.email || ""),
      phone: cleanString(profile.phone || ""),
      schoolId: schoolCode,
      loginCode: loginCode,
      className: className,
      section: section,
      rollNo: cleanString(profile.rollNo || profile.Roll_no || indexData.rollNo || ""),
      fatherName: cleanString(profile.fatherName || profile.father_name || ""),
      motherName: cleanString(profile.motherName || profile.mother_name || ""),
      dob: cleanString(profile.dob || ""),
      gender: cleanString(indexData.gender || profile.gender || profile.Gender || ""),
      admissionDate: cleanString(profile.admissionDate || profile.admission_date || ""),
      parentDbKey: schoolCode,
      profilePic: cleanString(profile.profilePic || profile.profile_pic || ""),
      status: cleanString(indexData.status || "Active"),
      session: cleanString(session || ""),
      migratedAt: timestamp(),
      migratedFrom: "rtdb",
    };

    studentDocs.push({
      collection: "students",
      docId: studentId,
      data: studentDoc,
    });

    // Also thin user doc
    studentDocs.push({
      collection: "users",
      docId: studentId,
      data: {
        userId: studentId,
        name: studentDoc.name,
        email: studentDoc.email,
        role: "student",
        schoolId: schoolCode,
        profilePic: studentDoc.profilePic,
        status: studentDoc.status,
        migratedAt: timestamp(),
      },
    });

    // Track parent data — group children under parentDbKey
    const pKey = schoolCode;
    if (!parentMap[pKey]) {
      parentMap[pKey] = { childrenIds: [], profile: profile };
    }
    parentMap[pKey].childrenIds.push(studentId);
  }

  if (studentDocs.length > 0) {
    await batchSet(studentDocs);
    stats.students += Object.keys(index).length;
    stats.users += Object.keys(index).length;
    console.log(`    🎓 Students: ${Object.keys(index).length} migrated`);
  }

  // Migrate parents (grouped by parentDbKey)
  const parentDocs = [];
  for (const [pKey, pData] of Object.entries(parentMap)) {
    const parentId = `PAR_${pKey}`;
    parentDocs.push({
      collection: "parents",
      docId: parentId,
      data: {
        parentDbKey: pKey,
        name: cleanString(pData.profile.fatherName || pData.profile.father_name || "Parent"),
        email: cleanString(pData.profile.email || ""),
        phone: cleanString(pData.profile.phone || ""),
        schoolId: schoolCode,
        childrenIds: pData.childrenIds,
        profilePic: "",
        status: "Active",
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (parentDocs.length > 0) {
    await batchSet(parentDocs);
    stats.parents += Object.keys(parentMap).length;
    console.log(`    👨‍👩‍👦 Parents: ${Object.keys(parentMap).length} migrated`);
  }
}

// ── Migrate Sections ───────────────────────────────────────────────

async function migrateSections(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) {
    console.log("    ⚠️  No active session found, skipping sections");
    return;
  }

  const sessionData = (await rtdbGet(`Schools/${schoolCode}/${activeSession}`)) || {};
  const subjectAssignments = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Academic/Subject_Assignments`)) || {};

  const sectionDocs = [];

  // Find all class/section nodes
  for (const [key, value] of Object.entries(sessionData)) {
    if (!key.startsWith("Class ") || !value || typeof value !== "object") continue;

    // key might be "Class 9th" (no section) or we need to look for section nodes inside
    const classLabel = key;
    const className = key.replace("Class ", "");

    // Check if this node has section-like children (Section A, Section B, etc.) or direct data
    for (const [subKey, subValue] of Object.entries(value)) {
      if (!subKey.startsWith("Section ") && !subKey.match(/^[A-Z]$/)) continue;
      if (!subValue || typeof subValue !== "object") continue;

      const sectionName = subKey.replace("Section ", "");
      const sectionId = `${schoolCode}_${activeSession}_${className}_${sectionName}`;

      // Extract roster
      const roster = {};
      const studentList = subValue.Students?.List || {};
      for (const [stuId, stuData] of Object.entries(studentList)) {
        if (stuData && typeof stuData === "object") {
          roster[stuId] = {
            name: cleanString(stuData.Name || stuData.name || ""),
            rollNo: cleanString(stuData.Roll_no || stuData.rollNo || ""),
            gender: cleanString(stuData.Gender || stuData.gender || ""),
          };
        }
      }

      // Extract subjects from subject assignments
      const subjects = [];
      for (const [assignKey, assignData] of Object.entries(subjectAssignments)) {
        if (!assignData || typeof assignData !== "object") continue;

        // Format: assign_001 style
        if (assignData.teacherId && assignData.subject) {
          const assignClass = cleanString(assignData.className).replace("Class ", "");
          const assignSection = cleanString(assignData.section).replace("Section ", "");
          if (assignClass === className && assignSection === sectionName) {
            subjects.push({
              name: cleanString(assignData.subject),
              teacherId: cleanString(assignData.teacherId),
              teacherName: cleanString(assignData.teacherName || ""),
            });
          }
        }
      }

      // Extract timetable
      const timetable = subValue.Time_table || null;

      // Find class teacher
      let classTeacherId = "";
      for (const [, assignData] of Object.entries(subjectAssignments)) {
        if (assignData && assignData.isClassTeacher === true) {
          const ac = cleanString(assignData.className).replace("Class ", "");
          const as2 = cleanString(assignData.section).replace("Section ", "");
          if (ac === className && as2 === sectionName) {
            classTeacherId = cleanString(assignData.teacherId);
            break;
          }
        }
      }

      sectionDocs.push({
        collection: "sections",
        docId: sectionId,
        data: {
          schoolId: schoolCode,
          session: activeSession,
          className: className,
          section: sectionName,
          classLabel: classLabel,
          classTeacherId: classTeacherId,
          studentCount: Object.keys(roster).length,
          roster: roster,
          subjects: subjects,
          timetable: timetable,
          migratedAt: timestamp(),
          migratedFrom: "rtdb",
        },
      });
    }
  }

  if (sectionDocs.length > 0) {
    await batchSet(sectionDocs);
    stats.sections += sectionDocs.length;
    console.log(`    📚 Sections: ${sectionDocs.length} migrated`);
  }
}

// ── Migrate Admins ─────────────────────────────────────────────────

async function migrateAdmins(schoolCode, loginCode) {
  const admins = (await rtdbGet(`Users/Admin/${loginCode}`)) || {};
  const docs = [];

  for (const [adminId, data] of Object.entries(admins)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "staff",
      docId: adminId,
      data: {
        userId: adminId,
        name: cleanString(data.name),
        email: cleanString(data.email),
        phone: cleanString(data.phone || ""),
        role: cleanString(data.role || "admin"),
        schoolId: schoolCode,
        loginCode: loginCode,
        department: "Administration",
        position: cleanString(data.role || "Admin"),
        status: cleanString(data.status || "Active"),
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });

    docs.push({
      collection: "users",
      docId: adminId,
      data: {
        userId: adminId,
        name: cleanString(data.name),
        email: cleanString(data.email),
        role: cleanString(data.role || "admin"),
        schoolId: schoolCode,
        profilePic: "",
        status: cleanString(data.status || "Active"),
        migratedAt: timestamp(),
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    console.log(`    🔑 Admins: ${Object.keys(admins).length} migrated`);
  }
}

// ── Migrate Attendance ─────────────────────────────────────────────

const STATUS_MAP = { P: "P", A: "A", L: "L", H: "H", T: "T", V: "V" };

function getDaysInMonth(monthYear) {
  // "March 2026" → number of days
  const [monthName, year] = monthYear.split(" ");
  const monthIndex = ["January","February","March","April","May","June","July","August","September","October","November","December"].indexOf(monthName);
  if (monthIndex === -1) return 31;
  return new Date(parseInt(year), monthIndex + 1, 0).getDate();
}

async function migrateAttendance(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const sessionData = (await rtdbGet(`Schools/${schoolCode}/${activeSession}`)) || {};
  const attDocs = [];
  const summaryDocs = [];

  for (const [classKey, classData] of Object.entries(sessionData)) {
    if (!classKey.startsWith("Class ") || !classData || typeof classData !== "object") continue;
    const className = classKey.replace("Class ", "");

    for (const [secKey, secData] of Object.entries(classData)) {
      if (!secKey.startsWith("Section ") && !secKey.match(/^[A-Z]$/)) continue;
      if (!secData || typeof secData !== "object") continue;
      const sectionName = secKey.replace("Section ", "");
      const sectionKey = `${className}_${sectionName}`;

      // Iterate students in this section
      const students = secData.Students || {};
      for (const [studentId, studentData] of Object.entries(students)) {
        if (studentId === "List" || !studentData || typeof studentData !== "object") continue;
        const attendance = studentData.Attendance || {};
        const studentName = students.List?.[studentId]?.Name || studentData.Name || "";

        for (const [month, dayWiseStr] of Object.entries(attendance)) {
          if (typeof dayWiseStr !== "string" || dayWiseStr.length === 0) continue;

          // Create per-day attendance docs
          const [monthName, year] = month.split(" ");
          const monthIndex = ["January","February","March","April","May","June","July","August","September","October","November","December"].indexOf(monthName);
          if (monthIndex === -1 || !year) continue;

          for (let i = 0; i < dayWiseStr.length; i++) {
            const status = dayWiseStr[i];
            if (!STATUS_MAP[status]) continue;
            const day = i + 1;
            const dateStr = `${year}-${String(monthIndex + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;

            attDocs.push({
              collection: "attendance",
              docId: `${schoolCode}_${dateStr}_${sectionKey}_${studentId}`,
              data: {
                schoolId: schoolCode,
                session: activeSession,
                date: dateStr,
                sectionKey: sectionKey,
                studentId: studentId,
                studentName: studentName,
                status: status,
                markedBy: "",
                late: status === "T",
                lateMinutes: 0,
                notified: false,
                migratedAt: timestamp(),
              },
            });
          }

          // Create monthly summary
          let present = 0, absent = 0, late = 0, leave = 0, holiday = 0, vacation = 0;
          for (const c of dayWiseStr) {
            switch (c) { case "P": present++; break; case "A": absent++; break; case "T": late++; break; case "L": leave++; break; case "H": holiday++; break; case "V": vacation++; break; }
          }
          const totalDays = dayWiseStr.length;
          const workingDays = totalDays - holiday - vacation;
          const percentage = workingDays > 0 ? Math.round((present / workingDays) * 10000) / 100 : 0;

          const summaryId = `${schoolCode}_${activeSession}_${month.replace(" ", "_")}_${studentId}`;
          summaryDocs.push({
            collection: "attendanceSummary",
            docId: summaryId,
            data: {
              schoolId: schoolCode,
              session: activeSession,
              month: month,
              studentId: studentId,
              studentName: studentName,
              sectionKey: sectionKey,
              dayWise: dayWiseStr,
              present, absent, late, leave, holiday, vacation,
              totalDays, workingDays, percentage,
              updatedAt: timestamp(),
              migratedFrom: "rtdb",
            },
          });
        }
      }
    }
  }

  if (attDocs.length > 0) {
    await batchSet(attDocs);
    stats.attendance += attDocs.length;
    console.log(`    📋 Attendance: ${attDocs.length} daily records`);
  }
  if (summaryDocs.length > 0) {
    await batchSet(summaryDocs);
    stats.attSummary += summaryDocs.length;
    console.log(`    📊 Att.Summary: ${summaryDocs.length} monthly summaries`);
  }
}

// ── Migrate Homework ──────────────────────────────────────────────

async function migrateHomework(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const hwDocs = [];
  const subDocs = [];
  const seenHwIds = new Set();

  // Read from app path: Schools/{schoolCode}/{session}/Homework/Class X/Section Y/
  const homeworkRoot = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Homework`)) || {};
  for (const [classKey, sections] of Object.entries(homeworkRoot)) {
    if (!sections || typeof sections !== "object") continue;
    const className = classKey.replace("Class ", "");

    for (const [secKey, hwList] of Object.entries(sections)) {
      if (!hwList || typeof hwList !== "object") continue;
      const sectionName = secKey.replace("Section ", "");
      const sectionKey = `${className}_${sectionName}`;

      for (const [hwId, hwData] of Object.entries(hwList)) {
        if (!hwData || typeof hwData !== "object" || seenHwIds.has(hwId)) continue;
        seenHwIds.add(hwId);

        hwDocs.push({
          collection: "homework",
          docId: hwId,
          data: {
            schoolId: schoolCode,
            session: activeSession,
            className: cleanString(hwData.className || className).replace("Class ", ""),
            section: cleanString(hwData.section || sectionName).replace("Section ", ""),
            sectionKey: sectionKey,
            title: cleanString(hwData.title),
            description: cleanString(hwData.description),
            subject: cleanString(hwData.subject),
            teacherId: cleanString(hwData.teacherId),
            teacherName: cleanString(hwData.teacherName),
            dueDate: cleanString(hwData.dueDate),
            createdAt: hwData.createdAt ? new Date(hwData.createdAt) : timestamp(),
            status: cleanString(hwData.status || "active"),
            submissionCount: 0,
            totalStudents: 0,
            attachments: Array.isArray(hwData.attachments) ? hwData.attachments : [],
            migratedAt: timestamp(),
            migratedFrom: "rtdb",
          },
        });
      }
    }
  }

  // Read HomeworkStatus
  const hwStatus = (await rtdbGet(`HomeworkStatus/${schoolCode}`)) || {};
  for (const [hwId, students] of Object.entries(hwStatus)) {
    if (!students || typeof students !== "object") continue;
    for (const [studentId, statusData] of Object.entries(students)) {
      if (!statusData || typeof statusData !== "object") continue;

      subDocs.push({
        collection: "submissions",
        docId: `${hwId}_${studentId}`,
        data: {
          schoolId: schoolCode,
          homeworkId: hwId,
          studentId: studentId,
          studentName: cleanString(statusData.studentName),
          sectionKey: "",
          status: cleanString(statusData.status || "pending"),
          remark: cleanString(statusData.remark || statusData.remarks || ""),
          submittedAt: statusData.submittedAt ? new Date(statusData.submittedAt) : null,
          reviewedBy: cleanString(statusData.reviewedBy),
          files: [],
          text: "",
          score: -1,
          maxMarks: 0,
          migratedAt: timestamp(),
          migratedFrom: "rtdb",
        },
      });
    }
  }

  if (hwDocs.length > 0) {
    await batchSet(hwDocs);
    stats.homework += hwDocs.length;
    console.log(`    📝 Homework: ${hwDocs.length} assignments`);
  }
  if (subDocs.length > 0) {
    await batchSet(subDocs);
    stats.submissions += subDocs.length;
    console.log(`    📤 Submissions: ${subDocs.length} records`);
  }
}

// ── Migrate Leave Applications ────────────────────────────────────

async function migrateLeave(schoolCode) {
  const leaveRecords = (await rtdbGet(`Schools/${schoolCode}/HR/Staff_Leave/Records`)) || {};
  const docs = [];

  for (const [teacherId, leaves] of Object.entries(leaveRecords)) {
    if (!leaves || typeof leaves !== "object") continue;

    for (const [leaveId, data] of Object.entries(leaves)) {
      if (!data || typeof data !== "object") continue;

      docs.push({
        collection: "leaveApplications",
        docId: leaveId,
        data: {
          schoolId: schoolCode,
          applicantType: "staff",
          applicantId: cleanString(data.teacherId || teacherId),
          applicantName: cleanString(data.teacherName),
          sectionKey: "",
          leaveType: cleanString(data.leaveType),
          startDate: cleanString(data.startDate),
          endDate: cleanString(data.endDate),
          numberOfDays: parseInt(data.numberOfDays) || 0,
          reason: cleanString(data.reason),
          attachments: [],
          status: cleanString(data.status || "pending"),
          appliedAt: data.appliedOn ? new Date(data.appliedOn) : timestamp(),
          approvedBy: cleanString(data.approvedBy),
          approvedAt: data.approvedOn ? new Date(data.approvedOn) : null,
          remarks: cleanString(data.remarks),
          migratedAt: timestamp(),
          migratedFrom: "rtdb",
        },
      });
    }
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.leaves += docs.length;
    console.log(`    🏖️  Leaves: ${docs.length} applications`);
  }
}

// ── Migrate Exams ─────────────────────────────────────────────────

async function migrateExams(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const exams = (await rtdbGet(`Schools/${schoolCode}/Config/Exams`)) || {};
  const docs = [];

  for (const [examId, data] of Object.entries(exams)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "exams",
      docId: `${schoolCode}_${examId}`,
      data: {
        schoolId: schoolCode,
        session: activeSession,
        examName: cleanString(data.name || data.Name),
        examType: cleanString(data.type || data.Type || ""),
        gradingScale: cleanString(data.grading_pattern || data.GradingScale || "percentage"),
        passingPercent: parseInt(data.passing_marks || data.PassingPercent || 33),
        maxTheory: parseFloat(data.maxTheory || 80),
        maxPractical: parseFloat(data.maxPractical || 20),
        maxTotal: parseFloat(data.maxTotal || 100),
        startDate: cleanString(data.date || data.StartDate || ""),
        endDate: cleanString(data.EndDate || ""),
        status: cleanString(data.status || data.Status || "Published"),
        weight: parseFloat(data.weight || 0),
        applicableClasses: [],
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.exams = (stats.exams || 0) + docs.length;
    console.log(`    📝 Exams: ${docs.length} definitions`);
  }
}

// ── Migrate Marks ─────────────────────────────────────────────────

async function migrateMarks(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const marksRoot = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Results/Marks`)) || {};
  const marksDocs = [];

  for (const [examId, classData] of Object.entries(marksRoot)) {
    if (!classData || typeof classData !== "object") continue;

    for (const [classKey, sectionData] of Object.entries(classData)) {
      if (!sectionData || typeof sectionData !== "object") continue;
      const className = classKey.replace("Class ", "");

      for (const [secKey, subjectData] of Object.entries(sectionData)) {
        if (!subjectData || typeof subjectData !== "object") continue;
        const sectionName = secKey.replace("Section ", "");
        const sectionKey = `${className}_${sectionName}`;

        for (const [subject, students] of Object.entries(subjectData)) {
          if (!students || typeof students !== "object") continue;

          for (const [studentId, marks] of Object.entries(students)) {
            if (!marks || typeof marks !== "object") continue;

            const docId = `${schoolCode}_${examId}_${sectionKey}_${subject}_${studentId}`;
            marksDocs.push({
              collection: "marks",
              docId: docId,
              data: {
                schoolId: schoolCode,
                session: activeSession,
                examId: examId,
                sectionKey: sectionKey,
                className: className,
                section: sectionName,
                subject: subject,
                studentId: studentId,
                studentName: "",
                theory: parseFloat(marks.Theory || 0),
                practical: parseFloat(marks.Practical || 0),
                total: parseFloat(marks.Total || 0),
                absent: marks.Absent === true,
                savedBy: cleanString(marks.SavedBy || ""),
                savedAt: marks.SavedAt ? new Date(marks.SavedAt) : timestamp(),
                status: "submitted",
                migratedAt: timestamp(),
                migratedFrom: "rtdb",
              },
            });
          }
        }
      }
    }
  }

  if (marksDocs.length > 0) {
    await batchSet(marksDocs);
    stats.marks = (stats.marks || 0) + marksDocs.length;
    console.log(`    ✏️  Marks: ${marksDocs.length} entries`);
  }
}

// ── Migrate Computed Results ──────────────────────────────────────

async function migrateResults(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const resultsRoot = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Results/Computed`)) || {};
  const resultDocs = [];

  for (const [examId, classData] of Object.entries(resultsRoot)) {
    if (!classData || typeof classData !== "object") continue;

    for (const [classKey, sectionData] of Object.entries(classData)) {
      if (!sectionData || typeof sectionData !== "object") continue;
      const className = classKey.replace("Class ", "");

      for (const [secKey, students] of Object.entries(sectionData)) {
        if (!students || typeof students !== "object") continue;
        const sectionName = secKey.replace("Section ", "");
        const sectionKey = `${className}_${sectionName}`;

        for (const [studentId, result] of Object.entries(students)) {
          if (studentId.startsWith("_") || !result || typeof result !== "object") continue;

          // Convert Subjects map to standardized format
          const subjects = {};
          if (result.Subjects && typeof result.Subjects === "object") {
            for (const [subName, subData] of Object.entries(result.Subjects)) {
              subjects[subName] = {
                total: parseFloat(subData.Total || 0),
                maxMarks: parseFloat(subData.MaxMarks || 100),
                percentage: parseFloat(subData.Percentage || 0),
                grade: cleanString(subData.Grade || ""),
                absent: subData.Absent === true,
              };
            }
          }

          const docId = `${schoolCode}_${examId}_${sectionKey}_${studentId}`;
          resultDocs.push({
            collection: "results",
            docId: docId,
            data: {
              schoolId: schoolCode,
              session: activeSession,
              examId: examId,
              examName: "",
              sectionKey: sectionKey,
              className: className,
              section: sectionName,
              studentId: studentId,
              studentName: "",
              rollNo: "",
              subjects: subjects,
              totalMarks: parseFloat(result.TotalMarks || 0),
              maxMarks: parseFloat(result.MaxMarks || 0),
              percentage: parseFloat(result.Percentage || 0),
              grade: cleanString(result.Grade || ""),
              rank: parseInt(result.Rank || 0),
              passFail: cleanString(result.PassFail || ""),
              computedAt: result.ComputedAt ? new Date(result.ComputedAt) : timestamp(),
              migratedAt: timestamp(),
              migratedFrom: "rtdb",
            },
          });
        }
      }
    }
  }

  if (resultDocs.length > 0) {
    await batchSet(resultDocs);
    stats.results = (stats.results || 0) + resultDocs.length;
    console.log(`    🏆 Results: ${resultDocs.length} computed`);
  }
}

// ── Migrate Fee Structures ─────────────────────────────────────────

async function migrateFeeStructures(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  const feeConfig = (await rtdbGet(`Schools/${schoolCode}/Config/FeeStructure`)) || {};
  if (!activeSession || Object.keys(feeConfig).length === 0) return;

  // Fee config is school-wide, create a doc per known class/section from sections
  const feeHeads = [];
  let totalMonthly = 0;
  for (const [name, data] of Object.entries(feeConfig)) {
    const amount = parseFloat(data.amount || data.Amount || 0);
    const frequency = cleanString(data.frequency || data.Frequency || "monthly");
    feeHeads.push({ name, amount, frequency });
    if (frequency === "month" || frequency === "monthly") totalMonthly += amount;
  }

  // Write a school-level fee structure doc
  const docId = `${schoolCode}_${activeSession}_default`;
  await fs.collection("feeStructures").doc(docId).set({
    schoolId: schoolCode,
    session: activeSession,
    className: "default",
    section: "default",
    feeHeads: feeHeads,
    totalMonthlyFee: totalMonthly,
    totalAnnualFee: totalMonthly * 12,
    updatedAt: timestamp(),
    migratedFrom: "rtdb",
  }, { merge: true });
  stats.feeStructures = (stats.feeStructures || 0) + 1;
  console.log(`    💰 Fee Structure: ${feeHeads.length} heads`);
}

// ── Migrate Fee Demands ───────────────────────────────────────────

async function migrateFeeDemands(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const demands = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Fees/Demands`)) || {};
  const docs = [];

  for (const [studentId, studentDemands] of Object.entries(demands)) {
    if (!studentDemands || typeof studentDemands !== "object") continue;

    for (const [demandId, data] of Object.entries(studentDemands)) {
      if (!data || typeof data !== "object") continue;

      const className = cleanString(data.class || "").replace("Class ", "");
      const section = cleanString(data.section || "").replace("Section ", "");

      docs.push({
        collection: "feeDemands",
        docId: `${schoolCode}_${demandId}`,
        data: {
          schoolId: schoolCode,
          session: activeSession,
          studentId: cleanString(data.student_id || studentId),
          studentName: cleanString(data.student_name || ""),
          className: className,
          section: section,
          sectionKey: `${className}_${section}`,
          month: cleanString(data.month || ""),
          demandId: cleanString(data.demand_id || demandId),
          feeItems: data.fee_items || {},
          grossAmount: parseFloat(data.gross_amount || 0),
          discountAmount: parseFloat(data.discount_amount || 0),
          fineAmount: parseFloat(data.fine_amount || 0),
          netAmount: parseFloat(data.net_amount || 0),
          paidAmount: parseFloat(data.paid_amount || 0),
          status: cleanString(data.status || "unpaid"),
          createdAt: cleanString(data.created_at || ""),
          updatedAt: cleanString(data.updated_at || ""),
          migratedAt: timestamp(),
          migratedFrom: "rtdb",
        },
      });
    }
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.feeDemands = (stats.feeDemands || 0) + docs.length;
    console.log(`    📄 Fee Demands: ${docs.length} records`);
  }
}

// ── Migrate Fee Defaulters ────────────────────────────────────────

async function migrateFeeDefaulters(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const defaulters = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Fees/Defaulters`)) || {};
  const docs = [];

  for (const [studentId, data] of Object.entries(defaulters)) {
    if (!data || typeof data !== "object") continue;

    const className = cleanString(data.class || "").replace("Class ", "");
    const section = cleanString(data.section || "").replace("Section ", "");

    docs.push({
      collection: "feeDefaulters",
      docId: `${schoolCode}_${studentId}`,
      data: {
        schoolId: schoolCode,
        session: activeSession,
        studentId: cleanString(data.student_id || studentId),
        studentName: cleanString(data.student_name || ""),
        className: className,
        section: section,
        totalDues: parseFloat(data.total_dues || 0),
        unpaidMonths: Array.isArray(data.unpaid_months) ? data.unpaid_months : [],
        overdueMonths: Array.isArray(data.overdue_months) ? data.overdue_months : [],
        examBlocked: data.exam_blocked === true,
        resultWithheld: data.result_withheld === true,
        lastPaymentDate: cleanString(data.last_payment_date || ""),
        flaggedAt: cleanString(data.flagged_at || ""),
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.feeDefaulters = (stats.feeDefaulters || 0) + docs.length;
    console.log(`    🚩 Defaulters: ${docs.length} flagged`);
  }
}

// ── Migrate Fee Receipts ──────────────────────────────────────────

async function migrateFeeReceipts(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  const receipts = (await rtdbGet(`Schools/${schoolCode}/${activeSession}/Accounts/Receipt_Index`)) || {};
  const docs = [];

  for (const [receiptKey, data] of Object.entries(receipts)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "feeReceipts",
      docId: `${schoolCode}_${receiptKey}`,
      data: {
        schoolId: schoolCode,
        session: activeSession,
        receiptNo: cleanString(data.receipt_no || data.receiptNo || receiptKey),
        studentId: cleanString(data.student_id || data.studentId || ""),
        studentName: cleanString(data.student_name || data.studentName || ""),
        className: cleanString(data.class || data.className || "").replace("Class ", ""),
        section: cleanString(data.section || "").replace("Section ", ""),
        amount: parseFloat(data.amount || data.total || 0),
        paymentMode: cleanString(data.mode || data.payment_mode || "Cash"),
        feeMonths: Array.isArray(data.months) ? data.months : (data.month ? [data.month] : []),
        feeBreakdown: data.breakdown || data.fee_items || {},
        remarks: cleanString(data.remarks || ""),
        collectedBy: cleanString(data.collected_by || data.admin_id || ""),
        createdAt: data.created_at || data.date || "",
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.feeReceipts = (stats.feeReceipts || 0) + docs.length;
    console.log(`    🧾 Receipts: ${docs.length} records`);
  }
}

// ── Migrate Notices → Circulars ────────────────────────────────────

async function migrateCirculars(schoolCode) {
  const notices = (await rtdbGet(`Schools/${schoolCode}/Communication/Notices`)) || {};
  const docs = [];

  for (const [noticeId, data] of Object.entries(notices)) {
    if (!data || typeof data !== "object") continue;
    if (noticeId === "Count") continue; // skip counter node

    docs.push({
      collection: "circulars",
      docId: `${schoolCode}_${noticeId}`,
      data: {
        schoolId: schoolCode,
        title: cleanString(data.title || data.Title || ""),
        body: cleanString(data.body || data.Body || data.message || ""),
        author: cleanString(data.author || data.Author || ""),
        authorId: cleanString(data.authorId || data.admin_id || ""),
        category: cleanString(data.category || data.Category || "General"),
        priority: cleanString(data.priority || data.Priority || "Normal"),
        targetType: cleanString(data.target || data.Target || "All"),
        targetClasses: Array.isArray(data.targetClasses) ? data.targetClasses : [],
        targetRoles: Array.isArray(data.targetRoles) ? data.targetRoles : [],
        attachmentUrl: cleanString(data.attachmentUrl || data.attachment || ""),
        requireAcknowledgement: data.requireAcknowledgement === true,
        totalRecipients: parseInt(data.totalRecipients || 0),
        readCount: parseInt(data.readCount || 0),
        channels: Array.isArray(data.channels) ? data.channels : ["push"],
        status: "sent",
        sentAt: data.date ? new Date(data.date) : (data.timestamp ? new Date(data.timestamp) : timestamp()),
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.circulars = (stats.circulars || 0) + docs.length;
    console.log(`    📢 Circulars: ${docs.length} notices migrated`);
  }
}

// ── Migrate Transport ──────────────────────────────────────────────

async function migrateTransport(schoolCode) {
  const assignments = (await rtdbGet(`Schools/${schoolCode}/Operations/Transport/Assignments`)) || {};
  const docs = [];

  for (const [studentId, data] of Object.entries(assignments)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "studentRoutes",
      docId: `${schoolCode}_${studentId}`,
      data: {
        schoolId: schoolCode,
        studentId: studentId,
        studentName: "",
        routeId: cleanString(data.routeId),
        routeName: cleanString(data.routeName),
        stopId: "",
        stopName: cleanString(data.pickupPoint),
        vehicleId: cleanString(data.vehicleNumber),
        vehicleNo: cleanString(data.vehicleNumber || data.busNumber),
        driverName: cleanString(data.driverName),
        driverPhone: cleanString(data.driverPhone),
        conductorName: cleanString(data.conductorName),
        pickupTime: cleanString(data.pickupTime),
        dropTime: cleanString(data.dropTime),
        monthlyFee: 0,
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.transport = (stats.transport || 0) + docs.length;
    console.log(`    🚌 Transport: ${docs.length} student routes`);
  }
}

// ── Migrate Events ────────────────────────────────────────────────

async function migrateEvents(schoolCode) {
  const events = (await rtdbGet(`Schools/${schoolCode}/Events/List`)) || {};
  const docs = [];

  for (const [eventId, data] of Object.entries(events)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "events",
      docId: `${schoolCode}_${eventId}`,
      data: {
        schoolId: schoolCode,
        title: cleanString(data.title || data.name),
        description: cleanString(data.description),
        type: cleanString(data.type || "event"),
        category: cleanString(data.category || "general"),
        startDate: cleanString(data.start_date || data.date),
        endDate: cleanString(data.end_date || data.date),
        venue: cleanString(data.venue || ""),
        organizer: cleanString(data.organizer || ""),
        coverImage: cleanString(data.image || data.cover_image || ""),
        status: cleanString(data.status || "upcoming"),
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.events = (stats.events || 0) + docs.length;
    console.log(`    📅 Events: ${docs.length} records`);
  }
}

// ── Migrate HR Extended ───────────────────────────────────────────

async function migrateHRExtended(schoolCode) {
  const activeSession = await rtdbGet(`Schools/${schoolCode}/Config/ActiveSession`);
  if (!activeSession) return;

  // Salary structures
  const salaryStructures = (await rtdbGet(`Schools/${schoolCode}/HR/Salary_Structures`)) || {};
  const docs = [];

  for (const [staffId, data] of Object.entries(salaryStructures)) {
    if (!data || typeof data !== "object") continue;

    docs.push({
      collection: "salarySlips",
      docId: `${schoolCode}_template_${staffId}`,
      data: {
        schoolId: schoolCode,
        month: "template",
        staffId: staffId,
        staffName: cleanString(data.name || ""),
        empId: cleanString(data.empId || ""),
        department: cleanString(data.department || ""),
        earnings: data.earnings || {},
        deductions: data.deductions || {},
        grossEarnings: parseFloat(data.gross || 0),
        totalDeductions: parseFloat(data.total_deductions || 0),
        netPayable: parseFloat(data.net || 0),
        status: "template",
        migratedAt: timestamp(),
        migratedFrom: "rtdb",
      },
    });
  }

  // Departments
  const departments = (await rtdbGet(`Schools/${schoolCode}/HR/Departments`)) || {};
  for (const [deptId, data] of Object.entries(departments)) {
    if (!data || typeof data !== "object") continue;
    // Store as part of school config — already in schools collection
  }

  if (docs.length > 0) {
    await batchSet(docs);
    stats.hrExtended = (stats.hrExtended || 0) + docs.length;
    console.log(`    💼 HR Extended: ${docs.length} records`);
  }
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
  console.log("🚀 Starting RTDB → Firestore migration...\n");
  console.log(`   Target database: schoolsync (Firestore Native)\n`);

  try {
    // Get all school codes
    const schoolCodes = (await rtdbGet("Indexes/School_codes")) || {};
    console.log(`Found ${Object.keys(schoolCodes).length} schools to migrate\n`);

    for (const [loginCode, schoolCode] of Object.entries(schoolCodes)) {
      console.log(`\n🏫 Migrating school: ${loginCode} → ${schoolCode}`);
      try {
        await migrateSchool(loginCode, schoolCode);
        await migrateAdmins(schoolCode, loginCode);   // Admins FIRST
        await migrateStaff(schoolCode, loginCode);     // Teachers SECOND (overwrites admin role for dual-role users)
        await migrateStudents(schoolCode, loginCode);
        await migrateSections(schoolCode);
        await migrateAttendance(schoolCode);
        await migrateHomework(schoolCode);
        await migrateLeave(schoolCode);
        await migrateExams(schoolCode);
        await migrateMarks(schoolCode);
        await migrateResults(schoolCode);
        await migrateFeeStructures(schoolCode);
        await migrateFeeDemands(schoolCode);
        await migrateFeeDefaulters(schoolCode);
        await migrateFeeReceipts(schoolCode);
        await migrateCirculars(schoolCode);
        await migrateTransport(schoolCode);
        await migrateEvents(schoolCode);
        await migrateHRExtended(schoolCode);
      } catch (err) {
        console.error(`  ❌ Error migrating ${schoolCode}:`, err.message);
        stats.errors++;
      }
    }

    console.log("\n" + "═".repeat(50));
    console.log("✅ Migration complete!\n");
    console.log("   📊 Results:");
    console.log(`      Schools:  ${stats.schools}`);
    console.log(`      Staff:    ${stats.staff}`);
    console.log(`      Students: ${stats.students}`);
    console.log(`      Parents:  ${stats.parents}`);
    console.log(`      Sections: ${stats.sections}`);
    console.log(`      Users:    ${stats.users}`);
    console.log(`      Attendance: ${stats.attendance} daily records`);
    console.log(`      Att.Summary: ${stats.attSummary} monthly summaries`);
    console.log(`      Homework: ${stats.homework}`);
    console.log(`      Submissions: ${stats.submissions}`);
    console.log(`      Leaves:   ${stats.leaves}`);
    console.log(`      Exams:    ${stats.exams || 0}`);
    console.log(`      Marks:    ${stats.marks || 0}`);
    console.log(`      Results:  ${stats.results || 0}`);
    console.log(`      Fee Structures: ${stats.feeStructures || 0}`);
    console.log(`      Fee Demands: ${stats.feeDemands || 0}`);
    console.log(`      Defaulters: ${stats.feeDefaulters || 0}`);
    console.log(`      Receipts: ${stats.feeReceipts || 0}`);
    console.log(`      Circulars: ${stats.circulars || 0}`);
    console.log(`      Transport: ${stats.transport || 0}`);
    console.log(`      Events:   ${stats.events || 0}`);
    console.log(`      HR Extended: ${stats.hrExtended || 0}`);
    console.log(`      Errors:   ${stats.errors}`);
    console.log("\n   🔗 View in console: https://console.firebase.google.com/project/graders-1c047/firestore/databases/schoolsync/data");
  } catch (err) {
    console.error("\n❌ Fatal error:", err);
    process.exit(1);
  }

  process.exit(0);
}

main();
