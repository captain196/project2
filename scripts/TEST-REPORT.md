# SchoolSync ERP — Comprehensive Test Report
## Test School: SchoolSync Test Academy (SCH0002 / Login: 10003)
## Date: 2026-04-15

---

## TEST DATA SUMMARY

| Entity | Count | Firestore | RTDB | MongoDB |
|--------|-------|-----------|------|---------|
| School | 1 | schools/SCH0002 | System/Schools/SCH0002 | N/A |
| Session | 1 (2026-27) | sessions/2026-27 | Config/ActiveSession | N/A |
| Classes | 10 | classes/ (10 docs) | Config/Classes/ (10) | N/A |
| Sections | 5 | sections/ (5 docs) | Session paths | N/A |
| Subject groups | 3 | subjects/ (3 docs) | Subject_list/ (3) | N/A |
| SSA | 1 (SSA0003) | users/SCH0002/schoolsuperadmins/ | Users/Admin/10003/ | 1 user |
| Admin | 1 (STA0013) | users/SCH0002/admins/ | Users/Admin/10003/ | 1 user |
| Teachers | 4 (TEA0011-14) | users/SCH0002/teachers/ (4) | Users/Teachers/10003/ (4) | 4 users |
| Staff | 2 (STA0014-15) | users/SCH0002/staff/ (2) | Users/Admin/10003/ | 2 users |
| Students | 15 (STU0020-34) | schools/SCH0002/students/ (15) + users/SCH0002/students/ (15) | Users/Parents/10003/ (15) | 15 users |
| Subject Assignments | 3 docs | subjectAssignments/ | Academic/Subject_Assignments/ | teachers.classesAssigned[] |
| Timetables | 3 docs | timetables/ (3) | Time_table/ per class | N/A |
| Timetable Settings | 1 | timetableSettings/2026-27 | Time_table_settings | N/A |

---

## BUG TRACKER — MASTER LOG

### P0 — CRITICAL (System crash, data loss, security hole)

| # | Phase | System | Feature | Description | File:Line | Evidence |
|---|-------|--------|---------|-------------|-----------|----------|
| B1 | 10 | Grader_Teacher (Legacy) | Login | **Plaintext password comparison**: App does `pass == value` but RTDB stores bcrypt hash. Login is COMPLETELY BROKEN for any user with hashed password. | `Login_page.kt:101` | `pass == value` where value is `$2b$10$...` |
| B2 | 11 | Admin Panel | Fees | **Fee writes are RTDB-only**: `Fees.php submit_fees()` writes fee records to RTDB only. Firestore sync is async/best-effort. Fee data may not exist in Firestore (the designated primary DB). | `Fees.php:2124-2489` | RTDB at 2124, async Firestore at 2489 |

### P1 — HIGH (Feature broken, flow blocked, wrong DB primary)

| # | Phase | System | Feature | Description | File:Line | Evidence |
|---|-------|--------|---------|-------------|-----------|----------|
| B3 | 1 | Backend API | Auth | **No role gate on web-login**: Teachers and students CAN log into admin panel. No role check after password validation. | `internalRoutes.js:56-206` | TEA0009 and STU0001 both returned `success:true` |
| B4 | 6.5 | Admin Panel | Exam | **Foundation Problem 1 CONFIRMED**: `Exam_engine.php get_subject_list()` reads from `Subject_list/{classKey}` (catalog), NOT `Subject_Assignments`. Exams can include subjects no teacher is assigned to. | `Exam_engine.php:334` | `firebase->get("Schools/{school}/Subject_list/{listKey}")` |
| B5 | 11 | Admin Panel | Subject Assignments | **Write order violation**: RTDB written FIRST at line 517, Firestore at line 534. Should be Firestore first. | `Academic.php:517,534` | RTDB `set()` before `firestoreSet()` |
| B6 | 11 | Admin Panel | Sections | **Write order violation**: RTDB written FIRST at line 254, Firestore at line 261. | `Classes.php:254,261` | RTDB `set()` before DAL create |
| B7 | 11 | Admin Panel | Sessions | **Write order violation**: RTDB written FIRST at line 1978, Firestore at line 1987. | `School_config.php:1978,1987` | RTDB `set()` before Firestore update |
| B8 | 11 | Admin Panel | Attendance | **Write order violation**: RTDB written FIRST at line 838, Firestore at line 987 (single-day only). Bulk attendance has NO Firestore write. | `Attendance.php:838,987` | Bulk save = RTDB only |
| B9 | 8 | SchoolSyncTeacher | Messages | **Chat uses RTDB only**: MessagesRepository reads/writes to RTDB paths `Schools/{code}/Communication/Messages/`. No Firestore migration. | `MessagesRepository.kt` | All `firebaseService.readSnapshot()` calls |
| B10 | 9 | SchoolSyncParent | Messages | **Chat uses RTDB only**: Same as teacher app. MessageRepository reads from RTDB. | `MessageRepository.kt` | `firebaseService.readChildren()` |
| B11 | 9 | SchoolSyncParent | Red Flags | **Red Flags use RTDB only**: RedFlagRepository reads from `StudentFlags/{schoolCode}/{studentId}/`. No Firestore path exists. | `RedFlagRepository.kt` | RTDB-only, no Firestore equivalent |
| B12 | 0 | Backend API | School Creation | **schoolService.js writes RTDB only**: `createSchool()` writes to `System/Schools/{id}` in RTDB but does NOT write to Firestore `schools/{id}/` | `schoolService.js:32-71` | No Firestore write in function |

### P2 — MEDIUM (Feature partial, workaround exists)

| # | Phase | System | Feature | Description | File:Line | Evidence |
|---|-------|--------|---------|-------------|-----------|----------|
| B13 | 1 | Backend API | Auth | **SUP0001 password not `Test1234`**: Super admin seed used random/env password instead of project standard. | `userService.js:242` | `process.env.SUPER_ADMIN_PASSWORD \|\| generateRandomPassword()` |
| B14 | 0 | Backend API | ID Generation | **SCHCODE counter format**: Counter generates sequential integers (1,2,3...) instead of 5-digit codes (10001,10002...). The `fresh-setup.js` hardcoded 10001-10003 bypassing the counter. | `idGenerator.js` | Counter at 3 instead of 10003 (now fixed for test school) |
| B15 | 0 | Backend API | Seed Script | **fresh-setup.js Firestore writes to ROOT collections**: Writes to `staff/`, `users/`, `students/`, `events/` at root level instead of `schools/{code}/` subcollections. | `fresh-setup.js:203-246` | `fs.collection("staff").doc(uid).set(...)` |
| B16 | 8 | SchoolSyncTeacher | Students | **RTDB fallback still active**: StudentsViewModel falls back to RTDB if Firestore returns empty, masking data issues. | `StudentsViewModel.kt:184` | TODO comments indicate pending removal |
| B17 | 9 | SchoolSyncParent | Dashboard | **RTDB fallback functions**: Dashboard has `loadAttendanceFromRtdb()`, `loadFeesFromRtdb()`, etc. as fallbacks. Can mask Firestore data gaps. | `DashboardViewModel.kt` | Multiple fallback functions |
| B18 | 13 | All | Academic | **Foundation Problem 2**: No teacher specialization[], maxPeriodsWeek, maxPeriodsDay fields. Can assign any teacher to any subject without validation. | Teacher profile schema | Fields don't exist in Firestore, RTDB, or MongoDB |
| B19 | 13 | All | Attendance | **Foundation Problem 3**: Attendance is single char per day. No per-period attendance model for CBSE 75% per-subject rule (Class 9-12). | Attendance model | `dayWise: "PPAPLVV..."` string format |
| B20 | 13 | All | Academic | **Foundation Problem 4**: No session rollover. New session starts fresh with no reference to previous year's assignments. | Academic.php | No carry-forward logic |
| B21 | 13 | All | Academic | **Foundation Problem 5**: Class Teacher not visible in Academic Planner Tab 1. CT assigned in Staff module, disconnected from subject assignment view. | Academic.php Tab 1 | CT info not fetched/displayed |
| B22 | 11 | Admin Panel | Staff | **Write order — Staff.php**: `new_staff()` writes Firestore at 1293, RTDB at 1318, MongoDB at 1340. Order is F→R→M which is CORRECT, but the audit initially flagged it wrong. Re-verified: this one is actually correct. | `Staff.php:1293-1340` | DAL saveUser at 1293 (Firestore first) |

### P3 — LOW (UI glitch, cosmetic, non-blocking)

| # | Phase | System | Feature | Description |
|---|-------|--------|---------|-------------|
| B23 | 10 | Grader_Teacher | Login | Legacy app uses Firebase Email/Password auth (`create_user` + `signInWithEmailAndPassword`) instead of backend API. Bypasses all modern auth (JWT, device binding, lockout). |
| B24 | 10 | Grader_Teacher | Compatibility | Legacy app can only read data that was written to RTDB. If a feature writes to Firestore only, legacy app won't see it. Transition gap. |

---

## FOUNDATION PROBLEMS — VERIFIED STATUS

| # | Problem | Status | Evidence |
|---|---------|--------|----------|
| FP1 | Fragmented Subject Source | **CONFIRMED** | `Exam_engine.php:334` reads `Subject_list`, not `Subject_Assignments`. Exams disconnected from teaching assignments. |
| FP2 | No Teacher Capacity Modeling | **CONFIRMED** | No `specialization[]`, `maxPeriodsWeek`, `maxPeriodsDay` in any DB. Maths teacher can be assigned English with no warning. |
| FP3 | Attendance Not Period-Wise | **CONFIRMED** | Single char per day format. No per-period model exists. CBSE 75% per-subject rule impossible for Class 9-12. |
| FP4 | No Session Rollover | **CONFIRMED** | New session starts empty. No side-by-side view of last year's assignments during planning. |
| FP5 | Class Teacher Not in Academic Planner | **CONFIRMED** | CT assigned in Staff.php Duties/ClassTeacher. Academic Planner Tab 1 doesn't fetch or display CT info. |

---

## DATA SOURCE AUDIT — APP FEATURES

### SchoolSyncTeacher App

| Feature | Repository | Database | Status |
|---------|-----------|----------|--------|
| Login | AuthRepository | Backend API | CORRECT |
| Dashboard | TimetableFirestoreRepo + CommunicationFirestoreRepo | Firestore | CORRECT |
| Attendance | AttendanceFirestoreRepository | Firestore (primary) + RTDB (dual-write) | CORRECT |
| Marks | ExamFirestoreRepository | Firestore | CORRECT |
| Homework | HomeworkFirestoreRepository | Firestore | CORRECT |
| Timetable | TimetableFirestoreRepository | Firestore | CORRECT |
| Students | StudentFirestoreRepository | Firestore (primary) + RTDB (fallback) | HYBRID |
| Class dropdown | TeacherRepository (Duties) | RTDB | CORRECT (intentional) |
| **Messages** | MessagesRepository | **RTDB** | **WRONG — needs migration** |
| Notices | CommunicationFirestoreRepository | Firestore | CORRECT |
| Leave | LeaveFirestoreRepository | Firestore | CORRECT |
| Red Flags | RedFlagRepository | RTDB | RTDB-only (acceptable for now) |
| Profile | Multiple | Firestore + RTDB + API | CORRECT |

### SchoolSyncParent App

| Feature | Repository | Database | Status |
|---------|-----------|----------|--------|
| Login | AuthRepository | Backend API + Firestore enrichment | CORRECT |
| Dashboard | Mixed | Firestore (primary) + RTDB fallbacks | HYBRID |
| Attendance | AttendanceFirestoreRepository | Firestore | CORRECT |
| Homework | HomeworkFirestoreRepository | Firestore | CORRECT |
| Timetable | TimetableFirestoreRepository | Firestore | CORRECT |
| Fees | FeeFirestoreRepository | Firestore | CORRECT |
| Results | ExamFirestoreRepository | Firestore | CORRECT |
| **Messages** | MessageRepository | **RTDB** | **WRONG — needs migration** |
| Notices | CommunicationFirestoreRepository | Firestore | CORRECT |
| **Red Flags** | RedFlagRepository | **RTDB** | **WRONG — needs migration** |
| Events | EventFirestoreRepository | Firestore | CORRECT |

### Admin Panel Write Order Audit

| Controller | Function | Write Order | Status |
|-----------|----------|-------------|--------|
| Sis.php | save_admission() | Firestore → RTDB → MongoDB | CORRECT |
| Staff.php | new_staff() | Firestore → RTDB → MongoDB | CORRECT |
| Academic.php | save_subject_assignments() | **RTDB → Firestore** | WRONG |
| Classes.php | add_section() | **RTDB → Firestore** | WRONG |
| School_config.php | add_session() | **RTDB → Firestore** | WRONG |
| Attendance.php | save_student_attendance() | **RTDB → Firestore (single only)** | WRONG |
| Fees.php | submit_fees() | **RTDB only (async Firestore)** | WRONG |

---

## CROSS-SYSTEM DATA FLOW VERIFICATION

| Data Created In | Written To | Read By Teacher App | Read By Parent App | Match? |
|-----------------|-----------|--------------------|--------------------|--------|
| Admin: Subject Assignments | Firestore + RTDB + MongoDB | Firestore (subjectAssignments) + RTDB (Duties) | N/A | YES |
| Admin: Timetable | Firestore + RTDB | Firestore (timetables) | Firestore (timetables) | YES |
| Admin: Students | Firestore + RTDB + MongoDB | Firestore (students) | Firestore (students) | YES |
| Teacher: Attendance | Firestore + RTDB | N/A (self) | Firestore (attendance) | YES |
| Teacher: Homework | Firestore + RTDB | N/A (self) | Firestore (homework) | YES |
| Teacher: Marks | Firestore | N/A (self) | Firestore (marks) | YES |
| Teacher: Messages | RTDB ONLY | RTDB | RTDB | YES (but wrong DB) |
| Teacher: Red Flags | RTDB ONLY | N/A | RTDB | YES (but wrong DB) |
| Admin: Fees | RTDB (primary), async Firestore | N/A | Firestore (expects it) | **POTENTIAL MISMATCH** |

---

## PRIORITY FIX ORDER

### Must Fix Before Launch
1. **B3**: Add role gate to `/internal/web-login` — block teacher/student/staff roles
2. **B2**: Make Fees.php write Firestore synchronously BEFORE RTDB
3. **B4**: Fix Exam to read from Subject_Assignments (FP1)
4. **B12**: Add Firestore write to schoolService.js createSchool()

### Should Fix Soon
5. **B5-B8**: Fix write order in Academic.php, Classes.php, School_config.php, Attendance.php
6. **B9-B10**: Migrate Messages to Firestore in both apps
7. **B11**: Migrate Red Flags to Firestore
8. **B15**: Fix fresh-setup.js to use subcollection paths

### Foundation Fixes (Planned)
9. **FP2**: Add specialization/maxPeriods to teacher profile
10. **FP3**: Design period-wise attendance model
11. **FP4**: Session rollover with previous year reference
12. **FP5**: Surface Class Teacher in Academic Planner

---

## TEST SCHOOL REFERENCE

```
School Name:    SchoolSync Test Academy
School Code:    SCH0002 (Firebase key)
Login Code:     10003 (5-digit login)
Session:        2026-27
Password:       Test1234 (all users)

SSA:     SSA0003 (Test SSA)
Admin:   STA0013 (Test Admin)
Teachers: TEA0011 (Rajesh Kumar), TEA0012 (Priya Sharma),
          TEA0013 (Amit Verma), TEA0014 (Neha Singh)
Staff:    STA0014 (Accountant), STA0015 (Librarian)
Students: STU0020-STU0034 (15 students)
          Class 8th/A: STU0020-24 (5)
          Class 8th/B: STU0025-29 (5)
          Class 9th/A: STU0030-34 (5)

IDs file: scripts/test-school-ids.json
```
