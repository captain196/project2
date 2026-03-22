const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema(
  {
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const deviceSchema = new mongoose.Schema(
  {
    deviceId: { type: String, required: true },     // Unique fingerprint from app (Android ID / IDFV)
    deviceName: { type: String, default: "" },       // "Samsung Galaxy S24", "iPhone 15"
    platform: { type: String, enum: ["android", "ios", "web"], default: "android" },
    os: { type: String, default: "" },               // "Android 14", "iOS 17.4"
    appVersion: { type: String, default: "" },       // "1.0.0"
    boundAt: { type: Date, default: Date.now },
    lastUsedAt: { type: Date, default: Date.now },
    status: { type: String, enum: ["active", "blocked"], default: "active" },
    fcmToken: { type: String, default: null },   // FCM push notification token
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    email: { type: String, lowercase: true, default: null },
    name: { type: String, required: true },
    phone: { type: String, default: null },
    role: {
      type: String,
      required: true,
      enum: ["super_admin", "school_super_admin", "admin", "student", "teacher"],
    },
    schoolId: { type: String, default: null },
    schoolCode: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    createdBy: { type: String, required: true },
    status: { type: String, default: "Active", enum: ["Active", "Inactive"] },
    refreshTokens: { type: [refreshTokenSchema], default: [] },

    // ── Student profile fields (for mobile app quick access) ──
    className: { type: String, default: null },        // "9th"
    section: { type: String, default: null },           // "A"
    rollNo: { type: String, default: null },
    fatherName: { type: String, default: null },
    motherName: { type: String, default: null },
    dob: { type: String, default: null },               // "15-08-2010"
    admissionDate: { type: String, default: null },     // "01-04-2024"
    gender: { type: String, default: null },
    profilePic: { type: String, default: null },        // Firebase Storage URL
    schoolDisplayName: { type: String, default: null }, // "Mount Litera Zee School"
    parentDbKey: { type: String, default: null },       // Firebase Users/Parents/{key} — resolves legacy vs SCH_ schools

    // ── Teacher profile fields (for mobile app quick access) ──
    position: { type: String, default: null },          // "Senior Teacher"
    department: { type: String, default: null },        // "Science"
    staffRoles: { type: [String], default: [] },        // ["ROLE_TEACHER", "ROLE_LAB_ASST"]
    primaryRole: { type: String, default: null },       // "ROLE_TEACHER"
    classesAssigned: { type: [String], default: [] },   // ["Class 9th 'A'", "Class 10th 'B'"]
    subjects: { type: [String], default: [] },          // ["Mathematics", "Science"]

    // ── Device binding (primarily for student/teacher mobile app) ──
    devices: { type: [deviceSchema], default: [] },
    parentPhone: { type: String, default: null },    // Parent's phone for OTP on new device binding
    deviceBindingMethod: { type: String, enum: ["otp", "auto"], default: "otp" }, // "otp" = OTP required for new devices
  },
  {
    timestamps: false,
    versionKey: false,
    collection: "users",
  }
);

// Unique email only for admin roles (super_admin, school_super_admin, admin).
// Students/teachers can share emails — siblings use parent's email, teachers may share school email.
userSchema.index(
  { email: 1 },
  {
    unique: true,
    partialFilterExpression: {
      email: { $type: "string" },
      role: { $in: ["super_admin", "school_super_admin", "admin"] },
    },
  }
);

module.exports = mongoose.model("User", userSchema);
