require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const helmet = require("helmet");
const cors = require("cors");
const multer = require("multer");
const XLSX = require("xlsx");
const path = require("path");
const fs = require("fs");
const SibApiV3Sdk = require("sib-api-v3-sdk");
const admin = require("firebase-admin");

// ================== MULTER (Excel upload) ==================
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter: (req, file, cb) => {
    const allowed = [
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
      "application/vnd.ms-excel", // .xls
      "text/csv",
    ];
    if (allowed.includes(file.mimetype)) return cb(null, true);
    cb(new Error("Only .xlsx, .xls, and .csv files are allowed"));
  },
});

// ================== FIREBASE ==================
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  ),
});

// ================== EXPRESS SETUP ==================
const app = express();

// Security headers
app.use(helmet());

// CORS – adjust origin to your frontend domain(s)
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",")
      : "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Body size limit to prevent large-payload attacks
app.use(express.json({ limit: "50kb" }));

// Health check for Fly.io
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ================== DB SETUP ==================
const client = new MongoClient(process.env.MONGODB_URI);
let usersCollection;
let otpCollection;
let loginAttemptsCollection;
let countersCollection;
let dbReady = false;

// ================== CONSTANTS ==================
const SALT_ROUNDS = 12;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESET_TOKEN_EXPIRY = "10m";
const MIN_PASSWORD_LENGTH = 8;

// Max simultaneous device logins per role
const MAX_DEVICES = { student: 5, teacher: 3, admin: 2 };

// ================== RATE LIMITER ==================
const inMemoryRateLimitStore = new Map();

// Periodic cleanup of expired rate-limit entries (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of inMemoryRateLimitStore) {
    if (now > value.windowEnd) {
      inMemoryRateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.ip ||
    "unknown"
  );
}

function createInMemoryRateLimiter({ windowMs, max, keyFn }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = keyFn(req);
    const current = inMemoryRateLimitStore.get(key);

    if (!current || now > current.windowEnd) {
      inMemoryRateLimitStore.set(key, { count: 1, windowEnd: now + windowMs });
      return next();
    }

    if (current.count >= max) {
      return res
        .status(429)
        .json({ success: false, message: "Too many requests. Please try again later." });
    }

    current.count += 1;
    inMemoryRateLimitStore.set(key, current);
    next();
  };
}

const loginRateLimiter = createInMemoryRateLimiter({
  windowMs: 60 * 1000,
  max: 10,
  keyFn: (req) =>
    `login:${getClientIp(req)}:${(req.body?.userId || "").toLowerCase()}`,
});

const otpRateLimiter = createInMemoryRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) =>
    `otp:${getClientIp(req)}:${(req.body?.email || "").toLowerCase()}`,
});

// ================== VALIDATORS ==================
function isStrongPassword(password) {
  if (typeof password !== "string") return false;
  if (password.length < MIN_PASSWORD_LENGTH) return false;
  return /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ================== HELPERS ==================
function generateOtp() {
  // Cryptographically secure OTP instead of Math.random()
  return crypto.randomInt(100000, 999999).toString();
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function normalizeEmail(email) {
  return email.toLowerCase().trim();
}

async function findUserByEmail(email) {
  return usersCollection.findOne({ email: normalizeEmail(email) });
}

async function findUserByUserId(userId) {
  return usersCollection.findOne({ userId: userId.trim() });
}

// ================== TOKEN GENERATION ==================
function generateAccessToken(user) {
  return jwt.sign(
    { userId: user.userId, tokenVersion: user.tokenVersion || 0 },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    {
      userId: user.userId,
      tokenVersion: user.tokenVersion || 0,
      jti: uuidv4(),
      createdAt: Date.now(),
    },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "60d" }
  );
}

// ================== BREVO ==================
const brevoClient = SibApiV3Sdk.ApiClient.instance;
brevoClient.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;
const brevoEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();

// ================== MIDDLEWARE ==================

// DB readiness check – prevents crashes if DB connection failed
function requireDB(req, res, next) {
  if (!dbReady) {
    return res.status(503).json({ success: false, message: "Service temporarily unavailable" });
  }
  next();
}

// Auth middleware – uses try/catch (no callback) for proper error handling
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    usersCollection
      .findOne({ userId: decoded.userId })
      .then((user) => {
        if (!user || user.tokenVersion !== decoded.tokenVersion) {
          return res
            .status(401)
            .json({ success: false, message: "Session expired, please log in again" });
        }
        req.user = decoded;
        next();
      })
      .catch((err) => {
        console.error("Auth DB error:", err);
        res.status(500).json({ success: false, message: "Server error" });
      });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ success: false, message: "Access token expired" });
    }
    return res.status(403).json({ success: false, message: "Invalid token" });
  }
}

// Simple admin check middleware (checks an `isAdmin` flag on the user document)
function requireAdmin(req, res, next) {
  usersCollection
    .findOne({ userId: req.user.userId })
    .then((user) => {
      if (!user || !user.isAdmin) {
        return res.status(403).json({ success: false, message: "Admin access required" });
      }
      next();
    })
    .catch((err) => {
      console.error("Admin check error:", err);
      res.status(500).json({ success: false, message: "Server error" });
    });
}

// Apply DB readiness check to all routes
app.use(requireDB);

// ================== REGISTRATION HELPERS ==================

const VALID_ROLES = ["student", "teacher", "admin"];
const ROLE_PREFIX = { student: "STU", teacher: "TEA", admin: "ADM" };
const DEFAULT_PASSWORD_LENGTH = 10;

// Generate a secure random default password (sent to user via email)
function generateDefaultPassword() {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const all = upper + lower + digits;

  // Guarantee at least one of each required type
  let password = "";
  password += upper[crypto.randomInt(upper.length)];
  password += lower[crypto.randomInt(lower.length)];
  password += digits[crypto.randomInt(digits.length)];

  for (let i = 3; i < DEFAULT_PASSWORD_LENGTH; i++) {
    password += all[crypto.randomInt(all.length)];
  }

  // Shuffle so the guaranteed chars aren't always first
  return password
    .split("")
    .sort(() => crypto.randomInt(3) - 1)
    .join("");
}

// Atomic auto-increment ID: STU0001, TEA0001, ADM0001 per school
async function generateNextId(role, schoolId) {
  const prefix = ROLE_PREFIX[role];
  if (!prefix) throw new Error("Invalid role");

  const counterKey = `${schoolId}_${role}`;
  const result = await countersCollection.findOneAndUpdate(
    { _id: counterKey },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: "after" }
  );

  const seq = result.seq || result.value?.seq;
  return `${prefix}${String(seq).padStart(4, "0")}`;
}

function sanitizeString(val) {
  if (typeof val !== "string") return "";
  return val.trim();
}

function isValidPhone(phone) {
  if (typeof phone !== "string") return false;
  return /^\+?[0-9]{7,15}$/.test(phone.replace(/\s/g, ""));
}

// ================== ROUTES ==================

app.get("/", (req, res) => {
  res.send("✅ Backend is running!");
});

// ========== REGISTER SINGLE USER (student / teacher / admin) ==========
// Admin-only: manually create one user at a time
app.post("/register", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { role, password, phone, email, schoolId, schoolName, name } = req.body;

    // --- Validate role ---
    if (!VALID_ROLES.includes(role)) {
      return res.status(400).json({
        success: false,
        message: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}`,
      });
    }

    // --- Validate required fields ---
    if (!schoolId || !schoolName) {
      return res.status(400).json({ success: false, message: "schoolId and schoolName are required" });
    }

    // --- Email handling based on role ---
    // Teachers & admins: email required + must be unique
    // Students: email optional, multiple accounts can share one email
    let nEmail = null;
    if (role === "teacher" || role === "admin") {
      if (!isValidEmail(email)) {
        return res.status(400).json({ success: false, message: "Valid email is required for teacher/admin" });
      }
      nEmail = normalizeEmail(email);

      const existingEmail = await usersCollection.findOne({ email: nEmail, role });
      if (existingEmail) {
        return res.status(409).json({ success: false, message: `Email already registered for a ${role}` });
      }
    } else {
      // Student: email optional
      if (email && isValidEmail(email)) {
        nEmail = normalizeEmail(email);
      }
    }

    // --- Validate phone (optional but validated if provided) ---
    const cleanPhone = sanitizeString(phone);
    if (cleanPhone && !isValidPhone(cleanPhone)) {
      return res.status(400).json({ success: false, message: "Invalid phone number format" });
    }

    // --- Password: use provided or generate default ---
    const rawPassword = typeof password === "string" && password.length > 0 ? password : generateDefaultPassword();
    if (!isStrongPassword(rawPassword)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters with upper, lower, and number",
      });
    }

    // --- Generate userId ---
    const userId = await generateNextId(role, schoolId);

    // --- Hash password ---
    const hashedPassword = await bcrypt.hash(rawPassword, SALT_ROUNDS);

    // --- Build user document ---
    const userDoc = {
      userId,
      password: hashedPassword,
      phone: cleanPhone || null,
      email: nEmail,
      schoolId: sanitizeString(schoolId),
      schoolName: sanitizeString(schoolName),
      name: sanitizeString(name) || null,
      role,
      isAdmin: role === "admin",
      tokenVersion: 0,
      refreshTokens: [],
      createdAt: new Date(),
      createdBy: req.user.userId,
    };

    await usersCollection.insertOne(userDoc);

    // --- Send welcome email with credentials (only if email provided) ---
    if (nEmail) {
      try {
        await brevoEmailApi.sendTransacEmail({
          sender: { email: process.env.SENDER_EMAIL || "yugant196@gmail.com", name: "GraderIQ" },
          to: [{ email: nEmail }],
          subject: "Your GraderIQ Account",
          htmlContent: `
            <h2>Welcome to GraderIQ!</h2>
            <p>Your account has been created.</p>
            <p><strong>User ID:</strong> ${userId}</p>
            <p><strong>Password:</strong> ${rawPassword}</p>
            <p><strong>School:</strong> ${schoolName}</p>
            <p>Please change your password after first login.</p>
          `,
        });
      } catch (emailErr) {
        console.error("Welcome email failed:", emailErr);
      }
    }

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user: {
        userId,
        email: nEmail,
        phone: cleanPhone || null,
        schoolId: sanitizeString(schoolId),
        schoolName: sanitizeString(schoolName),
        role,
        name: sanitizeString(name) || null,
      },
      // Only return password in response if it was auto-generated
      ...(typeof password !== "string" || password.length === 0
        ? { generatedPassword: rawPassword }
        : {}),
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({ success: false, message: "Duplicate userId or email" });
    }
    console.error("Register error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ========== BULK REGISTER STUDENTS (Excel upload) ==========
// Admin-only: upload .xlsx/.xls/.csv with student data
// Expected columns: name, email (optional), phone (optional) — password auto-generated
// Multiple students CAN share the same email (e.g. siblings with parent's email)
app.post(
  "/register/bulk",
  authenticateToken,
  requireAdmin,
  upload.single("file"),
  async (req, res) => {
    let filePath;
    try {
      if (!req.file) {
        return res.status(400).json({ success: false, message: "Excel/CSV file is required" });
      }
      filePath = req.file.path;

      const { schoolId, schoolName } = req.body;
      if (!schoolId || !schoolName) {
        return res.status(400).json({ success: false, message: "schoolId and schoolName are required" });
      }

      // --- Parse Excel ---
      const workbook = XLSX.readFile(filePath);
      const sheetName = workbook.SheetNames[0];
      const rows = XLSX.utils.sheet_to_json(workbook.Sheets[sheetName], { defval: "" });

      if (!rows.length) {
        return res.status(400).json({ success: false, message: "File is empty" });
      }
      if (rows.length > 500) {
        return res.status(400).json({ success: false, message: "Maximum 500 students per upload" });
      }

      // --- Normalize column headers (case-insensitive) ---
      const normalizedRows = rows.map((row) => {
        const normalized = {};
        for (const key of Object.keys(row)) {
          normalized[key.toLowerCase().trim()] = row[key];
        }
        return normalized;
      });

      // --- Validate & prepare all users ---
      const results = { created: [], failed: [] };
      const usersToInsert = [];

      for (let i = 0; i < normalizedRows.length; i++) {
        const row = normalizedRows[i];
        const rowNum = i + 2; // Excel row (1-indexed header + data)
        const name = sanitizeString(String(row.name || ""));
        const email = sanitizeString(String(row.email || ""));
        const phone = sanitizeString(String(row.phone || ""));

        // Name is required
        if (!name) {
          results.failed.push({ row: rowNum, name: "(empty)", reason: "Name is required" });
          continue;
        }

        // Validate email only if provided (optional for students)
        let nEmail = null;
        if (email) {
          if (!isValidEmail(email)) {
            results.failed.push({ row: rowNum, name, reason: "Invalid email format" });
            continue;
          }
          nEmail = normalizeEmail(email);
        }

        // Validate phone if provided
        if (phone && !isValidPhone(phone)) {
          results.failed.push({ row: rowNum, name, reason: "Invalid phone format" });
          continue;
        }

        // Generate ID and password
        const userId = await generateNextId("student", schoolId);
        const rawPassword = generateDefaultPassword();
        const hashedPassword = await bcrypt.hash(rawPassword, SALT_ROUNDS);

        usersToInsert.push({
          doc: {
            userId,
            password: hashedPassword,
            phone: phone || null,
            email: nEmail,
            schoolId: sanitizeString(schoolId),
            schoolName: sanitizeString(schoolName),
            name,
            role: "student",
            isAdmin: false,
            tokenVersion: 0,
            refreshTokens: [],
            createdAt: new Date(),
            createdBy: req.user.userId,
          },
          rawPassword,
          name,
          email: nEmail,
          userId,
          rowNum,
        });
      }

      // --- Bulk insert ---
      if (usersToInsert.length > 0) {
        await usersCollection.insertMany(usersToInsert.map((u) => u.doc), { ordered: false });

        for (const u of usersToInsert) {
          // Send welcome email only if email was provided
          if (u.email) {
            brevoEmailApi
              .sendTransacEmail({
                sender: { email: process.env.SENDER_EMAIL || "yugant196@gmail.com", name: "GraderIQ" },
                to: [{ email: u.email }],
                subject: "Your GraderIQ Account",
                htmlContent: `
                  <h2>Welcome to GraderIQ!</h2>
                  <p><strong>Student:</strong> ${u.name}</p>
                  <p><strong>User ID:</strong> ${u.userId}</p>
                  <p><strong>Password:</strong> ${u.rawPassword}</p>
                  <p><strong>School:</strong> ${schoolName}</p>
                  <p>Please change your password after first login.</p>
                `,
              })
              .catch((err) => console.error(`Email failed for ${u.email}:`, err));
          }

          results.created.push({
            row: u.rowNum,
            userId: u.userId,
            name: u.name,
            email: u.email || "(none)",
            generatedPassword: u.rawPassword,
          });
        }
      }

      res.status(201).json({
        success: true,
        message: `Bulk registration complete: ${results.created.length} created, ${results.failed.length} failed`,
        totalProcessed: normalizedRows.length,
        created: results.created,
        failed: results.failed,
      });
    } catch (error) {
      console.error("Bulk register error:", error);
      res.status(500).json({ success: false, message: "Server error during bulk registration" });
    } finally {
      // Always clean up uploaded file
      if (filePath) {
        fs.unlink(filePath, () => {});
      }
    }
  }
);

// ---------- LOOKUP ACCOUNTS BY EMAIL (for password reset) ----------
// Step 1: Parent enters email → sees HOW MANY accounts exist + masked preview
// Does NOT reveal userIds — those come only after OTP verification

const lookupRateLimiter = createInMemoryRateLimiter({
  windowMs: 60 * 1000,
  max: 5,
  keyFn: (req) => `lookup:${getClientIp(req)}`,
});

function maskName(name) {
  if (!name) return null;
  return name
    .split(" ")
    .map((word) => {
      if (word.length <= 2) return word[0] + "*";
      return word[0] + "*".repeat(word.length - 2) + word[word.length - 1];
    })
    .join(" ");
}

app.post("/lookup_accounts", lookupRateLimiter, async (req, res) => {
  const { email } = req.body;
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Valid email required" });
  }

  const nEmail = normalizeEmail(email);
  const users = await usersCollection
    .find({ email: nEmail }, { projection: { name: 1, role: 1, schoolName: 1, _id: 0 } })
    .toArray();

  // Always return success (even if empty) to prevent email enumeration
  res.json({
    success: true,
    count: users.length,
    // Only masked info — enough for parent to confirm, but no userId exposed
    accounts: users.map((u, i) => ({
      index: i,
      maskedName: maskName(u.name),
      role: u.role,
      schoolName: u.schoolName || null,
    })),
  });
});

// ---------- SEND OTP ----------
// Step 2: Parent requests OTP to prove they own the email
// No userId needed — OTP is tied to the email itself
app.post("/send_otp", otpRateLimiter, async (req, res) => {
  const { email } = req.body;
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Valid email required" });
  }

  // Always return the same response to prevent enumeration
  const genericResponse = { success: true, message: "If the account exists, OTP has been sent" };

  const nEmail = normalizeEmail(email);

  // Check if any account uses this email
  const user = await usersCollection.findOne(
    { email: nEmail },
    { projection: { _id: 1 } }
  );

  if (!user) {
    return res.json(genericResponse);
  }

  const otp = generateOtp();
  const otpHash = hashOtp(otp);
  const now = new Date();

  // OTP keyed by email (not userId) — parent proves they own the email
  await otpCollection.updateOne(
    { email: nEmail },
    {
      $set: {
        otpHash,
        attempts: 0,
        createdAt: now,
        expiresAt: new Date(Date.now() + OTP_EXPIRY_MS),
      },
    },
    { upsert: true }
  );

  try {
    await brevoEmailApi.sendTransacEmail({
      sender: { email: process.env.SENDER_EMAIL || "yugant196@gmail.com", name: "GraderIQ" },
      to: [{ email: nEmail }],
      subject: "Your Password Reset OTP",
      htmlContent: `
        <p>Someone requested a password reset for an account linked to this email.</p>
        <p>Your OTP is:</p>
        <h2>${otp}</h2>
        <p>This OTP is valid for 5 minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
      `,
    });

    res.json(genericResponse);
  } catch (err) {
    console.error("Brevo error:", err);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ---------- VERIFY OTP ----------
// Step 3: Parent enters OTP → proves they own the email
// Returns the FULL list of accounts linked to this email, each with its own resetToken
// Parent then picks which account to reset on the next screen
app.post("/verify_otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!isValidEmail(email) || typeof otp !== "string") {
    return res.status(400).json({ success: false, message: "email and otp are required" });
  }

  const nEmail = normalizeEmail(email);

  const record = await otpCollection.findOne({ email: nEmail });

  if (!record) return res.json({ success: false, message: "OTP not found" });

  if (record.attempts >= 5) {
    return res.json({ success: false, message: "Too many attempts" });
  }

  if (new Date() > record.expiresAt) {
    await otpCollection.deleteOne({ email: nEmail });
    return res.json({ success: false, message: "OTP expired" });
  }

  if (hashOtp(otp) !== record.otpHash) {
    await otpCollection.updateOne({ email: nEmail }, { $inc: { attempts: 1 } });
    return res.json({ success: false, message: "Invalid OTP" });
  }

  // OTP verified — parent proved they own this email
  await otpCollection.deleteOne({ email: nEmail });

  // Fetch ALL accounts linked to this email
  const users = await usersCollection
    .find({ email: nEmail }, { projection: { userId: 1, name: 1, role: 1, schoolName: 1, _id: 0 } })
    .toArray();

  // Generate a separate resetToken for each account
  // Each token is locked to a specific userId — can only reset that one account
  const accounts = users.map((u) => ({
    userId: u.userId,
    name: u.name || null,
    role: u.role,
    schoolName: u.schoolName || null,
    resetToken: jwt.sign(
      { userId: u.userId, email: nEmail, purpose: "password_reset" },
      process.env.JWT_SECRET,
      { expiresIn: RESET_TOKEN_EXPIRY }
    ),
  }));

  res.json({
    success: true,
    message: "OTP verified. Select an account to reset password.",
    accounts,
  });
});

// ---------- LOGIN ----------
app.post("/login", loginRateLimiter, async (req, res) => {
  const { userId, password } = req.body;
  if (typeof userId !== "string" || typeof password !== "string") {
    return res.status(400).json({ success: false, message: "Invalid payload" });
  }

  const normalizedUserId = userId.trim();

  try {
    const loginAttempt = await loginAttemptsCollection.findOne({ userId: normalizedUserId });
    if (loginAttempt?.lockUntil && loginAttempt.lockUntil > new Date()) {
      return res
        .status(429)
        .json({ success: false, message: "Account temporarily locked. Try again later." });
    }

    const user = await usersCollection.findOne({ userId: normalizedUserId });
    const validPassword = user ? await bcrypt.compare(password, user.password) : false;

    if (!validPassword) {
      const now = new Date();
      await loginAttemptsCollection.updateOne(
        { userId: normalizedUserId },
        {
          $inc: { failCount: 1 },
          $set: { updatedAt: now },
          $setOnInsert: { createdAt: now },
        },
        { upsert: true }
      );

      const updatedAttempt = await loginAttemptsCollection.findOne({ userId: normalizedUserId });
      if (updatedAttempt && updatedAttempt.failCount >= LOGIN_MAX_ATTEMPTS) {
        await loginAttemptsCollection.updateOne(
          { userId: normalizedUserId },
          {
            $set: {
              lockUntil: new Date(Date.now() + LOGIN_LOCK_MS),
              updatedAt: new Date(),
            },
            $unset: { failCount: "" },
          }
        );
      }

      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // ✅ Enforce per-role device limit
    const maxDevices = MAX_DEVICES[user.role] || 2;
    let currentTokens = Array.isArray(user.refreshTokens) ? user.refreshTokens : [];

    // If at limit, evict the oldest session(s) to make room for the new one
    if (currentTokens.length >= maxDevices) {
      // Sort by createdAt ascending (oldest first), keep only the newest (maxDevices - 1)
      currentTokens.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      currentTokens = currentTokens.slice(-(maxDevices - 1));

      await usersCollection.updateOne(
        { userId: user.userId },
        { $set: { refreshTokens: currentTokens } }
      );
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await usersCollection.updateOne(
      { userId: user.userId },
      {
        $push: {
          refreshTokens: { tokenHash: hashToken(refreshToken), createdAt: new Date() },
        },
      }
    );
    await loginAttemptsCollection.deleteOne({ userId: normalizedUserId });

    res.json({
      success: true,
      message: "Login successful",
      userId: user.userId,
      schoolId: user.schoolId || null,
      schoolName: user.schoolName,
      role: user.role,
      name: user.name || null,
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- REFRESH TOKEN ----------
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const user = await usersCollection.findOne({ userId: decoded.userId });
    if (!user) return res.status(403).json({ message: "User not found" });

    const incomingTokenHash = hashToken(refreshToken);
    const refreshTokens = Array.isArray(user.refreshTokens) ? user.refreshTokens : [];

    // Only match by hash – no legacy plaintext token comparison
    const storedToken = refreshTokens.find((rt) => rt.tokenHash === incomingTokenHash);
    if (!storedToken) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    if (user.tokenVersion !== decoded.tokenVersion) {
      return res.status(403).json({ message: "Session expired" });
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    const newRefreshTokenHash = hashToken(newRefreshToken);

    const updatedRefreshTokens = refreshTokens.map((rt) => {
      if (rt.tokenHash === incomingTokenHash) {
        return { tokenHash: newRefreshTokenHash, createdAt: new Date() };
      }
      return rt;
    });

    await usersCollection.updateOne(
      { userId: user.userId },
      { $set: { refreshTokens: updatedRefreshTokens } }
    );

    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    console.error("Refresh error:", err);
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

// ---------- FIND USERS BY PHONE ----------
app.post("/find_users_by_phone", authenticateToken, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ success: false, message: "Phone number is required" });
    }

    const users = await usersCollection.find({ phone }).toArray();

    return res.json({
      success: true,
      count: users.length,
      users: users.map((user) => ({
        userId: user.userId,
        schoolId: user.schoolId || null,
        phone: user.phone,
      })),
    });
  } catch (error) {
    console.error("Error finding users by phone:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- FIND USERS BY EMAIL ----------
app.post("/find_users_by_email", authenticateToken, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "EmailId is required" });
    }

    // Normalize email before querying
    const nEmail = normalizeEmail(email);
    const users = await usersCollection.find({ email: nEmail }).toArray();

    return res.json({
      success: true,
      count: users.length,
      users: users.map((user) => ({
        userId: user.userId,
        schoolId: user.schoolId || null,
        email: user.email,
      })),
    });
  } catch (error) {
    console.error("Error finding users by email:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- CHANGE PASSWORD (logged-in user) ----------
app.post("/change_password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (typeof currentPassword !== "string" || typeof newPassword !== "string") {
    return res
      .status(400)
      .json({ success: false, message: "Current and new password are required" });
  }
  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 8 characters and include upper, lower, and number",
    });
  }

  try {
    const user = await usersCollection.findOne({ userId: req.user.userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await usersCollection.updateOne(
      { userId: req.user.userId },
      {
        $set: { password: hashedPassword, refreshTokens: [] },
        $inc: { tokenVersion: 1 },
      }
    );

    res.json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- RESET PASSWORD (OTP verified user) ----------
// Uses userId from the reset token to target the exact account
app.post("/reset_password", async (req, res) => {
  const { resetToken, newPassword } = req.body;

  if (typeof resetToken !== "string" || typeof newPassword !== "string") {
    return res
      .status(400)
      .json({ success: false, message: "resetToken and newPassword required" });
  }
  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 8 characters and include upper, lower, and number",
    });
  }

  try {
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    if (decoded.purpose !== "password_reset" || !decoded.userId) {
      return res.status(401).json({ success: false, message: "Invalid reset token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    // Target by userId (exact account) instead of email (which may be shared)
    const result = await usersCollection.updateOne(
      { userId: decoded.userId },
      {
        $set: { password: hashedPassword, refreshTokens: [] },
        $inc: { tokenVersion: 1 },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    res.status(401).json({ success: false, message: "Invalid or expired reset token" });
  }
});

// ---------- ADMIN FORCE RESET PASSWORD ----------
// Admin can reset any user's password without OTP
// Useful when a student/parent can't do it themselves
app.post("/admin/reset_password", authenticateToken, requireAdmin, async (req, res) => {
  const { targetUserId, newPassword } = req.body;

  if (typeof targetUserId !== "string") {
    return res.status(400).json({ success: false, message: "targetUserId is required" });
  }

  // Password: use provided or auto-generate
  const rawPassword = typeof newPassword === "string" && newPassword.length > 0
    ? newPassword
    : generateDefaultPassword();

  if (!isStrongPassword(rawPassword)) {
    return res.status(400).json({
      success: false,
      message: "Password must be at least 8 characters with upper, lower, and number",
    });
  }

  try {
    const targetUser = await usersCollection.findOne({ userId: targetUserId.trim() });
    if (!targetUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(rawPassword, SALT_ROUNDS);
    await usersCollection.updateOne(
      { userId: targetUser.userId },
      {
        $set: { password: hashedPassword, refreshTokens: [] },
        $inc: { tokenVersion: 1 },
      }
    );

    // Notify the user via email if they have one
    if (targetUser.email) {
      brevoEmailApi
        .sendTransacEmail({
          sender: { email: process.env.SENDER_EMAIL || "yugant196@gmail.com", name: "GraderIQ" },
          to: [{ email: targetUser.email }],
          subject: "Your GraderIQ Password Has Been Reset",
          htmlContent: `
            <h2>Password Reset by Admin</h2>
            <p>Your password for account <strong>${targetUser.userId}</strong> has been reset by an administrator.</p>
            <p><strong>New Password:</strong> ${rawPassword}</p>
            <p>Please change your password after logging in.</p>
          `,
        })
        .catch((err) => console.error("Admin reset email failed:", err));
    }

    res.json({
      success: true,
      message: `Password reset for ${targetUser.userId}`,
      userId: targetUser.userId,
      emailSent: !!targetUser.email,
      // Return generated password so admin can tell the student verbally if needed
      ...(typeof newPassword !== "string" || newPassword.length === 0
        ? { generatedPassword: rawPassword }
        : {}),
    });
  } catch (error) {
    console.error("Admin reset error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- PROFILE ----------
app.get("/profile", authenticateToken, async (req, res) => {
  res.json({ success: true, message: "Welcome!", userId: req.user.userId });
});

// ---------- LOGOUT (per device) ----------
app.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ success: false, message: "No refresh token provided" });
  }

  try {
    const tokenHash = hashToken(refreshToken);
    await usersCollection.updateOne(
      { "refreshTokens.tokenHash": tokenHash },
      { $pull: { refreshTokens: { tokenHash } } }
    );

    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ success: false, message: "Server error during logout" });
  }
});

// ---------- LOGOUT ALL ----------
app.post("/logout_all", authenticateToken, async (req, res) => {
  await usersCollection.updateOne(
    { userId: req.user.userId },
    { $set: { refreshTokens: [] } }
  );
  res.json({ success: true, message: "Logged out from all devices" });
});

// ---------- NOTIFICATIONS (protected) ----------

// Send test notification – requires auth + admin
app.post("/send_test_notification", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { fcmToken, title, body, screen } = req.body;

    if (!fcmToken) {
      return res.status(400).json({ success: false, message: "FCM token required" });
    }

    const message = {
      data: {
        title: title || "",
        body: body || "",
        customKey: "customValue",
        type: "general",
        activity: screen || "",
      },
      token: fcmToken,
      android: {
        priority: "high",
        notification: { channelId: "channel_general", sound: "default" },
      },
      apns: {
        payload: { aps: { sound: "default" } },
      },
    };

    await admin.messaging().send(message);
    res.json({ success: true, message: "Test notification sent successfully" });
  } catch (error) {
    console.error("Error sending notification:", error);
    res.status(500).json({ success: false, message: "Failed to send notification" });
  }
});

// Send notification to specific device token – requires auth
app.post("/send_notification_to_token", authenticateToken, async (req, res) => {
  try {
    const { fcmToken, type, title, body, screen } = req.body;
    if (!fcmToken) {
      return res.status(400).json({ success: false, message: "FCM token required" });
    }

    const message = {
      data: {
        title: title || "",
        body: body || "",
        type: type || "",
        class: screen || "",
      },
      token: fcmToken,
      android: {
        priority: "high",
        notification: { channelId: "channel_personal", sound: "default" },
      },
    };

    await admin.messaging().send(message);
    res.json({ success: true, message: "Sent to specific device" });
  } catch (error) {
    console.error("Error sending:", error);
    res.status(500).json({ success: false, message: "Failed" });
  }
});

// Send notification to topic – requires auth + admin
app.post("/send_notification_to_topic", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { topic, type, title, body } = req.body;

    if (!topic) {
      return res.status(400).json({ success: false, message: "Topic required" });
    }

    const message = {
      notification: { title, body },
      data: {
        type: type || "",
        class: topic,
      },
      topic: topic,
      android: {
        priority: "high",
        notification: { channelId: "channel_class_updates", sound: "default" },
      },
    };

    await admin.messaging().send(message);
    res.json({ success: true, message: `Notification sent to topic: ${topic}` });
  } catch (error) {
    console.error("Error sending notification:", error.code, error.message);
    res.status(500).json({ success: false, message: "Failed to send notification" });
  }
});

// ================== ERROR HANDLER ==================
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({
    success: false,
    message: statusCode >= 500 ? "Internal server error" : err.message,
  });
});

// ================== DB CONNECT & START ==================
async function connectDB() {
  try {
    await client.connect();
    const db = client.db("graerIQ");
    usersCollection = db.collection("users");
    otpCollection = db.collection("password_otps");
    loginAttemptsCollection = db.collection("login_attempts");
    countersCollection = db.collection("counters");

    await usersCollection.createIndex({ userId: 1 }, { unique: true });
    // Email is NOT globally unique — multiple student accounts can share one email (siblings)
    // But teacher/admin emails must be unique within their role
    await usersCollection.createIndex({ email: 1 }); // non-unique, for fast lookups
    await usersCollection.createIndex(
      { email: 1, role: 1 },
      {
        unique: true,
        partialFilterExpression: { role: { $in: ["teacher", "admin"] }, email: { $ne: null } }
      }
    );
    await usersCollection.createIndex({ phone: 1 });
    await usersCollection.createIndex({ schoolId: 1, role: 1 }); // fast school-level queries

    await otpCollection.createIndex({ email: 1 }, { unique: true });
    await otpCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

    await loginAttemptsCollection.createIndex({ userId: 1 }, { unique: true });
    await loginAttemptsCollection.createIndex(
      { updatedAt: 1 },
      { expireAfterSeconds: 60 * 60 * 24 * 30 }
    );

    dbReady = true;
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("❌ DB connection error:", err);
    // Exit so the process manager (pm2, Docker, etc.) can restart
    process.exit(1);
  }
}

connectDB().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);

    // Keep-alive: ping self every 14 min to prevent Render free tier from sleeping
    if (process.env.RENDER_EXTERNAL_URL) {
      setInterval(() => {
        fetch(`${process.env.RENDER_EXTERNAL_URL}/health`).catch(() => {});
      }, 14 * 60 * 1000);
    }
  });
});