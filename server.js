require("dotenv").config();

const dns = require("dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

// ─── Validate environment ────────────────────────────────────────────────────
const { validateEnv } = require("./src/config/env");
validateEnv();

// ─── Express setup ───────────────────────────────────────────────────────────
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const app = express();

app.use(helmet());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim())
      : ["http://localhost", "http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Internal-Key"],
  })
);
app.use(express.json({ limit: "50kb" }));

// ─── Rate limiter (global) ──────────────────────────────────────────────────
const { apiLimiter } = require("./src/middleware/rateLimiter");
app.use("/api", apiLimiter);

// ─── Routes ──────────────────────────────────────────────────────────────────
const authRoutes = require("./src/routes/authRoutes");
const userRoutes = require("./src/routes/userRoutes");
const schoolRoutes = require("./src/routes/schoolRoutes");
const internalRoutes = require("./src/routes/internalRoutes");

app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/schools", schoolRoutes);
app.use("/internal", internalRoutes);

// ─── Health check (public) ──────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── Error handler ──────────────────────────────────────────────────────────
const { errorHandler } = require("./src/middleware/errorHandler");
app.use(errorHandler);

// ─── Start ──────────────────────────────────────────────────────────────────
const { connectDB } = require("./src/config/db");
const { initFirebase } = require("./src/config/firebase");
const { seedPrimarySuperAdmin } = require("./src/services/userService");

async function start() {
  // 1. Initialize Firebase
  initFirebase();

  // 2. Connect MongoDB
  await connectDB();

  // 2b. Migrate indexes: drop old userId-only unique → compound userId+schoolId
  try {
    const User = require("./src/models/User");
    const indexes = await User.collection.indexes();
    // Drop ALL email indexes — syncIndexes() will recreate the correct one
    for (const idx of indexes) {
      if (!idx.key || !idx.key.email || idx.name === '_id_') continue;
      try {
        await User.collection.dropIndex(idx.name);
        console.log(`🔧 Dropped email index "${idx.name}"`);
      } catch (e) { /* index already gone */ }
    }
    // Drop compound {userId, schoolId} if it exists
    const compoundUserIdx = indexes.find(
      (i) => i.key && i.key.userId === 1 && i.key.schoolId === 1 && i.unique
    );
    if (compoundUserIdx) {
      try {
        await User.collection.dropIndex(compoundUserIdx.name);
        console.log(`🔧 Dropped compound userId+schoolId index`);
      } catch (e) { /* already gone */ }
    }
    await User.syncIndexes();
  } catch (e) {
    console.warn("⚠️  Index migration note:", e.message);
  }

  // 3. Seed SUP0001 if first run
  await seedPrimarySuperAdmin();

  // 4. Start server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`   API:      http://localhost:${PORT}/api`);
    console.log(`   Health:   http://localhost:${PORT}/health`);

    // Keep-alive: ping self every 14 min to prevent Render free tier from sleeping
    if (process.env.RENDER_EXTERNAL_URL) {
      setInterval(() => {
        fetch(`${process.env.RENDER_EXTERNAL_URL}/health`).catch(() => {});
      }, 14 * 60 * 1000);
    }
  });
}

start().catch((err) => {
  console.error("❌ Startup failed:", err);
  process.exit(1);
});
