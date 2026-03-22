const REQUIRED = [
  "MONGODB_URI",
  "JWT_SECRET",
  "JWT_REFRESH_SECRET",
  "FIREBASE_SERVICE_ACCOUNT",
  "FIREBASE_DATABASE_URL",
  "AUTH_INTERNAL_SECRET",
];

function validateEnv() {
  const missing = REQUIRED.filter((k) => !process.env[k]);
  if (missing.length) {
    console.error("❌ Missing required env vars:", missing.join(", "));
    process.exit(1);
  }
}

module.exports = { validateEnv };
