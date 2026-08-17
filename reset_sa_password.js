require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./src/models/User");

const NEW_PW = "Admin@123";

(async () => {
  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  const sas = await User.find({ role: "super_admin" })
    .select("userId name email status role")
    .lean();

  console.log(`Found ${sas.length} super_admin user(s):`);
  sas.forEach((u) =>
    console.log(`  - userId=${u.userId}  name=${u.name}  email=${u.email}  status=${u.status}`)
  );

  if (sas.length === 0) {
    console.log("No super_admin found. Nothing to reset.");
    await mongoose.disconnect();
    process.exit(0);
  }

  const hash = await bcrypt.hash(NEW_PW, 12);
  const res = await User.updateMany(
    { role: "super_admin" },
    {
      $set: {
        password: hash,
        status: "Active",
        loginAttempts: 0,
        lockedUntil: null,
      },
    }
  );
  console.log(`\nReset password for ${res.modifiedCount} super_admin user(s) → "${NEW_PW}"`);

  await mongoose.disconnect();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
