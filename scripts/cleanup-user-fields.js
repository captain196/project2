/**
 * ONE-TIME CLEANUP: Remove irrelevant fields from existing MongoDB user documents.
 *
 * Usage: node scripts/cleanup-user-fields.js
 */
require("dotenv").config();
const mongoose = require("mongoose");
const User = require("../src/models/User");
const { FIELDS_TO_UNSET } = require("../src/models/User");

async function main() {
  await mongoose.connect(process.env.MONGODB_URI, { dbName: "graderIQ" });
  console.log("Connected to MongoDB (graderIQ)\n");

  const roles = Object.keys(FIELDS_TO_UNSET);

  for (const role of roles) {
    const fields = FIELDS_TO_UNSET[role];
    if (!fields.length) continue;

    const unset = {};
    for (const f of fields) unset[f] = "";

    const result = await User.updateMany({ role }, { $unset: unset });

    console.log(`${role}: cleaned ${result.modifiedCount}/${result.matchedCount} documents — removed ${fields.length} fields`);
    console.log(`   Fields: ${fields.join(", ")}\n`);
  }

  // Verify: show a sample document per role
  console.log("── Verification ──\n");
  for (const role of roles) {
    const sample = await User.findOne({ role }).lean();
    if (!sample) {
      console.log(`${role}: no documents found\n`);
      continue;
    }
    const keys = Object.keys(sample).filter(k => k !== "_id" && k !== "__v");
    console.log(`${role} (${sample.userId}): ${keys.length} fields`);
    console.log(`   Keys: ${keys.join(", ")}\n`);
  }

  await mongoose.disconnect();
  console.log("Done.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
