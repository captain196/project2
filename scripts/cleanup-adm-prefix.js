#!/usr/bin/env node
/**
 * cleanup-adm-prefix.js
 *
 * Removes all ADM-prefixed user data from MongoDB and Firestore.
 * Migrates the ADM counter value into STA counter (additive).
 *
 * Run: node scripts/cleanup-adm-prefix.js
 */

require("dotenv").config();
const mongoose = require("mongoose");
const admin = require("firebase-admin");

const MONGODB_URI = process.env.MONGODB_URI + "graderIQ";

// ─── Firebase init ───────────────────────────────────────────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL,
  });
}
const rtdb = admin.database();
const fs = admin.firestore();
// Use the named 'schoolsync' Firestore database
const namedFs = new admin.firestore.Firestore({
  projectId: serviceAccount.project_id,
  credentials: {
    client_email: serviceAccount.client_email,
    private_key: serviceAccount.private_key,
  },
  databaseId: "schoolsync",
});

async function main() {
  console.log("\n╔══════════════════════════════════════════════════╗");
  console.log("║  ADM PREFIX CLEANUP — MongoDB + Firestore       ║");
  console.log("╚══════════════════════════════════════════════════╝\n");

  // ─── Step 1: Connect to MongoDB ────────────────────────────────────────────
  console.log("1️⃣  Connecting to MongoDB...");
  await mongoose.connect(MONGODB_URI);
  console.log("   ✅ Connected to graderIQ\n");

  const User = mongoose.connection.collection("users");
  const Counter = mongoose.connection.collection("counters");

  // ─── Step 2: Find ADM users in MongoDB ─────────────────────────────────────
  console.log("2️⃣  Finding ADM-prefixed users in MongoDB...");
  const admUsers = await User.find({ userId: /^ADM/ }).toArray();
  console.log(`   Found ${admUsers.length} ADM users:`);
  for (const u of admUsers) {
    console.log(`     ${u.userId} — ${u.name} (${u.role}) [${u.schoolCode || "no school"}]`);
  }

  // ─── Step 3: Delete ADM users from MongoDB ────────────────────────────────
  if (admUsers.length > 0) {
    console.log("\n3️⃣  Deleting ADM users from MongoDB...");
    const delResult = await User.deleteMany({ userId: /^ADM/ });
    console.log(`   ✅ Deleted ${delResult.deletedCount} ADM users from MongoDB\n`);
  } else {
    console.log("\n3️⃣  No ADM users to delete from MongoDB\n");
  }

  // ─── Step 4: Handle counters ───────────────────────────────────────────────
  console.log("4️⃣  Handling counters...");
  const admCounter = await Counter.findOne({ _id: "ADM" });
  const staCounter = await Counter.findOne({ _id: "STA" });

  console.log(`   ADM counter: ${admCounter ? admCounter.seq : "not found"}`);
  console.log(`   STA counter: ${staCounter ? staCounter.seq : "not found"}`);

  // Merge ADM counter into STA (take the higher value to avoid collisions)
  const admSeq = admCounter ? admCounter.seq : 0;
  const staSeq = staCounter ? staCounter.seq : 0;
  const newStaSeq = Math.max(admSeq, staSeq);

  if (newStaSeq > staSeq) {
    await Counter.updateOne(
      { _id: "STA" },
      { $set: { seq: newStaSeq } },
      { upsert: true }
    );
    console.log(`   ✅ STA counter set to ${newStaSeq} (merged from ADM=${admSeq}, STA=${staSeq})`);
  } else {
    // Ensure STA counter exists
    await Counter.updateOne(
      { _id: "STA" },
      { $setOnInsert: { seq: 0 } },
      { upsert: true }
    );
    console.log(`   ✅ STA counter already at ${staSeq} (>= ADM ${admSeq})`);
  }

  // Remove ADM counter
  if (admCounter) {
    await Counter.deleteOne({ _id: "ADM" });
    console.log("   ✅ ADM counter removed");
  }

  // Show all counters
  const allCounters = await Counter.find({}).toArray();
  console.log("\n   Current counters:");
  for (const c of allCounters) {
    console.log(`     ${c._id} → ${c.seq}`);
  }

  // ─── Step 5: Clean Firestore (default database) ───────────────────────────
  console.log("\n5️⃣  Cleaning ADM docs from Firestore (default)...");
  let fsDefaultCleaned = 0;
  for (const col of ["users", "staff"]) {
    try {
      const snap = await fs.collection(col).where("userId", ">=", "ADM").where("userId", "<", "ADN").get();
      for (const doc of snap.docs) {
        console.log(`   Deleting ${col}/${doc.id} (${doc.data().userId})`);
        await doc.ref.delete();
        fsDefaultCleaned++;
      }
    } catch (e) {
      console.log(`   ⚠️  ${col}: ${e.message}`);
    }
  }
  console.log(`   ✅ Removed ${fsDefaultCleaned} ADM docs from default Firestore\n`);

  // ─── Step 6: Clean Firestore (named 'schoolsync' database) ────────────────
  console.log("6️⃣  Cleaning ADM docs from Firestore (schoolsync)...");
  let fsNamedCleaned = 0;

  // Get all schools first
  try {
    const schoolsSnap = await namedFs.collection("schools").get();
    for (const schoolDoc of schoolsSnap.docs) {
      const schoolId = schoolDoc.id;
      // Check subcollections that might have ADM-prefixed docs
      for (const subCol of ["admins", "teachers", "staff"]) {
        try {
          const subSnap = await namedFs.collection(`users/${schoolId}/${subCol}`).get();
          for (const doc of subSnap.docs) {
            if (doc.id.startsWith("ADM")) {
              console.log(`   Deleting users/${schoolId}/${subCol}/${doc.id}`);
              await doc.ref.delete();
              fsNamedCleaned++;
            }
          }
        } catch (_) {}
      }
    }
  } catch (e) {
    console.log(`   ⚠️  schoolsync: ${e.message}`);
  }

  // Also check global superadmins
  try {
    const globalSnap = await namedFs.collection("users/global/superadmins").get();
    for (const doc of globalSnap.docs) {
      if (doc.id.startsWith("ADM")) {
        console.log(`   Deleting users/global/superadmins/${doc.id}`);
        await doc.ref.delete();
        fsNamedCleaned++;
      }
    }
  } catch (_) {}

  console.log(`   ✅ Removed ${fsNamedCleaned} ADM docs from schoolsync Firestore\n`);

  // ─── Step 7: Clean RTDB ADM references ─────────────────────────────────────
  console.log("7️⃣  Cleaning ADM refs from RTDB...");
  let rtdbCleaned = 0;

  // Check Users/Admin/{schoolCode}/ for ADM-prefixed keys
  const adminNodes = await rtdb.ref("Users/Admin").once("value");
  if (adminNodes.exists()) {
    const schools = adminNodes.val();
    for (const [schoolKey, schoolData] of Object.entries(schools || {})) {
      if (schoolKey === "Our Panel") continue; // Skip super admin
      if (typeof schoolData !== "object" || !schoolData) continue;
      for (const uid of Object.keys(schoolData)) {
        if (uid.startsWith("ADM")) {
          console.log(`   Removing Users/Admin/${schoolKey}/${uid}`);
          await rtdb.ref(`Users/Admin/${schoolKey}/${uid}`).remove();
          rtdbCleaned++;
        }
      }
    }
  }
  console.log(`   ✅ Removed ${rtdbCleaned} ADM nodes from RTDB\n`);

  // ─── Summary ───────────────────────────────────────────────────────────────
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║  CLEANUP COMPLETE                               ║");
  console.log("╠══════════════════════════════════════════════════╣");
  console.log(`║  MongoDB:   ${admUsers.length} ADM users deleted              ║`);
  console.log(`║  Counters:  ADM removed, STA = ${newStaSeq}                  ║`);
  console.log(`║  Firestore: ${fsDefaultCleaned + fsNamedCleaned} ADM docs removed                ║`);
  console.log(`║  RTDB:      ${rtdbCleaned} ADM nodes removed                ║`);
  console.log("╚══════════════════════════════════════════════════╝\n");

  await mongoose.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error("❌ Cleanup failed:", err);
  process.exit(1);
});
