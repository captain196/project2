const admin = require("firebase-admin");

let db = null;

function initFirebase() {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(
        JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
      ),
      databaseURL: process.env.FIREBASE_DATABASE_URL,
    });
  }
  db = admin.database();
  return db;
}

function getFirebaseDb() {
  if (!db) throw new Error("Firebase not initialized");
  return db;
}

module.exports = { initFirebase, getFirebaseDb, admin };
