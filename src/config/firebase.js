const admin = require("firebase-admin");
const { getFirestore: getAdminFirestore } = require("firebase-admin/firestore");

let db = null;
let firestore = null;

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
  // Use the named 'schoolsync' database (Native mode).
  // The default database is in Datastore mode and cannot be used for Firestore client operations.
  firestore = getAdminFirestore(admin.app(), "schoolsync");
  return db;
}

function getFirebaseDb() {
  if (!db) throw new Error("Firebase not initialized");
  return db;
}

function getFirestore() {
  if (!firestore) throw new Error("Firebase not initialized");
  return firestore;
}

module.exports = { initFirebase, getFirebaseDb, getFirestore, admin };
