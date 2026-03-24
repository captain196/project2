const { getFirestore } = require("../config/firebase");

/**
 * Get a document by collection and ID.
 * @returns {Object|null} Document data with id, or null if not found.
 */
async function getDoc(collection, docId) {
  const snap = await getFirestore().collection(collection).doc(docId).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

/**
 * Set (create/overwrite) a document.
 * @param {Object} options - { merge: true } for partial updates.
 */
async function setDoc(collection, docId, data, options = {}) {
  await getFirestore().collection(collection).doc(docId).set(data, options);
}

/**
 * Update specific fields on an existing document.
 */
async function updateDoc(collection, docId, data) {
  await getFirestore().collection(collection).doc(docId).update(data);
}

/**
 * Delete a document.
 */
async function deleteDoc(collection, docId) {
  await getFirestore().collection(collection).doc(docId).delete();
}

/**
 * Query documents in a collection.
 * @param {string} collection - Collection name
 * @param {Array} conditions - Array of [field, operator, value] tuples
 * @param {Object} options - { orderBy, limit, startAfter }
 * @returns {Array} Array of { id, ...data }
 */
async function query(collection, conditions = [], options = {}) {
  let ref = getFirestore().collection(collection);

  for (const [field, op, value] of conditions) {
    ref = ref.where(field, op, value);
  }

  if (options.orderBy) {
    const [field, direction] = Array.isArray(options.orderBy)
      ? options.orderBy
      : [options.orderBy, "asc"];
    ref = ref.orderBy(field, direction);
  }

  if (options.limit) {
    ref = ref.limit(options.limit);
  }

  if (options.startAfter) {
    ref = ref.startAfter(options.startAfter);
  }

  const snap = await ref.get();
  return snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
}

/**
 * Batch write — up to 500 operations.
 * @param {Array} operations - [{ type: "set"|"update"|"delete", collection, docId, data, options }]
 */
async function batchWrite(operations) {
  const db = getFirestore();
  const batch = db.batch();

  for (const op of operations) {
    const ref = db.collection(op.collection).doc(op.docId);
    switch (op.type) {
      case "set":
        batch.set(ref, op.data, op.options || {});
        break;
      case "update":
        batch.update(ref, op.data);
        break;
      case "delete":
        batch.delete(ref);
        break;
    }
  }

  await batch.commit();
}

/**
 * Get Firestore server timestamp value.
 */
function serverTimestamp() {
  const admin = require("firebase-admin");
  return admin.firestore.FieldValue.serverTimestamp();
}

module.exports = { getDoc, setDoc, updateDoc, deleteDoc, query, batchWrite, serverTimestamp };
