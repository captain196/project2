const { getFirebaseDb } = require("../config/firebase");

function ref(path) {
  return getFirebaseDb().ref(path);
}

async function set(path, data) {
  await ref(path).set(data);
}

async function get(path) {
  const snap = await ref(path).once("value");
  return snap.val();
}

async function update(path, data) {
  await ref(path).update(data);
}

async function remove(path) {
  await ref(path).remove();
}

module.exports = { set, get, update, remove };
