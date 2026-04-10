const Counter = require("../models/Counter");

/**
 * Atomically increment and return next sequence number.
 * Uses findOneAndUpdate with $inc — race-condition safe.
 *
 * @param {string} prefix - "SUP", "SSA", "STA", "TEA", "STU", "SCH"
 * @returns {Promise<number>} next sequence number
 */
async function getNextSequence(prefix) {
  const result = await Counter.findOneAndUpdate(
    { _id: prefix },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: "after" }
  );
  return result.seq;
}

/**
 * Return the next sequence number WITHOUT incrementing.
 * Preview only — for showing on forms before actual save.
 */
async function peekNextSequence(prefix) {
  const doc = await Counter.findOne({ _id: prefix });
  return doc ? doc.seq + 1 : 1;
}

module.exports = { getNextSequence, peekNextSequence };
