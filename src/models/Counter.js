const mongoose = require("mongoose");

const counterSchema = new mongoose.Schema(
  {
    _id: { type: String, required: true }, // "DSA", "SSA", "ADM", "SCH"
    seq: { type: Number, default: 0 },
  },
  {
    versionKey: false,
    collection: "counters",
  }
);

module.exports = mongoose.model("Counter", counterSchema);
