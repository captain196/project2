require("dotenv").config();
const mongoose = require("mongoose");
const User = require("./src/models/User");

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  const byRole = await User.aggregate([
    { $group: { _id: "$role", count: { $sum: 1 } } },
    { $sort: { count: -1 } },
  ]);
  console.log("User counts by role:");
  byRole.forEach((r) => console.log(`  ${r._id}: ${r.count}`));

  const adminRoles = ["super_admin", "school_super_admin", "admin", "principal"];
  const admins = await User.find({ role: { $in: adminRoles } })
    .select("userId name email role schoolId schoolCode status")
    .lean();
  console.log(`\nAdmin-tier users (${admins.length}):`);
  admins.forEach((u) =>
    console.log(
      `  role=${u.role}  userId=${u.userId}  name=${u.name}  email=${u.email}  schoolCode=${u.schoolCode}  status=${u.status}`
    )
  );
  await mongoose.disconnect();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
