require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

// ✅ Use environment variable, no hardcoding here
const client = new MongoClient(process.env.MONGODB_URI);

let usersCollection;

async function connectDB() {
  try {
    await client.connect();
    const db = client.db("graerIQ"); // ✅ make sure db name is correct
    usersCollection = db.collection("users");
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("❌ DB connection error:", err);
  }
}

app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  try {
    const user = await usersCollection.findOne({ userId });
    if (user && user.password === password) {
      res.json({ success: true, message: "Login successful" });
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Start app after DB is ready
connectDB().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
