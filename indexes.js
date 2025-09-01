require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

// ✅ DB setup
const client = new MongoClient(process.env.MONGODB_URI);
let usersCollection;

async function connectDB() {
  try {
    await client.connect();
    const db = client.db("graerIQ"); 
    usersCollection = db.collection("users");
    console.log("✅ Connected to MongoDB");
  } catch (err) {
    console.error("❌ DB connection error:", err);
  }
}

// ✅ Login API
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;
  console.log("Login attempt:", userId);

  try {
    const user = await usersCollection.findOne({ userId });
    console.log("User found:", user);

    if (!user) {
      return res.json({ success: false, message: "Invalid UserID" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    console.log("Password valid?", validPassword);

    if (!validPassword) {
      return res.json({ success: false, message: "Wrong Password" });
    }

    const token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      success: true,
      message: "Login successful",
      userId: user.userId || null,
      schoolId: user.schoolId || null,
      token,
    });
  } catch (err) {
    console.error("Login error:", err);  // 🔹 This will print the real error
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// ✅ Protected route example
app.get("/profile", authenticateToken, async (req, res) => {
  res.json({ success: true, message: "Welcome!", userId: req.user.userId });
});

// ✅ Middleware to check token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  

  if (!token) return res.status(401).json({ message: "No token provided" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });

    req.user = user; // attach user info
    next();
  });
}

connectDB().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
