require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

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

app.get("/", (req, res) => {
  res.send("✅ Backend is running!");
});


// ✅ Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail", // you can use smtp if needed
  auth: {
    user: process.env.EMAIL_USER, // your email
    pass: process.env.EMAIL_PASS  // app-specific password
  }
});


// ✅ Temporary OTP store (replace with DB in production)
const otpStore = new Map();

// ✅ Send OTP via email
app.post("/send_otp", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit code
  otpStore.set(email, otp);

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Verification Code",
      text: `Your OTP is: ${otp}`,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ✅ Verify OTP
app.post("/verify_otp", (req, res) => {
  const { email, otp } = req.body;
  const savedOtp = otpStore.get(email);

  try{
    if (savedOtp && savedOtp.toString() === otp.toString()) {
      otpStore.delete(email); // clear OTP once used
      return res.json({ success: true, message: "OTP verified successfully" });
    } else {
      return res.json({ success: false, message: "Invalid or expired OTP" });
    }
  }catch (error){
    console.error("❌ Error verifying OTP:", error);
    res.status(500).json({ success: false, message: "Failed to verify OTP" });
  }
});

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

// ✅ Check if phone exists API
app.post("/find_users_by_phone", async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ success: false, message: "Phone number is required" });
    }

    const users = await usersCollection.find({ phone }).toArray();

    if (users.length > 0) {
      return res.json({
        success: true,
        count: users.length,
        users: users.map(user => ({
          userId: user.userId,
          schoolId: user.schoolId || null,
          phone: user.phone
        }))
      });
    } else {
      return res.json({ success: true, count: 0, users: [] });
    }
  } catch (error) {
    console.error("Error finding users by phone:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Check if email exists API
app.post("/find_users_by_email", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "EmailId is required" });
    }

    const users = await usersCollection.find({ email }).toArray();

    if (users.length > 0) {
      return res.json({
        success: true,
        count: users.length,
        users: users.map(user => ({
          userId: user.userId,
          schoolId: user.schoolId || null,
          phone: user.email
        }))
      });
    } else {
      return res.json({ success: true, count: 0, users: [] });
    }
  } catch (error) {
    console.error("Error finding users by email:", error);
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
