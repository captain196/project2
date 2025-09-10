require("dotenv").config();
const express = require("express");
const { MongoClient } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");

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


// 🔑 Generate Tokens
function generateAccessToken(user) {
  return jwt.sign(
    { userId: user.userId, tokenVersion: user.tokenVersion || 0 },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }   // short expiry
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    {
      userId: user.userId,
      tokenVersion: user.tokenVersion || 0,
      jti: uuidv4(),  // 👈 This must be inside the payload
      createdAt: Date.now() // 👈 ensures uniqueness
    },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "60d" }
  );
}



// ✅ Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail", // you can use smtp if needed
  auth: {
    user: process.env.EMAIL_USER, // your email
    pass: process.env.EMAIL_PASS  // app-specific password
  }
});


// ✅ Temporary OTP store 
const otpStore = new Map();

// ✅ Send OTP
app.post("/send_otp", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
  const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes from now

  otpStore.set(email, { otp: otp.toString(), expiry });

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
  const record = otpStore.get(email);

  if (!record) {
    return res.json({ success: false, message: "No OTP found or already used" });
  }

  if (Date.now() > record.expiry) {
    otpStore.delete(email); // cleanup
    return res.json({ success: false, message: "OTP expired" });
  }

  if (record.otp !== otp.toString()) {
    return res.json({ success: false, message: "Invalid OTP" });
  }

  // ✅ OTP is correct and valid
  otpStore.delete(email); // one-time use
  res.json({ success: true, message: "OTP verified successfully" });
});


// ✅ Login API
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;

  try {
    const user = await usersCollection.findOne({ userId });
    if (!user) {
      return res.json({ success: false, message: "Invalid UserID" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.json({ success: false, message: "Wrong Password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // ✅ Save refresh token in DB (so we can revoke it if needed)
     await usersCollection.updateOne(
      { userId: user.userId },
      { $push: { refreshTokens: { token: refreshToken, createdAt: new Date() } } }
    );

    res.json({
      success: true,
      message: "Login successful",
      userId: user.userId,
      schoolId: user.schoolId || null,
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Refresh Token API
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const user = await usersCollection.findOne({ userId: decoded.userId });
    if (!user || !user.refreshTokens.includes(refreshToken)) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }


    // ❌ Check if tokenVersion mismatch (force logout if password changed)
    if (user.tokenVersion !== decoded.tokenVersion) {
      return res.status(403).json({ message: "Session expired" });
    }

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // ✅ Update stored refresh token
    await usersCollection.updateOne(
      { userId: user.userId, "refreshTokens.token": refreshToken },
      { $set: { "refreshTokens.$.token": newRefreshToken, "refreshTokens.$.createdAt": new Date() } }
    );



    res.json({
      success: true,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });
  } catch (err) {
    console.error("Refresh error:", err);
    res.status(403).json({ message: "Invalid refresh token" });
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
          email: user.email
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

// ✅ Change/Update Password API
app.post("/change_password", async (req, res) => {
  const { userId, password } = req.body;

  if (!userId || !password) {
    return res.status(400).json({ success: false, message: "UserId and Password required" });
  }

  try {
    const user = await usersCollection.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Update password + increment tokenVersion
    await usersCollection.updateOne(
      { userId },
      { 
        $set: { password: hashedPassword },
        $inc: { tokenVersion: 1 }  // 👈 invalidate old tokens
      }
    );

    res.json({ success: true, message: "Password updated successfully, all sessions logged out" });
  } catch (error) {
    console.error("❌ Error updating password:", error);
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

  if (!token) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        // Token expired → frontend should call /refresh
        return res.status(401).json({ success: false, message: "Access token expired" });
      }
      // Invalid token (tampered, wrong secret, etc.)
      return res.status(403).json({ success: false, message: "Invalid token" });
    }

    // ✅ Check DB user + tokenVersion
    const user = await usersCollection.findOne({ userId: decoded.userId });
    if (!user || user.tokenVersion !== decoded.tokenVersion) {
      return res.status(401).json({ success: false, message: "Session expired, please log in again" });
    }

    req.user = decoded;
    next();
  });
}


// ✅ Logout API (per device)
app.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ success: false, message: "No refresh token provided" });

  try {
    // Remove the token from user's refreshTokens array
    await usersCollection.updateOne(
      { "refreshTokens.token": refreshToken },
      { $pull: { refreshTokens: { token: refreshToken } } }
    );

    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ success: false, message: "Server error during logout" });
  }
});

app.post("/logout_all", async (req, res) => {
  const { userId } = req.body;
  await usersCollection.updateOne(
    { userId },
    { $set: { refreshTokens: [] } }
  );
  res.json({ success: true, message: "Logged out from all devices" });
});



connectDB().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});

