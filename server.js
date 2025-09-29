const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const fs = require("fs");
const nodemailer = require("nodemailer");
const axios = require("axios");
const multer = require("multer");
const path = require("path");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;
const JWT_SECRET = "your-secret-key-change-in-production";
const USERS_FILE = "./users.json";
const RECAPTCHA_SECRET = "6LeNLXUrAAAAAMXWbJPhAsYVzlNQy3Tz_7--OvbY";

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(".")); // Serve static files from current directory
app.use(cookieParser());

// Set up CSRF protection middleware (using cookies)
const csrfProtection = csrf({ cookie: true });

// Nodemailer transporter (replace with your Gmail and app password)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "boey0587@gmail.com", // <-- your Gmail address
    pass: "dfiaarknwqpcfugr", // <-- your app password, no spaces
  },
});

// In-memory OTP store: { username: { otp, expires } }
let otpStore = {};

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper to load users from file
function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, "utf-8");
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

// Helper to save users to file
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

let users = loadUsers();

async function verifyRecaptcha(token) {
  const response = await axios.post(
    `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`
  );
  return response.data.success && response.data.score > 0.5;
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/Index.html log form.html");
});

// Register endpoint
app.post("/api/register", async (req, res) => {
  try {
    const {
      fullname,
      username,
      email,
      phone,
      password,
      confirmPassword,
      recaptchaToken,
    } = req.body;

    // Verify reCAPTCHA
    const isHuman = await verifyRecaptcha(recaptchaToken);
    if (!isHuman) {
      return res
        .status(400)
        .json({
          success: false,
          message: "reCAPTCHA failed. Are you a robot?",
        });
    }

    // Validation
    if (
      !fullname ||
      !username ||
      !email ||
      !phone ||
      !password ||
      !confirmPassword
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters long",
      });
    }

    // Check if user already exists
    const existingUser = users.find(
      (user) => user.username === username || user.email === email
    );

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Username or email already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = {
      id: users.length ? Math.max(...users.map((u) => u.id)) + 1 : 1,
      fullname,
      username,
      email,
      phone,
      password: hashedPassword,
      role: "user",
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveUsers(users);

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username, role: newUser.role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(201).json({
      success: true,
      message: "Registration successful!",
      token,
      user: {
        id: newUser.id,
        fullname: newUser.fullname,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      message: "Server error during registration",
    });
  }
});

// Login Step 1: Verify credentials, send OTP
app.post("/api/login", async (req, res) => {
  try {
    const { username, password, recaptchaToken } = req.body;

    // Verify reCAPTCHA
    const isHuman = await verifyRecaptcha(recaptchaToken);
    if (!isHuman) {
      return res
        .status(400)
        .json({
          success: false,
          message: "reCAPTCHA failed. Are you a robot?",
        });
    }

    if (!username || !password) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Username and password are required",
        });
    }
    const user = users.find((u) => u.username === username);
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password" });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password" });
    }
    // Generate OTP, store with expiry (5 min)
    const otp = generateOTP();
    otpStore[username] = { otp, expires: Date.now() + 5 * 60 * 1000 };
    // Send OTP to user's email
    const mailOptions = {
      from: "boey058@gmail.com", // TODO: Replace with your Gmail
      to: user.email,
      subject: "Your Login OTP",
      text: `Your OTP code is: ${otp}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Nodemailer error:", error);
        return res
          .status(500)
          .json({ success: false, message: "Error sending OTP email" });
      }
      res.json({
        success: true,
        mfaRequired: true,
        message: "OTP sent to your registered Gmail.",
      });
    });
  } catch (error) {
    console.error("Login error:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error during login" });
  }
});

// Login Step 2: Verify OTP, complete login
app.post("/api/verify-otp", (req, res) => {
  const { username, otp } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username" });
  }
  const record = otpStore[username];
  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired OTP" });
  }
  delete otpStore[username]; // Clean up
  // --- Record login activity and notification ---
  if (!user.loginActivity) user.loginActivity = [];
  if (!user.notifications) user.notifications = [];
  const now = new Date();
  const loginEntry = {
    time: now.toLocaleString(),
    ip: (
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress ||
      ""
    ).toString(),
  };
  user.loginActivity.push(loginEntry);
  // Keep only last 20 logins
  if (user.loginActivity.length > 20)
    user.loginActivity = user.loginActivity.slice(-20);
  user.notifications.push(
    `New login from ${loginEntry.ip} at ${loginEntry.time}`
  );
  if (user.notifications.length > 10)
    user.notifications = user.notifications.slice(-10);
  saveUsers(users);
  // Generate JWT token
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
  res.json({
    success: true,
    message: "Login successful!",
    token,
    user: {
      id: user.id,
      fullname: user.fullname,
      username: user.username,
      email: user.email,
      role: user.role,
    },
  });
});

// Get all users (for testing - remove in production)
app.get("/api/users", authorizeRoles("admin"), (req, res) => {
  const safeUsers = users.map((user) => ({
    id: user.id,
    fullname: user.fullname,
    username: user.username,
    email: user.email,
    phone: user.phone,
    createdAt: user.createdAt,
  }));
  res.json({ users: safeUsers });
});

// Protected route example
app.get("/api/profile", authorizeRoles("admin", "user"), (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "No token provided",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = users.find((u) => u.id === decoded.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        fullname: user.fullname,
        username: user.username,
        email: user.email,
        phone: user.phone,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
});

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ message: "No token provided" });
    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (!allowedRoles.includes(decoded.role)) {
        return res
          .status(403)
          .json({ message: "Forbidden: insufficient role" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
  };
}

// --- DASHBOARD API ENDPOINTS ---

// Helper: Find user by JWT token
function getUserFromToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return users.find((u) => u.id === decoded.userId);
  } catch (err) {
    return null;
  }
}

// GET /api/user-profile
// Returns user's name, email, and profile picture
app.get("/api/user-profile", authorizeRoles("admin"), (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  // Ensure profilePic exists
  if (!user.profilePic) user.profilePic = "";
  res.json({
    name: user.fullname || user.username,
    email: user.email,
    profilePic: user.profilePic,
  });
});

// GET /api/notifications
// Returns user's notifications array
app.get("/api/notifications", authorizeRoles("admin", "user"), (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  // Ensure notifications exists
  if (!user.notifications) user.notifications = [];
  res.json(user.notifications);
});

// GET /api/login-activity
// Returns user's recent login activity
app.get("/api/login-activity", authorizeRoles("admin", "user"), (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  // Ensure loginActivity exists
  if (!user.loginActivity) user.loginActivity = [];
  res.json(user.loginActivity.slice(-10).reverse()); // last 10, most recent first
});

// POST /api/change-password
// Changes user's password after verifying old password
app.post(
  "/api/change-password",
  authorizeRoles("admin", "user"),
  async (req, res) => {
    const user = getUserFromToken(req);
    if (!user)
      return res.status(401).json({ success: false, message: "Unauthorized" });
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.json({
        success: false,
        message: "Both old and new passwords are required.",
      });
    }
    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) {
      return res.json({
        success: false,
        message: "Old password is incorrect.",
      });
    }
    if (newPassword.length < 6) {
      return res.json({
        success: false,
        message: "New password must be at least 6 characters.",
      });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    saveUsers(users);
    res.json({ success: true, message: "Password changed successfully." });
  }
);

// POST /api/logout
// Dummy endpoint for client-side logout
app.post("/api/logout", (req, res) => {
  // For JWT, logout is handled client-side by deleting the token
  res.json({ success: true, message: "Logged out." });
});

// Multer setup for profile picture uploads
const profilePicDir = path.join(__dirname, "profile-pics");
if (!fs.existsSync(profilePicDir)) fs.mkdirSync(profilePicDir);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, profilePicDir);
  },
  filename: function (req, file, cb) {
    // Use user id and timestamp for unique filename
    const ext = path.extname(file.originalname);
    const user = getUserFromToken(req);
    if (!user) return cb(new Error("Unauthorized"));
    cb(null, `user${user.id}_${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// POST /api/upload-profile-pic
app.post(
  "/api/upload-profile-pic",
  authorizeRoles("admin", "user"),
  upload.single("profilePic"),
  (req, res) => {
    const user = getUserFromToken(req);
    if (!user)
      return res.status(401).json({ success: false, message: "Unauthorized" });
    if (!req.file)
      return res
        .status(400)
        .json({ success: false, message: "No file uploaded" });
    // Save relative path to user.profilePic
    user.profilePic = "/profile-pics/" + req.file.filename;
    saveUsers(users);
    res.json({
      success: true,
      message: "Profile picture updated",
      profilePic: user.profilePic,
    });
  }
);

// Provide CSRF token to frontend
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Apply CSRF protection to all POST routes after this point
app.use((req, res, next) => {
  if (req.method === "POST") {
    return csrfProtection(req, res, next);
  }
  next();
});

// --- END DASHBOARD API ENDPOINTS ---

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
