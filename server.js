
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  connectTimeout:20000,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.message);
    return;
  }
  console.log("Connected to MySQL database.");
});

app.get("/api/products", (req, res) => {
  db.query("SELECT * FROM products", (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(results);
  });
});

const PORT = process.env.PORT || 5000;
const bcrypt = require("bcryptjs");

const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dns = require('dns');
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port:587,
  secure:false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const token = crypto.randomBytes(32).toString("hex");

  db.query(
    "INSERT INTO users (email, password, verified, verification_token) VALUES (?, ?, 0, ?)",
    [email, hashedPassword, token],
    async (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      const verifyUrl = `http://localhost:5000/api/verify/${token}`;

      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "Verify your Curvy Minds account",
          html: `<p>Click the link below to verify your account:</p><a href="${verifyUrl}">${verifyUrl}</a>`,
        });
      } catch (mailErr) {
        console.error("Email failed to send:", mailErr.message);
      }

      res.json({ message: "Registered. Please check your email to verify your account." });
    }
  );
});

app.get("/api/verify/:token", (req, res) => {
  const { token } = req.params;
  db.query(
    "UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?",
    [token],
    (err, result) => {
      if (err) return res.status(500).send("Something went wrong.");
      if (result.affectedRows === 0) return res.status(400).send("Invalid or expired link.");
      res.send("Your email has been verified! You can now log in.");
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: "Invalid email or password" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid email or password" });

    if (!user.verified) {
      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    res.json({ id: user.id, email: user.email });
  });
});


app.post("/api/orders", (req, res) => {
  const { user_email, items, total } = req.body;
  if (!user_email || !items || !total) {
    return res.status(400).json({ error: "Missing order details" });
  }

  db.query(
    "INSERT INTO orders (user_email, items, total, status) VALUES (?, ?, ?, 'pending')",
    [user_email, JSON.stringify(items), total],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: result.insertId, message: "Order placed successfully" });
    }
  );
});

app.get("/api/orders/:email", (req, res) => {
  const { email } = req.params;
  db.query("SELECT * FROM orders WHERE user_email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
app.get("/api/admin/orders", (req, res) => {
  db.query("SELECT * FROM orders ORDER BY created_at DESC", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
