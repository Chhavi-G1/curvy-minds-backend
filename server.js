const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Resend } = require("resend");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());


// ===============================
// DATABASE
// ===============================

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  connectTimeout: 20000,
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.message);
    return;
  }

  console.log("Connected to MySQL database.");
});


// ===============================
// RESEND
// ===============================

const resend = new Resend(process.env.RESEND_API_KEY);


// ===============================
// PRODUCTS
// ===============================

app.get("/api/products", (req, res) => {
  db.query("SELECT * FROM products", (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    res.json(results);
  });
});


// ===============================
// REGISTER
// ===============================

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password required",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString("hex");

    db.query(
      `INSERT INTO users
      (email, password, verified, verification_token)
      VALUES (?, ?, 0, ?)`,
      [email, hashedPassword, token],
      async (err, result) => {
        if (err) {
          console.error("Registration database error:", err.message);

          return res.status(500).json({
            error: err.message,
          });
        }

        const verifyUrl =
          `${process.env.BACKEND_URL}/api/verify/${token}`;

        try {
          const { data, error } = await resend.emails.send({
            from: process.env.EMAIL_FROM,
            to: [email],
            subject: "Verify your Curvy Minds account",
            html: `
              <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Welcome to Curvy Minds!</h2>

                <p>
                  Thanks for creating an account.
                  Please click the button below to verify your email address.
                </p>

                <p>
                  <a
                    href="${verifyUrl}"
                    style="
                      display:inline-block;
                      padding:12px 20px;
                      background:#6d3545;
                      color:white;
                      text-decoration:none;
                      border-radius:8px;
                    "
                  >
                    Verify My Email
                  </a>
                </p>

                <p>
                  If the button doesn't work, copy and paste this link
                  into your browser:
                </p>

                <p>${verifyUrl}</p>

                <p>— Curvy Minds</p>
              </div>
            `,
          });

          if (error) {
            console.error("========== RESEND ERROR ==========");
            console.error(error);
            console.error("==================================");

            return res.status(500).json({
              error:
                "Account created, but verification email could not be sent.",
            });
          }

          console.log("Verification email sent:", data);

          return res.json({
            message:
              "Registered successfully. Please check your email to verify your account.",
          });

        } catch (mailErr) {
          console.error("Email sending failed:", mailErr.message);

          return res.status(500).json({
            error:
              "Account created, but verification email could not be sent.",
          });
        }
      }
    );

  } catch (err) {
    console.error("Registration error:", err);

    return res.status(500).json({
      error: "Something went wrong during registration.",
    });
  }
});


// ===============================
// VERIFY EMAIL
// ===============================

app.get("/api/verify/:token", (req, res) => {
  const { token } = req.params;

  db.query(
    "UPDATE users SET verified = 1 WHERE verification_token = ?",
    [token],
    (err, result) => {
      if (err) {
        console.error("Verification error:", err.message);

        return res.status(500).send(
          "Something went wrong while verifying your email."
        );
      }

      if (result.affectedRows === 0) {
        return res.status(400).send(
          "Invalid or expired verification link."
        );
      }

      res.send(`
        <html>
          <body style="
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 60px;
          ">
            <h1>Email verified! 🎉</h1>

            <p>
              Your Curvy Minds account has been verified.
            </p>

            <p>
              You can now return to the website and log in.
            </p>
          </body>
        </html>
      `);
    }
  );
});


// ===============================
// LOGIN
// ===============================

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  console.log("LOGIN ATTEMPT");
  console.log("Email received:", email);

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {

      if (err) {
        console.error("LOGIN DB ERROR:", err.message);
        return res.status(500).json({ error: err.message });
      }

      console.log("Users found:", results.length);

      if (results.length === 0) {
        console.log("NO USER FOUND");
        return res.status(401).json({
          error: "Invalid email or password"
        });
      }

      const user = results[0];

      console.log("User found. Verified:", user.verified);
      console.log("Password hash exists:", !!user.password);

      const match = await bcrypt.compare(password, user.password);

      console.log("Password matches:", match);

      if (!match) {
        console.log("PASSWORD DOES NOT MATCH");
        return res.status(401).json({
          error: "Invalid email or password"
        });
      }

      if (!user.verified) {
        console.log("EMAIL NOT VERIFIED");
        return res.status(403).json({
          error: "Please verify your email before logging in."
        });
      }

      console.log("LOGIN SUCCESS");

      res.json({
        id: user.id,
        email: user.email
      });
    }
  );
});


// ===============================
// ORDERS
// ===============================

app.post("/api/orders", (req, res) => {
  const { user_email, items, total } = req.body;

  if (!user_email || !items || !total) {
    return res.status(400).json({
      error: "Missing order details",
    });
  }

  db.query(
    `INSERT INTO orders
    (user_email, items, total, status)
    VALUES (?, ?, ?, 'pending')`,
    [
      user_email,
      JSON.stringify(items),
      total,
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          error: err.message,
        });
      }

      res.json({
        id: result.insertId,
        message: "Order placed successfully",
      });
    }
  );
});


// ===============================
// USER ORDERS
// ===============================

app.get("/api/orders/:email", (req, res) => {
  const { email } = req.params;

  db.query(
    "SELECT * FROM orders WHERE user_email = ?",
    [email],
    (err, results) => {
      if (err) {
        return res.status(500).json({
          error: err.message,
        });
      }

      res.json(results);
    }
  );
});


// ===============================
// ADMIN ORDERS
// ===============================

app.get("/api/admin/orders", (req, res) => {
  db.query(
    "SELECT * FROM orders ORDER BY created_at DESC",
    (err, results) => {
      if (err) {
        return res.status(500).json({
          error: err.message,
        });
      }

      res.json(results);
    }
  );
});


// ===============================
// START SERVER
// ===============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});