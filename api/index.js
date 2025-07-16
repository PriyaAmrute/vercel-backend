import dotenv from "dotenv";
dotenv.config();
import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import multer from "multer";
import Razorpay from "razorpay";
import crypto from "crypto"





const app = express();
const salt = 10;

// file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "_" + file.originalname),
});
const upload = multer({ storage });

app.use(express.json());
cors({
  origin: true, // WARNING: Dev only
  credentials: true
});

app.use(cookieParser());
app.use("/uploads", express.static("uploads"));


const urlDB=`mysql://${process.env.MYSQLUSER}:${process.env.MYSQLPASSWORD}@${process.env.MYSQLHOST}:${process.env.MYSQLPORT}/${process.env.MYSQLDATABASE}`
// mysql
const db = mysql.createConnection(urlDB);

// middleware
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.json({ Status: "error", Error: "Not authenticated" });

  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) return res.json({ Status: "error", Error: "Invalid token" });
    req.email = decoded.email;
    req.role = decoded.role;
    req.user_id = decoded.id;
    req.isGoogle = decoded.isGoogle || false; // 👈 Add this
    next();
  });
};


const verifyAdmin = (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.json({ Status: "error", Error: "Not authenticated" });
  jwt.verify(token, "jwt-secret-key", (err, decoded) => {
    if (err) return res.json({ Status: "error", Error: "Invalid token" });
    if (decoded.role !== "superadmin")
      return res.json({ Status: "error", Error: "Unauthorized" });
    req.email = decoded.email;
    next();
  });
};

// login with streak-based status
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM login WHERE email=?", [email], (err, data) => {
    if (err) return res.json({ Status: "error", Error: err });
    if (data.length === 0)
      return res.json({ Status: "error", Error: "User not found" });

    bcrypt.compare(password, data[0].password, (err, result) => {
      if (err) return res.json({ Status: "error", Error: err });
      if (!result)
        return res.json({ Status: "error", Error: "Invalid credentials" });

      // streak tracking
      let streak = 1;
      const today = new Date();
      const lastLogin = data[0].last_login ? new Date(data[0].last_login) : null;

      if (lastLogin) {
        const diffDays = Math.floor(
          (today - lastLogin) / (1000 * 60 * 60 * 24)
        );
        if (diffDays === 1) {
          streak = data[0].login_streak + 1;
        }
      }

      // determine status
      let status = "inactive";
      if (data[0].role === "user" && streak >= 7) status = "active";
      if (data[0].role === "superadmin" && streak >= 15) status = "active";

      // update DB
      db.query(
        "UPDATE login SET login_streak=?, last_login=?, status=? WHERE id=?",
        [streak, today, status, data[0].id],
        (updateErr) => {
          if (updateErr) console.log(updateErr);
        }
      );

      // JWT token
      const token = jwt.sign(
        { email, role: data[0].role, id: data[0].id },
        "jwt-secret-key",
        { expiresIn: "1d" }
      );
      res.cookie("token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.json({
        Status: "success",
        role: data[0].role,
        name: data[0].name,
        profile: data[0].profile,
        status: status,
      });
    });
  });
});



// verify-session
app.get("/verify-session", verifyUser, (req, res) => {
  db.query(
    "SELECT name, profile, role, status FROM login WHERE email=?",
    [req.email],
    (err, result) => {
      if (err) return res.json({ Status: "error", Error: err });
      if (result.length === 0)
        return res.json({ Status: "error", Error: "User not found" });

      const user = result[0];

      // ✅ Allow superadmin without license check
      if (user.role === "superadmin") {
        return res.json({
          Status: "success",
          email: req.email,
          role: user.role,
          name: user.name,
          profile: user.profile,
          status: user.status,
        });
      }

      // ✅ If logged in via Google, skip license check
      if (req.isGoogle) {
        return res.json({
          Status: "success",
          email: req.email,
          role: user.role,
          name: user.name,
          profile: user.profile,
          status: user.status,
          message: "Google login - license bypassed",
        });
      }

      // ❌ For normal login, check license
     // ✅ Check if user was created by admin, skip license check if true
db.query(
  "SELECT created_by_admin_id FROM login WHERE email = ?",
  [req.email],
  (errCheck, userCheckResult) => {
    if (errCheck) return res.json({ Status: "error", Error: errCheck });

    const createdByAdmin = userCheckResult[0]?.created_by_admin_id;

    if (createdByAdmin) {
      return res.json({
        Status: "success",
        email: req.email,
        role: user.role,
        name: user.name,
        profile: user.profile,
        status: user.status,
        message: "Admin-created user - license bypassed",
      });
    }

    // Otherwise, check license as usual
    db.query(
      "SELECT license_start, license_duration_months FROM licenses WHERE client_email = ?",
      [req.email],
      (err2, licenses) => {
        if (err2) return res.json({ Status: "error", Error: err2 });

        if (licenses.length === 0) {
          return res.json({
            Status: "error",
            Error: "No license found for this account",
          });
        }

        const license = licenses[0];
        const start = new Date(license.license_start);
        const expiry = new Date(start);
        expiry.setMonth(expiry.getMonth() + license.license_duration_months);

        if (new Date() > expiry) {
          return res.json({
            Status: "expired",
            Message: "Your license has expired. Please contact admin.",
          });
        }

        res.json({
          Status: "success",
          email: req.email,
          role: user.role,
          name: user.name,
          profile: user.profile,
          status: user.status,
        });
      }
    );
  }
);

    }
  );
});

// logout
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ Status: "success" });
});

// get all users
app.get("/users", verifyUser, (req, res) => {
  if (req.role === "superadmin") {
    db.query(
      "SELECT id,name,email,profile,role,status FROM login",
      (err, data) => {
        if (err) return res.json({ Status: "error", Error: err });
        res.json({ Status: "success", Users: data });
      }
    );
  } else {
    db.query(
      "SELECT id,name,email,profile,role,status FROM login WHERE role='user' AND created_by_admin_id=?",
      [req.user_id],
      (err, data) => {
        if (err) return res.json({ Status: "error", Error: err });
        db.query(
          "SELECT user_limit FROM licenses WHERE client_email=?",
          [req.email],
          (err2, license) => {
            if (err2) return res.json({ Status: "error", Error: err2 });
            const userLimit = license.length > 0 ? license[0].user_limit : 5;
            res.json({ Status: "success", Users: data, userLimit });
          }
        );
      }
    );
  }
});

// add user
app.post("/register", verifyUser, upload.single("profile"), (req, res) => {
  const { name, email, password } = req.body;
  const profile = req.file ? req.file.filename : null;
  const createdBy = req.role === "admin" ? req.user_id : null; // set creator only if admin

  bcrypt.hash(password, salt, (err, hash) => {
    if (err) return res.json({ Status: "error", Error: err });

    const sql = "INSERT INTO login (name, email, password, profile, role, status, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?, ?)";
    db.query(sql, [name, email, hash, profile, "user", "inactive", createdBy], (err2, result) => {
      if (err2) return res.json({ Status: "error", Error: err2 });
      return res.json({ Status: "success" });
    });
  });
});


// update user
app.put("/users/:id", upload.single("profile"), verifyUser, (req, res) => {
  const { name, email, password } = req.body;
  const profile = req.file ? req.file.filename : "";
  if (password) {
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) return res.json({ Status: "error", Error: err });
      db.query(
        "UPDATE login SET name=?,email=?,password=?,profile=? WHERE id=?",
        [name, email, hash, profile, req.params.id],
        (err) => {
          if (err) return res.json({ Status: "error", Error: err });
          res.json({ Status: "success" });
        }
      );
    });
  } else {
    db.query(
      "UPDATE login SET name=?,email=?,profile=? WHERE id=?",
      [name, email, profile, req.params.id],
      (err) => {
        if (err) return res.json({ Status: "error", Error: err });
        res.json({ Status: "success" });
      }
    );
  }
});

// delete user
app.delete("/users/:id", verifyUser, (req, res) => {
  db.query("DELETE FROM login WHERE id=?", [req.params.id], (err) => {
    if (err) return res.json({ Status: "error", Error: err });
    res.json({ Status: "success" });
  });
});

// GET all leads
app.get('/api/leads', verifyUser, (req, res) => {
  const userId = req.user_id;
  const role = req.role;

  const query = role === 'superadmin'
    ? 'SELECT leads.*, login.name AS created_by_name FROM leads LEFT JOIN login ON leads.created_by = login.id'
    : 'SELECT * FROM leads WHERE created_by = ?';

  const params = role === 'superadmin' ? [] : [userId];

  db.query(query, params, (err, results) => {
    if (err) return res.json({ Error: "Server error" });
    res.json({ Leads: results });
  });
});

// ADD a lead
app.post('/api/leads/add', verifyUser, (req, res) => {
  const userId = req.user_id;
  const { name, email, phone, source, status, leadDate, remarks, template, followUpDate } = req.body;

  const insertLeadQuery = `
    INSERT INTO leads (name, email, phone, source, status, leadDate, remarks, template, followUpDate, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    insertLeadQuery,
    [name, email, phone, source, status, leadDate, remarks, template, followUpDate, userId],
    (err, result) => {
      if (err) {
        console.error("MySQL Insert Error:", err);
        return res.status(500).json({ Error: "MySQL Insert Error", Detail: err });
      }

      // ✅ Insert notification here
      const message = `🆕 New lead "${name}" added`;
      db.query(
        'INSERT INTO notifications (message) VALUES (?)',
        [message],
        (notifErr) => {
          if (notifErr) console.error("Notification insert error:", notifErr);
        }
      );

      return res.json({ Status: 'success' });
    }
  );
});


app.get('/api/notifications', verifyUser, (req, res) => {
  db.query(
    'SELECT * FROM notifications ORDER BY created_at DESC LIMIT 10',
    (err, result) => {
      if (err) return res.json({ Status: 'error', Error: err });
      res.json({ Status: 'success', Notifications: result });
    }
  );
});


// UPDATE a lead
// approve/reject license
app.put('/approve-license/:id', verifyUser, (req, res) => {
  const licenseId = req.params.id;
  const { status } = req.body;

  // Update license status
  const updateLicenseQuery = `UPDATE licenses SET approval_status = ? WHERE id = ?`;
  db.query(updateLicenseQuery, [status, licenseId], (err, result) => {
    if (err) return res.json({ Status: "error", Error: err });

    if (status === "approved") {
      // Get client email
      const getEmailQuery = `SELECT client_email FROM licenses WHERE id = ?`;
      db.query(getEmailQuery, [licenseId], (err, result) => {
        if (err || result.length === 0)
          return res.json({ Status: "error", Error: "License not found" });

        const clientEmail = result[0].client_email;

        // ✅ Update role in correct table
        const updateUserRoleQuery = `UPDATE login SET role = 'admin' WHERE email = ?`;
        db.query(updateUserRoleQuery, [clientEmail], (err) => {
          if (err) return res.json({ Status: "error", Error: err });

          return res.json({
            Status: "success",
            Message: "License approved and user promoted to admin",
          });
        });
      });
    } else {
      return res.json({
        Status: "success",
        Message: `License marked as ${status}`,
      });
    }
  });
});



// UPDATE a lead
app.put("/api/leads/:id", verifyUser, (req, res) => {
  const { name, email, phone, source, status, leadDate, remarks, followUpDate } = req.body;
  const id = req.params.id;
  const role = req.role;
  const userId = req.user_id;

  const query = role === "superadmin"
    ? `UPDATE leads SET name=?, email=?, phone=?, source=?, status=?, leadDate=?, remarks=?, followUpDate=? WHERE id=?`
    : `UPDATE leads SET name=?, email=?, phone=?, source=?, status=?, leadDate=?, remarks=?, followUpDate=? WHERE id=? AND created_by=?`;

  const values = role === "superadmin"
    ? [name, email, phone, source, status, leadDate, remarks, followUpDate, id]
    : [name, email, phone, source, status, leadDate, remarks, followUpDate, id, userId];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error("Update Error:", err);
      return res.status(500).json({ Status: "error", Error: err });
    }
    res.json({ Status: "success", Message: "Lead updated successfully" });
  });
});


// DELETE a lead
app.delete('/api/leads/:id', verifyUser, (req, res) => {
  const userId = req.user_id;
  const role = req.role;
  const id = req.params.id;

  const query = role === 'superadmin'
    ? 'DELETE FROM leads WHERE id = ?'
    : 'DELETE FROM leads WHERE id = ? AND created_by = ?';

  const params = role === 'superadmin' ? [id] : [id, userId];

  db.query(query, params, (err, result) => {
    if (err) return res.json({ Error: "Server error" });
    res.json({ Status: 'success' });
  });
});

// license
app.post("/add-license", verifyAdmin, (req, res) => {
  const {
    client_email,
    license_key,
    license_start,
    license_duration_months,
    user_limit,
  } = req.body;
  db.query(
    "INSERT INTO licenses (client_email,license_key,license_start,license_duration_months,user_limit) VALUES (?,?,?,?,?)",
    [client_email, license_key, license_start, license_duration_months, user_limit],
    (err) => {
      if (err) return res.json({ Status: "error", Error: err });
      res.json({ Status: "success" });
    }
  );
});

app.get("/get-all-licenses", verifyAdmin, (req, res) => {
  db.query("SELECT * FROM licenses", (err, result) => {
    if (err) return res.json({ Status: "error", Error: err });
    res.json({ Status: "success", Licenses: result });
  });
});

app.put("/update-license/:id", verifyAdmin, (req, res) => {
  const {
    client_email,
    license_key,
    license_start,
    license_duration_months,
    user_limit,
  } = req.body;
  db.query(
    "UPDATE licenses SET client_email=?, license_key=?, license_start=?, license_duration_months=?, user_limit=? WHERE id=?",
    [
      client_email,
      license_key,
      license_start,
      license_duration_months,
      user_limit,
      req.params.id,
    ],
    (err) => {
      if (err) return res.json({ Status: "error", Error: err });
      res.json({ Status: "success" });
    }
  );
});

app.delete("/delete-license/:id", verifyAdmin, (req, res) => {
  db.query("DELETE FROM licenses WHERE id=?", [req.params.id], (err) => {
    if (err) return res.json({ Status: "error", Error: err });
    res.json({ Status: "success" });
  });
});

// ✅ Google Login Route
app.post('/google-login', (req, res) => {
  const { name, email, profile } = req.body;

  if (!email) {
    return res.json({ Status: "error", Error: "Email is required" });
  }

  // Check if user already exists
  db.query("SELECT * FROM login WHERE email = ?", [email], (err, result) => {
    if (err) return res.json({ Status: "error", Error: err });

   if (result.length > 0) {
  const user = result[0];

  // 🔒 Block login if not yet approved
  if (user.status !== 'active') {
    return res.json({
      Status: "pending",
      Message: "Your account is awaiting approval by admin.",
    });
  }

  const token = jwt.sign(
    { email, role: user.role, id: user.id, isGoogle: true },
    "jwt-secret-key",
    { expiresIn: "1d" }
  );

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
  });

  return res.json({
    Status: "success",
    role: user.role,
    name: user.name,
    profile: user.profile || profile,
  });
}
 else {
      // If user does not exist, register as 'user' with no password
      db.query(
        "INSERT INTO login (name, email, profile, role, status) VALUES (?, ?, ?, 'user', 'inactive')",
        [name, email, profile],
        (err2, insertResult) => {
          if (err2) return res.json({ Status: "error", Error: err2 });

          const newUserId = insertResult.insertId;

       const token = jwt.sign(
  { email, role: "user", id: newUserId, isGoogle: true },
  "jwt-secret-key",
  { expiresIn: "1d" }
);




          res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
            secure: false,
            maxAge: 24 * 60 * 60 * 1000,
          });

         return res.json({
  Status: "pending",
  role: "user",
  name,
  profile,
  Message: "Account created. Waiting for admin approval.",
});

        }
      );
    }
  });
});

app.get("/get-plans", verifyAdmin, (req, res) => {
  db.query("SELECT * FROM plans", (err, results) => {
    if (err) return res.json({ Status: "error", Error: err });
    res.json({ Status: "success", Plans: results });
  });
});


app.post("/upgrade-plan", verifyAdmin, (req, res) => {
  const { client_email, plan_id } = req.body;

  const getPlanQuery = "SELECT * FROM plans WHERE id = ?";
  const updateLicenseQuery = `
    UPDATE licenses 
    SET plan_id = ?, user_limit = ?, license_start = NOW(), license_duration_months = 1, license_expiry = DATE_ADD(NOW(), INTERVAL 1 MONTH)
    WHERE client_email = ?
  `;

  db.query(getPlanQuery, [plan_id], (err, planResults) => {
    if (err || planResults.length === 0) {
      return res.json({ Status: "error", Error: "Plan not found" });
    }

    const selectedPlan = planResults[0];

    db.query(
      updateLicenseQuery,
      [selectedPlan.id, selectedPlan.user_limit, client_email],
      (err2) => {
        if (err2) return res.json({ Status: "error", Error: err2 });
        return res.json({ Status: "success", Message: "Plan upgraded successfully" });
      }
    );
  });
});



// Razorpay instance
app.post("/create-order", async (req, res) => {
  try {
    console.log("▶ create-order body:", req.body);

    const { amount } = req.body;
    if (!amount) {
      return res.status(400).json({ Status: "error", Error: "Amount is required" });
    }

    const order = await razorpay.orders.create({
      amount: amount * 100,
      currency: "INR",
    });

    res.json({ Status: "success", order });
  } catch (err) {
    console.error("❌ Razorpay error:", err); // log full error
    res.status(500).json({ Status: "error", Error: err.message });
  }
});


// Create Razorpay Order
app.post("/create-order", async (req, res) => {
  try {
    console.log("▶ create-order body:", req.body);
    console.log("▶ Razorpay ID:", process.env.RAZORPAY_KEY_ID);
    console.log("▶ Razorpay Secret:", process.env.RAZORPAY_SECRET);

    const { amount } = req.body;

    const order = await razorpay.orders.create({
      amount: amount * 100, // paise
      currency: "INR",
    });

    res.json({ Status: "success", order });
  } catch (err) {
    console.error("❌ Razorpay error:", err);
    res.status(500).json({ Status: "error", Error: err.message });
  }
});



// Verify and Activate Plan
app.post("/confirm-payment", verifyUser, (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    plan_id,
  } = req.body;

  const generated_signature = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(razorpay_order_id + "|" + razorpay_payment_id)
    .digest("hex");

  if (generated_signature !== razorpay_signature) {
    return res.json({ Status: "error", Error: "Signature verification failed" });
  }

  // Activate plan for logged-in user
  db.query(
    "SELECT * FROM plans WHERE id = ?",
    [plan_id],
    (err, results) => {
      if (err || results.length === 0) {
        return res.json({ Status: "error", Error: "Plan not found" });
      }

      const plan = results[0];
      db.query(
        `INSERT INTO licenses (client_email, license_key, license_start, license_duration_months, user_limit, plan_id)
         VALUES (?, ?, NOW(), 1, ?, ?)
         ON DUPLICATE KEY UPDATE 
           license_start=NOW(), license_duration_months=1, user_limit=?, plan_id=?`,
        [
          req.email,
          `KEY-${Date.now()}`,
          plan.user_limit,
          plan.id,
          plan.user_limit,
          plan.id,
        ],
        (err2) => {
          if (err2) return res.json({ Status: "error", Error: err2 });
          res.json({ Status: "success", Message: "Plan activated" });
        }
      );
    }
  );
});





app.get("/my-plan", verifyUser, (req, res) => {
  if (req.role !== "superadmin") return res.json({ Status: "error", Error: "Unauthorized" });

  db.query(
    "SELECT * FROM licenses WHERE client_email = ?",
    [req.email],
    (err, result) => {
      if (err) return res.json({ Status: "error", Error: err });
      if (result.length === 0) return res.json({ Status: "error", Error: "Plan not found" });

      res.json({ Status: "success", Plan: result[0] });
    }
  );
});
// Endpoint to handle Stripe webhook (server.js)
app.get("/test-razorpay", async (req, res) => {
  try {
    const testOrder = await razorpay.orders.create({
      amount: 1000, // ₹10
      currency: "INR",
    });
    console.log("✅ Test Razorpay Order Created:", testOrder);
    res.json({ Status: "success", order: testOrder });
  } catch (err) {
    console.error("❌ Razorpay Test Error:", err.message);
    res.status(500).json({ Status: "error", Error: err.message });
  }
});

app.get("/get-plans", verifyAdmin, (req, res) => {
  db.query("SELECT * FROM plans", (err, results) => {
    if (err) return res.json({ Status: "error", Error: err });
    res.json({ Status: "success", Plans: results });
  });
});
// PUT /update-plan/:id
// Old - WRONG column name
// UPDATE plans SET name = ?, price = ?, user_limit = ?, description = ? WHERE id = ?

// ✅ NEW - Corrected to match your DB column `permissions`
app.put("/update-plan/:id", (req, res) => {
  const planId = req.params.id;
  const { name, price, user_limit, description } = req.body;

  let parsedPermissions;
  try {
    parsedPermissions = JSON.stringify(JSON.parse(description));
  } catch (err) {
    return res.status(400).json({ Status: "error", Error: "Invalid JSON in description" });
  }

  const sql = `
    UPDATE plans SET name = ?, price = ?, user_limit = ?, permissions = ?
    WHERE id = ?
  `;

  db.query(sql, [name, price, user_limit, parsedPermissions, planId], (err, result) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ Status: "error", Error: "Database update failed" });
    }
    return res.json({ Status: "success" });
  });
});

app.get("/test", (req, res) => {
  res.json({ Status: "success", message: "Backend is working!" });
});

export default app;


// start
// // app.listen(8081, () => {
// //   console.log("✅ Server running on https://vercel-backend-woad-phi.vercel.app
// ");
// // });  