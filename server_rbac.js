
// ==========================================================
// ROLE-BASED ACCESS CONTROL (RBAC) WITH JWT - Node + Express
// ==========================================================

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// Secret key for JWT signing
const SECRET_KEY = "mysecretkey";

// Sample users with roles
const users = [
  { id: 1, username: "adminUser", password: "admin123", role: "Admin" },
  { id: 2, username: "moderatorUser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normalUser", password: "user123", role: "User" }
];

// ---------------------------
// LOGIN ROUTE (Generate JWT)
// ---------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (user) {
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

// ---------------------------------
// Middleware: Verify JWT Token
// ---------------------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(403).json({ message: "Token missing" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// ---------------------------------
// Middleware: Role Authorization
// ---------------------------------
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }
    next();
  };
}

// ---------------------------------
// PROTECTED ROUTES BY ROLE
// ---------------------------------
app.get("/admin", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({ message: "Welcome Admin! You have full access.", user: req.user });
});

app.get("/moderator", verifyToken, authorizeRoles("Admin", "Moderator"), (req, res) => {
  res.json({ message: "Welcome Moderator! You can manage user content.", user: req.user });
});

app.get("/user", verifyToken, authorizeRoles("Admin", "Moderator", "User"), (req, res) => {
  res.json({ message: "Welcome User! You can view your profile.", user: req.user });
});

// ---------------------------
// START SERVER
// ---------------------------
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
