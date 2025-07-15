import bcrypt from "bcrypt";

const saltRounds = 10;
const adminPassword = "admin123"; // change to whatever you want

bcrypt.hash(adminPassword, saltRounds, (err, hash) => {
  if (err) {
    console.error("❌ Error hashing password:", err);
  } else {
    console.log("✅ Hashed password:\n", hash);
  }
});
