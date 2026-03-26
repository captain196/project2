const { ValidationError } = require("../utils/errors");

function validate(schema) {
  return (req, res, next) => {
    const errors = [];
    for (const [field, validator] of Object.entries(schema)) {
      const result = validator(req.body[field], req.body);
      if (result) errors.push(`${field}: ${result}`);
    }
    if (errors.length) return next(new ValidationError(errors.join("; ")));
    next();
  };
}

// ─── Common validators ───────────────────────────────────────────────────────

const required = (label) => (v) => {
  if (v === undefined || v === null) return `${label} is required`;
  if (typeof v !== "string") return `${label} must be a string`;
  if (!v.trim()) return `${label} is required`;
  return null;
};

const requiredEmail = (v) => {
  if (!v || !v.trim()) return "Email is required";
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? null : "Invalid email format";
};

const password = (v) => {
  if (!v) return "Password is required";
  if (v.length < 8) return "Min 8 characters";
  if (!/[A-Z]/.test(v)) return "Must include uppercase letter";
  if (!/[a-z]/.test(v)) return "Must include lowercase letter";
  if (!/[0-9]/.test(v)) return "Must include a number";
  return null;
};

const role = (v) => {
  if (!v) return "Role is required";
  return ["super_admin", "school_super_admin", "admin", "teacher", "student"].includes(v) ? null : "Invalid role";
};

// ─── Pre-built schemas ───────────────────────────────────────────────────────

const loginSchema = {
  userId: required("User ID"),
  password: required("Password"),
};

const createUserSchema = {
  name: required("Name"),
  email: requiredEmail,
  password,
  role,
};

const createSchoolSchema = {
  schoolName: required("School name"),
};

const changePasswordSchema = {
  currentPassword: required("Current password"),
  newPassword: password,
};

module.exports = {
  validate,
  loginSchema,
  createUserSchema,
  createSchoolSchema,
  changePasswordSchema,
};
