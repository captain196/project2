const { Router } = require("express");
const userCtrl = require("../controllers/userController");
const { authenticate } = require("../middleware/auth");
const { requireRole, requireSameSchool } = require("../middleware/rbac");
const { validate, createUserSchema } = require("../middleware/validate");

const router = Router();

// All user routes require authentication
router.use(authenticate);

// GET /api/users/me — own profile
router.get("/me", userCtrl.getProfile);

// GET /api/users/:userId — get specific user profile
router.get("/:userId", requireRole("admin"), userCtrl.getProfile);

// GET /api/users?role=super_admin or ?schoolId=SCH0001
router.get("/", requireRole("admin"), userCtrl.listUsers);

// POST /api/users — create user (permission checked in service layer via CAN_CREATE)
router.post(
  "/",
  requireRole("school_super_admin"),
  requireSameSchool,
  validate(createUserSchema),
  userCtrl.createUser
);

// PUT /api/users/:userId — update profile
router.put("/:userId", requireRole("admin"), userCtrl.updateProfile);

// DELETE /api/users/:userId — delete user
router.delete("/:userId", requireRole("super_admin"), userCtrl.deleteUser);

module.exports = router;
