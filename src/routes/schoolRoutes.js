const { Router } = require("express");
const schoolCtrl = require("../controllers/schoolController");
const { authenticate } = require("../middleware/auth");
const { requireRole } = require("../middleware/rbac");
const { validate, createSchoolSchema } = require("../middleware/validate");

const router = Router();

router.use(authenticate);

// POST /api/schools — create school (DSA only)
router.post(
  "/",
  requireRole("super_admin"),
  validate(createSchoolSchema),
  schoolCtrl.createSchool
);

module.exports = router;
