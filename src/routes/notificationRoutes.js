const { Router } = require("express");
const { authenticate } = require("../middleware/auth");
const notifCtrl = require("../controllers/notificationController");

const router = Router();

// POST /api/notifications/homework — notify class about new homework
router.post("/homework", authenticate, notifCtrl.sendHomeworkNotification);

// POST /api/notifications/flag — notify student about a new flag
router.post("/flag", authenticate, notifCtrl.sendFlagNotification);

// POST /api/notifications/attendance — notify parent when child is absent/late
router.post("/attendance", authenticate, notifCtrl.sendAttendanceNotification);

// POST /api/notifications/results — notify class when results are published
router.post("/results", authenticate, notifCtrl.sendResultsNotification);

module.exports = router;
