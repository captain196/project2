const { Router } = require("express");
const { authenticate } = require("../middleware/auth");
const notifCtrl = require("../controllers/notificationController");

const router = Router();

// POST /api/notifications/homework — notify class about new homework
router.post("/homework", authenticate, notifCtrl.sendHomeworkNotification);

// POST /api/notifications/flag — notify student about a new flag
router.post("/flag", authenticate, notifCtrl.sendFlagNotification);

module.exports = router;
