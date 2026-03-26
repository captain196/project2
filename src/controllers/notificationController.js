const { admin } = require("../config/firebase");
const User = require("../models/User");
const { ValidationError, ForbiddenError } = require("../utils/errors");

/**
 * Collect all active FCM tokens for students in a given class/section at a school.
 */
async function getStudentFcmTokens(schoolId, className, section) {
  const students = await User.find(
    {
      schoolId,
      role: "student",
      className,
      section,
      status: "Active",
      "devices.fcmToken": { $ne: null },
    },
    { devices: 1 }
  ).lean();

  const tokens = [];
  for (const student of students) {
    for (const device of student.devices || []) {
      if (device.fcmToken && device.status === "active") {
        tokens.push(device.fcmToken);
      }
    }
  }
  return tokens;
}

/**
 * Collect FCM tokens for a specific student (by userId) at a school.
 */
async function getStudentTokensById(schoolId, studentId) {
  const student = await User.findOne(
    {
      schoolId,
      userId: studentId,
      role: "student",
      status: "Active",
    },
    { devices: 1 }
  ).lean();

  if (!student) return [];

  const tokens = [];
  for (const device of student.devices || []) {
    if (device.fcmToken && device.status === "active") {
      tokens.push(device.fcmToken);
    }
  }
  return tokens;
}

/**
 * Send FCM multicast to a list of tokens.
 * Silently removes invalid tokens from the database if the send reports them.
 */
async function sendToTokens(tokens, title, body, data) {
  const validTokens = tokens.filter(Boolean);
  if (!validTokens.length) return { successCount: 0, failureCount: 0 };

  const message = {
    notification: { title, body },
    data: data || {},
    tokens: validTokens,
  };

  try {
    const response = await admin.messaging().sendEachForMulticast(message);
    return {
      successCount: response.successCount,
      failureCount: response.failureCount,
    };
  } catch (e) {
    console.error("FCM send error:", e.message);
    return { successCount: 0, failureCount: validTokens.length, error: e.message };
  }
}

/**
 * POST /api/notifications/homework
 *
 * Body: { className, section, title, description, dueDate }
 * Sends FCM to all students in that class/section.
 * Requires: authenticated teacher (or admin).
 */
async function sendHomeworkNotification(req, res, next) {
  try {
    const { role, schoolId, userId, name } = req.user;

    if (!["teacher", "admin", "school_super_admin", "super_admin"].includes(role)) {
      throw new ForbiddenError("Only teachers and admins can send homework notifications");
    }

    const { className, section, title, description, dueDate } = req.body;
    if (!className || !section || !title) {
      throw new ValidationError("className, section, and title are required");
    }

    const tokens = await getStudentFcmTokens(schoolId, className, section);

    const notifTitle = "New Homework";
    const notifBody = `${title}${dueDate ? " - Due: " + dueDate : ""}`;
    const data = {
      type: "homework",
      className: String(className),
      section: String(section),
      title: String(title),
      description: String(description || ""),
      dueDate: String(dueDate || ""),
      teacherName: String(name || ""),
      teacherId: String(userId || ""),
    };

    const result = await sendToTokens(tokens, notifTitle, notifBody, data);

    res.json({
      success: true,
      message: `Notification sent to ${result.successCount} device(s)`,
      tokensTargeted: tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/notifications/flag
 *
 * Body: { studentId, flagType, flagTitle, flagMessage }
 * Sends FCM to the specific student's devices when a flag is created.
 * Requires: authenticated teacher (or admin).
 */
async function sendFlagNotification(req, res, next) {
  try {
    const { role, schoolId, userId, name } = req.user;

    if (!["teacher", "admin", "school_super_admin", "super_admin"].includes(role)) {
      throw new ForbiddenError("Only teachers and admins can send flag notifications");
    }

    const { studentId, flagType, flagTitle, flagMessage } = req.body;
    if (!studentId || !flagType) {
      throw new ValidationError("studentId and flagType are required");
    }

    const tokens = await getStudentTokensById(schoolId, studentId);

    const notifTitle = flagTitle || `New ${flagType} Flag`;
    const notifBody = flagMessage || `A ${flagType} flag has been added to your profile.`;
    const data = {
      type: "flag",
      flagType: String(flagType),
      studentId: String(studentId),
      flagTitle: String(flagTitle || ""),
      flagMessage: String(flagMessage || ""),
      teacherName: String(name || ""),
      teacherId: String(userId || ""),
    };

    const result = await sendToTokens(tokens, notifTitle, notifBody, data);

    res.json({
      success: true,
      message: `Notification sent to ${result.successCount} device(s)`,
      tokensTargeted: tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/notifications/attendance
 *
 * Body: { studentId, studentName, className, section, date, status }
 * Sends FCM to the specific student's parent devices when marked absent/late.
 * Requires: authenticated teacher (or admin).
 */
async function sendAttendanceNotification(req, res, next) {
  try {
    const { role, schoolId } = req.user;

    if (!["teacher", "admin", "school_super_admin", "super_admin"].includes(role)) {
      throw new ForbiddenError("Only teachers and admins can send attendance notifications");
    }

    const { studentId, studentName, className, section, date, status } = req.body;
    if (!studentId || !status) {
      throw new ValidationError("studentId and status are required");
    }

    // Only notify for absent or late
    if (!["A", "L"].includes(status)) {
      return res.json({ success: true, message: "No notification needed for this status", sent: false });
    }

    const tokens = await getStudentTokensById(schoolId, studentId);

    const statusLabel = status === "A" ? "absent" : "late";
    const notifTitle = "Attendance Alert";
    const notifBody = `${studentName || "Your child"} was marked ${statusLabel} on ${date || "today"}`;
    const data = {
      type: "attendance",
      studentId: String(studentId),
      studentName: String(studentName || ""),
      className: String(className || ""),
      section: String(section || ""),
      date: String(date || ""),
      status: String(status),
    };

    const result = await sendToTokens(tokens, notifTitle, notifBody, data);

    res.json({
      success: true,
      message: `Notification sent to ${result.successCount} device(s)`,
      tokensTargeted: tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/notifications/results
 *
 * Body: { className, section, examName }
 * Sends FCM to all students in a class when results are published.
 * Requires: authenticated admin.
 */
async function sendResultsNotification(req, res, next) {
  try {
    const { role, schoolId } = req.user;

    if (!["admin", "school_super_admin", "super_admin"].includes(role)) {
      throw new ForbiddenError("Only admins can send results notifications");
    }

    const { className, section, examName } = req.body;
    if (!className || !section) {
      throw new ValidationError("className and section are required");
    }

    const tokens = await getStudentFcmTokens(schoolId, className, section);

    const notifTitle = "Results Published";
    const notifBody = `${examName || "Exam"} results are now available. Check your report card.`;
    const data = {
      type: "results",
      className: String(className),
      section: String(section),
      examName: String(examName || ""),
    };

    const result = await sendToTokens(tokens, notifTitle, notifBody, data);

    res.json({
      success: true,
      message: `Notification sent to ${result.successCount} device(s)`,
      tokensTargeted: tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount,
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  sendHomeworkNotification,
  sendFlagNotification,
  sendAttendanceNotification,
  sendResultsNotification,
  // Shared helpers — used by internalRoutes for server-to-server notification calls
  getStudentTokensById,
  sendToTokens,
};
