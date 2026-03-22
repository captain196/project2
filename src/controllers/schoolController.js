const schoolService = require("../services/schoolService");

async function createSchool(req, res, next) {
  try {
    const { schoolName, city, email, phone } = req.body;
    const school = await schoolService.createSchool({
      schoolName,
      city,
      email,
      phone,
      createdBy: req.user.userId,
    });

    res.status(201).json({ success: true, school });
  } catch (err) {
    next(err);
  }
}

module.exports = { createSchool };
