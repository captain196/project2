const userService = require("../services/userService");

async function createUser(req, res, next) {
  try {
    const { name, email, phone, password, role, schoolId } = req.body;

    const result = await userService.createUser({
      name,
      email,
      phone,
      password,
      role,
      schoolId,
      createdBy: req.user.userId,
    });

    res.status(201).json({ success: true, user: result });
  } catch (err) {
    next(err);
  }
}

async function updateProfile(req, res, next) {
  try {
    const userId = req.params.userId || req.user.userId;
    const { name, email, phone } = req.body;

    const result = await userService.updateUserProfile(
      userId,
      { name, email, phone },
      req.user.userId
    );

    res.json({ success: true, user: result });
  } catch (err) {
    next(err);
  }
}

async function deleteUser(req, res, next) {
  try {
    const { userId } = req.params;
    const result = await userService.deleteUser(userId, req.user.userId);

    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
}

async function listUsers(req, res, next) {
  try {
    const { role, schoolId } = req.query;
    const users = await userService.listUsers({ role, schoolId });

    res.json({ success: true, users });
  } catch (err) {
    next(err);
  }
}

async function getProfile(req, res, next) {
  try {
    const mongoUserRepo = require("../repositories/mongoUserRepo");
    const userId = req.params.userId || req.user.userId;
    const user = await mongoUserRepo.findByUserId(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        schoolId: user.schoolId,
        status: user.status,
        createdAt: user.createdAt,
        createdBy: user.createdBy,
      },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = { createUser, updateProfile, deleteUser, listUsers, getProfile };
