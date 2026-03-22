const { ForbiddenError } = require("../utils/errors");

/**
 * Role hierarchy: super_admin > school_super_admin > admin
 */
const ROLE_LEVEL = { super_admin: 5, school_super_admin: 4, admin: 3, teacher: 2, student: 1 };

/**
 * Require minimum role level.
 * super_admin always passes.
 *
 * Usage: requireRole("school_super_admin") — allows school_super_admin and super_admin
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) return next(new ForbiddenError("No role in token"));

    const userLevel = ROLE_LEVEL[req.user.role] || 0;

    // super_admin passes everything
    if (userLevel >= 5) return next();

    if (allowedRoles.includes(req.user.role)) return next();

    const minLevel = Math.min(...allowedRoles.map((r) => ROLE_LEVEL[r] || 99));
    if (userLevel >= minLevel) return next();

    next(new ForbiddenError(`Requires role: ${allowedRoles.join(" or ")}`));
  };
}

/**
 * Require same school for school-scoped operations.
 * super_admin bypasses.
 */
function requireSameSchool(req, res, next) {
  if (!req.user) return next(new ForbiddenError());
  if (req.user.role === "super_admin") return next();

  const targetSchoolId = req.body.schoolId || req.params.schoolId || req.query.schoolId;
  if (targetSchoolId && req.user.schoolId !== targetSchoolId) {
    return next(new ForbiddenError("Access denied: wrong school"));
  }

  next();
}

module.exports = { requireRole, requireSameSchool, ROLE_LEVEL };
