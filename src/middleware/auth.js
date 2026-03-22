const { verifyAccessToken } = require("../utils/token");
const { AuthError } = require("../utils/errors");

/**
 * JWT authentication middleware.
 * Extracts Bearer token from Authorization header, verifies it,
 * and attaches decoded payload to req.user.
 */
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return next(new AuthError("Authorization token required"));
  }

  const token = header.slice(7);
  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    next(new AuthError("Invalid or expired token"));
  }
}

module.exports = { authenticate };
