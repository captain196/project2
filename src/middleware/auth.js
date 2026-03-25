const { verifyAccessToken } = require("../utils/token");
const { AuthError } = require("../utils/errors");
const User = require("../models/User");

/**
 * JWT authentication middleware.
 * Extracts Bearer token from Authorization header, verifies it,
 * and attaches decoded payload to req.user.
 * Also updates lastActivityAt for session idle timeout tracking.
 */
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return next(new AuthError("Authorization token required"));
  }

  const token = header.slice(7);
  try {
    req.user = verifyAccessToken(token);

    // Update lastActivityAt asynchronously (non-blocking, best-effort)
    // Throttle: only update if last update was >5 minutes ago to reduce DB writes
    if (req.user && req.user.userId) {
      User.findOneAndUpdate(
        {
          userId: req.user.userId,
          $or: [
            { lastActivityAt: null },
            { lastActivityAt: { $lt: new Date(Date.now() - 5 * 60 * 1000) } },
          ],
        },
        { $set: { lastActivityAt: new Date() } }
      ).catch(() => {}); // fire-and-forget
    }

    next();
  } catch (err) {
    next(new AuthError("Invalid or expired token"));
  }
}

module.exports = { authenticate };
