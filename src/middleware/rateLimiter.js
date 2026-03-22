const store = new Map();

// Cleanup expired entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of store) {
    if (now > val.windowEnd) store.delete(key);
  }
}, 5 * 60 * 1000);

/**
 * In-memory rate limiter factory.
 *
 * @param {object} options
 * @param {number} options.windowMs  - Time window in ms
 * @param {number} options.max       - Max requests per window
 * @param {function} options.keyFn   - (req) => string (rate limit key)
 */
function createRateLimiter({ windowMs, max, keyFn }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = keyFn(req);
    const current = store.get(key);

    if (!current || now > current.windowEnd) {
      store.set(key, { count: 1, windowEnd: now + windowMs });
      return next();
    }

    if (current.count >= max) {
      const retryAfter = Math.ceil((current.windowEnd - now) / 1000);
      res.set("Retry-After", String(retryAfter));
      return res.status(429).json({
        success: false,
        message: `Too many requests. Retry after ${retryAfter}s.`,
      });
    }

    current.count++;
    next();
  };
}

function getClientIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "unknown";
}

// Pre-built limiters
const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyFn: (req) => `login:${getClientIp(req)}`,
});

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 100,
  keyFn: (req) => `api:${getClientIp(req)}`,
});

module.exports = { createRateLimiter, loginLimiter, apiLimiter, getClientIp };
