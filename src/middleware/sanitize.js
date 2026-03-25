/**
 * Middleware to prevent NoSQL injection by stripping MongoDB operators
 * from request body, query, and params.
 *
 * MongoDB operators start with $ (e.g., $gt, $ne, $regex).
 * This middleware recursively removes any keys starting with $ from objects.
 */

function stripOperators(obj) {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(stripOperators);

  const clean = {};
  for (const [key, value] of Object.entries(obj)) {
    if (key.startsWith("$")) continue; // strip MongoDB operator keys
    clean[key] = typeof value === "object" ? stripOperators(value) : value;
  }
  return clean;
}

function sanitize(req, res, next) {
  if (req.body && typeof req.body === "object") {
    req.body = stripOperators(req.body);
  }
  if (req.query && typeof req.query === "object") {
    req.query = stripOperators(req.query);
  }
  if (req.params && typeof req.params === "object") {
    req.params = stripOperators(req.params);
  }
  next();
}

module.exports = { sanitize };
