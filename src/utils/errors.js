class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
  }
}

class ValidationError extends AppError {
  constructor(message) {
    super(message, 400);
  }
}

class AuthError extends AppError {
  constructor(message = "Authentication required") {
    super(message, 401);
  }
}

class ForbiddenError extends AppError {
  constructor(message = "Access denied") {
    super(message, 403);
  }
}

class NotFoundError extends AppError {
  constructor(message = "Not found") {
    super(message, 404);
  }
}

class ConflictError extends AppError {
  constructor(message = "Conflict") {
    super(message, 409);
  }
}

module.exports = {
  AppError,
  ValidationError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
};
