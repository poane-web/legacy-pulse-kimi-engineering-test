'use strict';

class AppError extends Error {
  constructor(message, statusCode = 500, code = undefined) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

class BadRequestError extends AppError {
  constructor(message = 'Bad request', code) { super(message, 400, code); }
}
class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized', code) { super(message, 401, code); }
}
class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', code) { super(message, 403, code); }
}
class NotFoundError extends AppError {
  constructor(message = 'Not found', code) { super(message, 404, code); }
}
class ConflictError extends AppError {
  constructor(message = 'Conflict', code) { super(message, 409, code); }
}

module.exports = { AppError, BadRequestError, UnauthorizedError, ForbiddenError, NotFoundError, ConflictError };
