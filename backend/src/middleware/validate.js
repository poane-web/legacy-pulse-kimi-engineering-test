'use strict';

const { validationResult } = require('express-validator');
const { BadRequestError } = require('../utils/errors');

/**
 * Runs after an array of express-validator checks; collects errors into a
 * single consistent 400 response rather than each route hand-rolling this.
 */
function handleValidation(req, res, next) {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    const first = result.array()[0];
    return next(new BadRequestError(`${first.path}: ${first.msg}`, 'VALIDATION_ERROR'));
  }
  next();
}

module.exports = { handleValidation };
