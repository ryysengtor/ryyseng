'use strict';

const validate = {
  notEmpty(str) {
    return typeof str === 'string' && str.trim().length > 0;
  },

  url(url, domain = null) {
    if (!this.notEmpty(url)) return false;
    try {
      const parsed = new URL(url);
      if (domain) return parsed.hostname.includes(domain);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  },

  email(email) {
    if (!this.notEmpty(email)) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  },

  number(num, min = null, max = null) {
    const parsed = Number(num);
    if (isNaN(parsed)) return false;
    if (min !== null && parsed < min) return false;
    if (max !== null && parsed > max) return false;
    return true;
  },

  array(arr, minLength = 1) {
    return Array.isArray(arr) && arr.length >= minLength;
  },

  object(obj) {
    return typeof obj === 'object' && obj !== null && !Array.isArray(obj) && Object.keys(obj).length > 0;
  },

  inArray(value, allowed) {
    return allowed.includes(value);
  },

  fields(data, rules) {
    const errors = [];

    for (const [field, rule] of Object.entries(rules)) {
      const value = data[field];

      if (rule.required && !this.notEmpty(value)) {
        errors.push(`${field} is required`);
        continue;
      }

      if (!rule.required && !this.notEmpty(value)) continue;

      switch (rule.type) {
        case 'url':
          if (!this.url(value, rule.domain))
            errors.push(`${field} must be a valid URL${rule.domain ? ` from ${rule.domain}` : ''}`);
          break;
        case 'email':
          if (!this.email(value))
            errors.push(`${field} must be a valid email`);
          break;
        case 'number':
          if (!this.number(value, rule.min, rule.max)) {
            let msg = `${field} must be a valid number`;
            if (rule.min !== undefined && rule.max !== undefined) msg += ` between ${rule.min} and ${rule.max}`;
            else if (rule.min !== undefined) msg += ` >= ${rule.min}`;
            else if (rule.max !== undefined) msg += ` <= ${rule.max}`;
            errors.push(msg);
          }
          break;
        case 'array':
          if (!this.array(value, rule.minLength))
            errors.push(`${field} must be an array with at least ${rule.minLength || 1} items`);
          break;
        case 'enum':
          if (!this.inArray(value, rule.values))
            errors.push(`${field} must be one of: ${rule.values.join(', ')}`);
          break;
      }

      if (rule.custom && typeof rule.custom === 'function') {
        const customError = rule.custom(value);
        if (customError) errors.push(customError);
      }
    }

    return { valid: errors.length === 0, errors };
  },
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch((error) => {
    console.error('[asyncHandler]', error.message);
    const { sendErrorResponse } = require('../config/apikeyConfig');
    sendErrorResponse(res, error.message || 'Internal server error', error.status || 500);
  });
};

class ValidationError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name   = 'ValidationError';
    this.status = status;
  }
}

const validateRequest = (rules, source = 'query') => (req, res, next) => {
  const result = validate.fields(req[source], rules);
  if (!result.valid) {
    const { sendErrorResponse } = require('../config/apikeyConfig');
    return sendErrorResponse(res, result.errors.join(', '), 400);
  }
  next();
};

module.exports = { validate, asyncHandler, ValidationError, validateRequest };
