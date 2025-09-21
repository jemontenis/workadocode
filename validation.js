// middleware/validation.js - Валидационные middleware

'use strict';

const SecurityValidator = require('../lib/security-validator');
const { sendError } = require('./error-handler');

const { getLogger } = require('../lib/logger');

const logger = getLogger();

/**
 * Middleware для валидации параметров запроса
 */
function validateRequestParams(paramValidators) {
  return (req, res, next) => {
    try {
      for (const [paramName, validator] of Object.entries(paramValidators)) {
        if (req.params[paramName]) {
          req.params[paramName] = validator(req.params[paramName]);
        }
      }
      next();
    } catch (error) {
      sendError.badRequest(res, { message: error.message });
    }
  };
}

/**
 * Middleware для валидации query параметров
 */
function validateQueryParams(queryValidators) {
  return (req, res, next) => {
    try {
      for (const [paramName, validator] of Object.entries(queryValidators)) {
        if (req.query[paramName]) {
          req.query[paramName] = validator(req.query[paramName]);
        }
      }
      next();
    } catch (error) {
      sendError.badRequest(res, { message: error.message });
    }
  };
}

/**
 * Middleware для валидации тела запроса по JSON схеме
 */
function validateJsonBody(schema) {
  return (req, res, next) => {
    try {
      req.body = SecurityValidator.validateJsonStructure(req.body, schema);
      next();
    } catch (error) {
      sendError.badRequest(res, { message: error.message });
    }
  };
}

/**
 * Middleware для валидации ID параметров
 */
function validateIds(paramNames) {
  const validators = {};
  paramNames.forEach(name => {
    validators[name] = SecurityValidator.validateId;
  });
  return validateRequestParams(validators);
}

/**
 * Middleware для валидации пагинации
 */
function validatePagination() {
  return (req, res, next) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;

      const validated = SecurityValidator.validatePagination(page, limit);
      req.pagination = validated;

      next();
    } catch (error) {
      sendError.badRequest(res, { message: error.message });
    }
  };
}

/**
 * Middleware для валидации IP адресов в заголовках
 */
function validateClientIP() {
  return (req, res, next) => {
    try {
      const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
      if (ip) {
        // Очищаем IP от префиксов IPv6
        const cleanIP = ip.replace('::ffff:', '');
        SecurityValidator.validateIPAddress(cleanIP);
        req.validatedIP = cleanIP;
      }
      next();
    } catch (error) {
      logger.warn('Invalid client IP detected', { ip: req.ip || req.connection?.remoteAddress, error: error.message });
      // Не блокируем запрос, просто логируем
      next();
    }
  };
}

/**
 * Middleware для валидации размера тела запроса
 */
function validateBodySize(maxSize = 1024 * 1024) { // 1MB по умолчанию
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length']);

    if (contentLength && contentLength > maxSize) {
      return sendError.badRequest(res, { message: `Размер запроса превышает ${Math.round(maxSize / 1024 / 1024)}MB` });
    }

    next();
  };
}

/**
 * Middleware для валидации User-Agent
 */
function validateUserAgent() {
  return (req, res, next) => {
    const userAgent = req.headers['user-agent'];

    if (!userAgent || userAgent.length > 1000) {
      return sendError.badRequest(res, { message: 'Некорректный User-Agent' });
    }

    // Блокировка подозрительных User-Agent
    const blockedPatterns = [
      /curl/i,
      /wget/i,
      /python/i,
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i
    ];

    // В production включаем блокировку ботов по умолчанию
    const blockBots = process.env.BLOCK_BOTS !== 'false' && process.env.NODE_ENV === 'production';

    if (blockBots) {
      for (const pattern of blockedPatterns) {
        if (pattern.test(userAgent)) {
          return sendError.forbidden(res, { message: 'Доступ запрещен' });
        }
      }
    }

    next();
  };
}

/**
 * Middleware для валидации заголовков безопасности
 */
function validateSecurityHeaders() {
  return (req, res, next) => {
    // Проверяем на отсутствие опасных заголовков
    const dangerousHeaders = [
      'x-forwarded-host',
      'x-real-ip',
      'x-cluster-client-ip'
    ];

    for (const header of dangerousHeaders) {
      if (req.headers[header]) {
        logger.logSecurity('dangerous_header_detected', { header, value: req.headers[header], ip: req.ip });
      }
    }

    // Проверяем Content-Type для POST/PUT запросов с телом
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.headers['content-type'];
      const contentLength = parseInt(req.headers['content-length']) || 0;

      // Требуем Content-Type только если есть тело запроса
      if (contentLength > 0 && !contentType) {
        return sendError.badRequest(res, { message: 'Content-Type header обязателен для запросов с телом' });
      }

      // Проверяем тип контента только если он указан
      if (contentType) {
        // Разрешенные типы контента
        const allowedTypes = [
          'application/json',
          'application/x-www-form-urlencoded',
          'multipart/form-data'
        ];

        const isAllowed = allowedTypes.some(type => contentType.includes(type));

        if (!isAllowed) {
          return sendError.badRequest(res, { message: 'Неподдерживаемый тип контента' });
        }
      }
    }

    next();
  };
}

/**
 * Комбинированный middleware для общих проверок безопасности
 */
function securityValidation() {
  return [
    validateClientIP(),
    validateUserAgent(),
    validateSecurityHeaders(),
    validateBodySize()
  ];
}

module.exports = {
  validateRequestParams,
  validateQueryParams,
  validateJsonBody,
  validateIds,
  validatePagination,
  validateClientIP,
  validateBodySize,
  validateUserAgent,
  validateSecurityHeaders,
  securityValidation
};