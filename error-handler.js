// middleware/error-handler.js - Централизованная обработка ошибок

'use strict';

const { getLogger } = require('../lib/logger');
const DateUtils = require('../lib/date-utils');

const logger = getLogger();

// HTTP статус коды
const HTTP_STATUS = {
  OK: 200,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  BAD_REQUEST: 400,
  PAYLOAD_TOO_LARGE: 413,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503
};

// Стандартные коды ошибок и сообщения
const ERROR_CODES = {
  // Authentication & Authorization
  UNAUTHORIZED: { status: HTTP_STATUS.UNAUTHORIZED, message: 'Не авторизован' },
  FORBIDDEN: { status: HTTP_STATUS.FORBIDDEN, message: 'Доступ запрещен' },
  INVALID_TOKEN: { status: HTTP_STATUS.UNAUTHORIZED, message: 'Неверный токен' },
  TOKEN_EXPIRED: { status: HTTP_STATUS.UNAUTHORIZED, message: 'Токен истек' },

  // Validation
  VALIDATION_ERROR: { status: HTTP_STATUS.BAD_REQUEST, message: 'Ошибка валидации' },
  MISSING_REQUIRED: { status: HTTP_STATUS.BAD_REQUEST, message: 'Отсутствуют обязательные поля' },
  INVALID_FORMAT: { status: HTTP_STATUS.BAD_REQUEST, message: 'Неверный формат данных' },

  // Resources
  NOT_FOUND: { status: HTTP_STATUS.NOT_FOUND, message: 'Ресурс не найден' },
  USER_NOT_FOUND: { status: HTTP_STATUS.NOT_FOUND, message: 'Пользователь не найден' },
  TASK_NOT_FOUND: { status: HTTP_STATUS.NOT_FOUND, message: 'Задача не найдена' },

  // Business Logic
  INSUFFICIENT_BALANCE: { status: HTTP_STATUS.BAD_REQUEST, message: 'Недостаточно средств' },
  TASK_ALREADY_CLAIMED: { status: HTTP_STATUS.BAD_REQUEST, message: 'Задача уже взята' },
  TASK_NOT_AVAILABLE: { status: HTTP_STATUS.BAD_REQUEST, message: 'Задача недоступна' },

  // File Upload
  FILE_TOO_LARGE: { status: HTTP_STATUS.PAYLOAD_TOO_LARGE, message: 'Файл слишком большой' },
  INVALID_FILE_TYPE: { status: HTTP_STATUS.BAD_REQUEST, message: 'Недопустимый тип файла' },

  // Rate Limiting
  TOO_MANY_REQUESTS: { status: HTTP_STATUS.TOO_MANY_REQUESTS, message: 'Слишком много запросов' },

  // System
  DATABASE_ERROR: { status: HTTP_STATUS.INTERNAL_SERVER_ERROR, message: 'Ошибка базы данных' },
  SERVER_ERROR: { status: HTTP_STATUS.INTERNAL_SERVER_ERROR, message: 'Внутренняя ошибка сервера' },
  SERVICE_UNAVAILABLE: { status: HTTP_STATUS.SERVICE_UNAVAILABLE, message: 'Сервис недоступен' }
};

// Кастомный класс ошибки
class AppError extends Error {
  constructor(code, details = {}, originalError = null) {
    const errorInfo = ERROR_CODES[code] || ERROR_CODES.SERVER_ERROR;
    // Используем переданное сообщение или стандартное
    const message = details.message || errorInfo.message;
    super(message);

    this.name = 'AppError';
    this.code = code;
    this.status = errorInfo.status;
    this.details = details;
    this.originalError = originalError;
    this.timestamp = DateUtils.now();
  }
}

// Функция для создания стандартных ошибок
function createError(code, details, originalError) {
  return new AppError(code, details, originalError);
}

// Middleware для обработки ошибок
function errorHandler(err, req, res, _next) {
  let error = err;

  // Преобразуем обычные ошибки в AppError
  if (!(err instanceof AppError)) {
    // Validation errors от express-validator
    if (err.name === 'ValidationError' || (err.errors && Array.isArray(err.errors))) {
      error = createError('VALIDATION_ERROR', {
        errors: err.errors || err.message
      }, err);
    }
    // Multer errors
    else if (err.code === 'LIMIT_FILE_SIZE') {
      error = createError('FILE_TOO_LARGE', { limit: err.limit }, err);
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      error = createError('INVALID_FILE_TYPE', { field: err.field }, err);
    }
    // Database errors
    else if (err.code && err.code.startsWith('23')) { // PostgreSQL constraint errors
      // Не раскрываем детали БД ошибок в production
      const details = process.env.NODE_ENV === 'production' ? {} : { constraint: err.constraint };
      error = createError('DATABASE_ERROR', details, err);
    }
    // JWT errors
    else if (err.name === 'TokenExpiredError') {
      error = createError('TOKEN_EXPIRED', {}, err);
    } else if (err.name === 'JsonWebTokenError') {
      error = createError('INVALID_TOKEN', {}, err);
    }
    // Общие ошибки
    else {
      error = createError('SERVER_ERROR', { original: err.message }, err);
    }
  }

  // Логируем ошибку
  const logData = {
    error: {
      code: error.code,
      message: error.message,
      status: error.status,
      details: error.details,
      stack: error.originalError?.stack || error.stack
    },
    request: {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id
    },
    timestamp: error.timestamp
  };

  // Оптимизируем логирование для уменьшения нагрузки
  const shouldLogDetails = error.status >= 500 || process.env.NODE_ENV === 'development';
  const minimalLogData = shouldLogDetails ? logData : {
    error: { code: error.code, status: error.status },
    request: { method: req.method, url: req.url },
    timestamp: error.timestamp
  };

  if (error.status >= 500) {
    logger.error('Server Error', minimalLogData);
  } else if (error.status >= 400 && error.status !== 404) {
    // Не логируем 404 ошибки для уменьшения шума
    logger.warn('Client Error', minimalLogData);
  }

  // Формируем ответ
  const response = {
    success: false,
    error: error.message,
    code: error.code,
    timestamp: error.timestamp
  };

  // В development режиме добавляем дополнительную информацию
  if (process.env.NODE_ENV === 'development') {
    response.details = error.details;
    // Ограничиваем стек трейс только для development
    if (error.stack && error.status >= 500) {
      response.stack = error.stack.split('\n').slice(0, 10).join('\n');
    }
  }

  // Отправляем ответ
  res.status(error.status).json(response);
}

// Middleware для обработка 404 ошибок
function notFoundHandler(req, res, next) {
  const error = createError('NOT_FOUND', {
    method: req.method,
    url: req.url
  });
  next(error);
}

// Функции-помощники для быстрого создания стандартных ответов
const sendError = {
  unauthorized: (res, details) => {
    const error = createError('UNAUTHORIZED', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  },

  forbidden: (res, details) => {
    const error = createError('FORBIDDEN', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  },

  notFound: (res, details) => {
    const error = createError('NOT_FOUND', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  },

  badRequest: (res, details) => {
    const error = createError('VALIDATION_ERROR', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  },

  serverError: (res, details) => {
    const error = createError('SERVER_ERROR', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  },

  tooManyRequests: (res, details) => {
    const error = createError('TOO_MANY_REQUESTS', details);
    res.status(error.status).json({
      success: false,
      error: error.message,
      code: error.code
    });
  }
};

module.exports = {
  AppError,
  createError,
  errorHandler,
  notFoundHandler,
  sendError,
  ERROR_CODES
};