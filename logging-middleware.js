// middleware/logging-middleware.js - Middleware для интеграции улучшенного логирования

'use strict';

const { getLogger } = require('../lib/logger');

// Константы для HTTP статусов
const HTTP_STATUS_OK = 200;
const HTTP_STATUS_MULTIPLE_CHOICES = 300;
const HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
const SYSTEM_METRICS_DEFAULT_INTERVAL = 5 * 60 * 1000; // 5 минут по умолчанию

/**
 * Middleware для логирования всех HTTP запросов
 */
function requestLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    const startTime = Date.now();

    // Сохраняем оригинальные методы
    const originalJson = res.json;
    const originalSend = res.send;

    // Логируем начало запроса
    logger.debug('Request started', {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id
    });

    // Перехватываем ответы
    res.json = function(data) {
      const duration = Date.now() - startTime;
      // Оптимизация: вычисляем размер только для debug режима
      const responseSize = process.env.NODE_ENV === 'development'
        ? JSON.stringify(data).length
        : undefined;

      logger.logPerformance(`${req.method} ${req.originalUrl}`, duration, {
        statusCode: res.statusCode,
        responseSize,
        userId: req.user?.id
      });

      return originalJson.call(this, data);
    };

    res.send = function(data) {
      const duration = Date.now() - startTime;
      // Оптимизация: вычисляем размер только для debug режима
      const responseSize = process.env.NODE_ENV === 'development' && data
        ? data.toString().length
        : undefined;

      logger.logPerformance(`${req.method} ${req.originalUrl}`, duration, {
        statusCode: res.statusCode,
        responseSize,
        userId: req.user?.id
      });

      return originalSend.call(this, data);
    };

    // Обработка ошибок
    res.on('error', (error) => {
      logger.error('Response error', {
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.originalUrl,
        userId: req.user?.id
      });
    });

    next();
  };
}

/**
 * Middleware для логирования ошибок
 */
function errorLoggingMiddleware() {
  const logger = getLogger();

  return (error, req, res, next) => {
    // Классифицируем ошибку
    const errorLevel = error.status >= HTTP_STATUS_INTERNAL_SERVER_ERROR ? 'error' : 'warn';

    logger.logger[errorLevel]('Application Error', {
      message: error.message,
      stack: error.stack,
      status: error.status || HTTP_STATUS_INTERNAL_SERVER_ERROR,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      body: req.body,
      query: req.query,
      params: req.params
    });

    // Если это security-related ошибка
    if (error.type === 'security') {
      logger.logSecurity(error.action || 'unknown', {
        severity: 'high',
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id,
        details: error.details
      });
    }

    next(error);
  };
}

/**
 * Middleware для логирования операций с базой данных
 */
function databaseLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Добавляем функцию логирования к объекту запроса
    req.logDatabase = (operation, query, params = [], duration = null, error = null) => {
      logger.logDatabase(operation, query, params, duration, error);
    };

    next();
  };
}

/**
 * Middleware для логирования операций с кэшем
 */
function cacheLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Добавляем функцию логирования к объекту запроса
    req.logCache = (operation, key, hit = null, ttl = null) => {
      logger.logCache(operation, key, hit, ttl);
    };

    next();
  };
}

/**
 * Middleware для логирования бизнес-событий
 */
function businessEventLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Добавляем функцию логирования к объекту запроса
    req.logBusinessEvent = (event, details = {}) => {
      logger.logBusinessEvent(event, req.user?.id, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        ...details
      });
    };

    next();
  };
}

/**
 * Middleware для логирования аутентификации
 */
function authLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Сохраняем оригинальный json метод
    const originalJson = res.json;

    res.json = function(data) {
      // Логируем попытки аутентификации
      if (req.originalUrl.includes('/auth/') || req.originalUrl.includes('/login') || req.originalUrl.includes('/register')) {
        const success = res.statusCode >= HTTP_STATUS_OK && res.statusCode < HTTP_STATUS_MULTIPLE_CHOICES;

        logger.logAuth(req.originalUrl.split('/').pop(), req.body?.email || req.body?.username, success, {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          statusCode: res.statusCode,
          method: req.method
        });
      }

      return originalJson.call(this, data);
    };

    next();
  };
}

/**
 * Middleware для логирования платежей
 */
function paymentLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Добавляем функцию логирования к объекту запроса
    req.logPayment = (action, amount, paymentId, details = {}) => {
      logger.logPayment(action, req.user?.id, amount, paymentId, {
        ip: req.ip,
        method: req.method,
        url: req.originalUrl,
        ...details
      });
    };

    next();
  };
}

/**
 * Middleware для логирования операций с задачами
 */
function taskLoggingMiddleware() {
  const logger = getLogger();

  return (req, res, next) => {
    // Добавляем функцию логирования к объекту запроса
    req.logTask = (action, taskId, details = {}) => {
      logger.logTask(action, taskId, req.user?.id, {
        ip: req.ip,
        method: req.method,
        url: req.originalUrl,
        ...details
      });
    };

    next();
  };
}

/**
 * Комплексное middleware для всех типов логирования
 */
function comprehensiveLoggingMiddleware() {
  return [
    requestLoggingMiddleware(),
    databaseLoggingMiddleware(),
    cacheLoggingMiddleware(),
    businessEventLoggingMiddleware(),
    authLoggingMiddleware(),
    paymentLoggingMiddleware(),
    taskLoggingMiddleware()
  ];
}

/**
 * Middleware для логирования системных событий при запуске
 */
function systemStartupLogging() {
  const logger = getLogger();

  logger.logSystem('Application startup', {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    env: process.env.NODE_ENV,
    memory: process.memoryUsage(),
    cwd: process.cwd()
  });
}

/**
 * Middleware для периодического логирования системных метрик
 */
function systemMetricsLogging(intervalMs = SYSTEM_METRICS_DEFAULT_INTERVAL) { // 5 минут по умолчанию
  const logger = getLogger();

  const interval = setInterval(() => {
    logger.logSystem('System metrics', {
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      cpuUsage: process.cpuUsage()
    });
  }, intervalMs);

  // Очистка при завершении процесса
  process.on('SIGINT', () => clearInterval(interval));
  process.on('SIGTERM', () => clearInterval(interval));

  return interval;
}

/**
 * Функция для получения статистики логирования
 */
function getLoggingStats() {
  const logger = getLogger();
  return logger.getStats();
}

module.exports = {
  requestLoggingMiddleware,
  errorLoggingMiddleware,
  databaseLoggingMiddleware,
  cacheLoggingMiddleware,
  businessEventLoggingMiddleware,
  authLoggingMiddleware,
  paymentLoggingMiddleware,
  taskLoggingMiddleware,
  comprehensiveLoggingMiddleware,
  systemStartupLogging,
  systemMetricsLogging,
  getLoggingStats
};