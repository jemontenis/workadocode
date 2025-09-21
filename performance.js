// middleware/performance.js

'use strict';

const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { getLogger } = require('../lib/logger');

const logger = getLogger();

module.exports = {
  // Compression middleware с оптимальными настройками
  compression: compression({
    level: 6, // Уровень сжатия (1-9, где 9 максимальный)
    threshold: 1024, // Минимальный размер для сжатия (1KB)
    filter: (req, res) => {
      // Не сжимаем уже сжатые файлы
      if (req.headers['x-no-compression']) {
        return false;
      }
      // Используем стандартный фильтр compression
      return compression.filter(req, res);
    }
  }),

  // Rate limiting для API эндпоинтов
  apiLimit: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 100, // максимум 100 запросов на IP за 15 минут
    message: {
      error: 'Слишком много запросов с этого IP, попробуйте позже.',
      retryAfter: '15 минут'
    },
    standardHeaders: true, // Возвращать rate limit заголовки
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Слишком много запросов с этого IP, попробуйте позже.',
        retryAfter: '15 минут'
      });
    }
  }),

  // Rate limiting для авторизации (более строгий)
  authLimit: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 10, // максимум 10 попыток авторизации за 15 минут
    message: {
      error: 'Слишком много попыток входа, попробуйте позже.',
      retryAfter: '15 минут'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Слишком много попыток входа, попробуйте позже.',
        retryAfter: '15 минут'
      });
    }
  }),

  // Rate limiting для загрузки файлов
  uploadLimit: rateLimit({
    windowMs: 60 * 1000, // 1 минута
    max: 5, // максимум 5 загрузок в минуту
    message: {
      error: 'Слишком много загрузок файлов, попробуйте позже.',
      retryAfter: '1 минута'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Слишком много загрузок файлов, попробуйте позже.',
        retryAfter: '1 минута'
      });
    }
  })
};