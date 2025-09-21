// middleware/static-optimization.js - Оптимизация статических ресурсов

'use strict';

const compression = require('compression');
const { sendError } = require('./error-handler');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;
const { getLogger } = require('../lib/logger');

const logger = getLogger();

// Константы для кэширования
const COMPRESSION_THRESHOLD = 1024; // 1KB
const COMPRESSION_LEVEL = 6;
const ETAG_CACHE_SIZE_LIMIT = 1000;
const ETAG_CACHE_TTL = 60 * 1000; // 1 минута
const CACHE_MAX_AGE_ONE_YEAR = 31536000; // 1 год в секундах
const CACHE_MAX_AGE_ONE_MONTH = 2592000; // 30 дней в секундах
const CACHE_MAX_AGE_ONE_HOUR = 3600; // 1 час в секундах
const HTTP_STATUS_NOT_MODIFIED = 304;

// Кэш для ETag значений
const etagCache = new Map();

/**
 * Middleware для сжатия ответов
 */
function compressionMiddleware() {
  return compression({
    // Сжимаем только если размер больше 1KB
    threshold: COMPRESSION_THRESHOLD,
    // Уровень сжатия (1-9, где 9 - максимальное сжатие)
    level: COMPRESSION_LEVEL,
    // Фильтр для типов контента
    filter: (req, res) => {
      // Не сжимаем уже сжатые файлы
      if (req.headers['x-no-compression']) {
        return false;
      }

      const contentType = res.get('Content-Type');
      if (!contentType) return false;

      // Сжимаем текстовые типы контента
      return /text|javascript|json|css|xml|svg/.test(contentType);
    },
    // Минимальный размер для сжатия
    chunkSize: COMPRESSION_THRESHOLD
  });
}

/**
 * Middleware для кэширования статических файлов
 */
function staticCacheMiddleware() {
  return async (req, res, next) => {
    try {
    const ext = path.extname(req.url).toLowerCase();

    // Настройки кэширования для разных типов файлов
    const cacheSettings = {
      // Долгосрочное кэширование для неизменяемых ресурсов
      '.js': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год
      '.css': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год
      '.woff': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год
      '.woff2': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год
      '.ttf': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год
      '.otf': { maxAge: CACHE_MAX_AGE_ONE_YEAR, immutable: true }, // 1 год

      // Среднесрочное кэширование для изображений
      '.jpg': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.jpeg': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.png': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.gif': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.svg': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.ico': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней
      '.webp': { maxAge: CACHE_MAX_AGE_ONE_MONTH }, // 30 дней

      // Краткосрочное кэширование для HTML
      '.html': { maxAge: CACHE_MAX_AGE_ONE_HOUR }, // 1 час
      '.htm': { maxAge: CACHE_MAX_AGE_ONE_HOUR } // 1 час
    };

    const settings = cacheSettings[ext];

    if (settings) {
      // Устанавливаем заголовки кэширования
      res.set({
        'Cache-Control': `public, max-age=${settings.maxAge}${settings.immutable ? ', immutable' : ''}`,
        'Expires': new Date(Date.now() + settings.maxAge * 1000).toUTCString()
      });

      // Добавляем ETag для валидации кэша (асинхронно)
      const etag = await generateETag(req.url);
      res.set('ETag', etag);

      // Проверяем If-None-Match header
      const clientETag = req.get('If-None-Match');
      if (clientETag === etag) {
        return res.status(HTTP_STATUS_NOT_MODIFIED).end();
      }
    }

    next();
    } catch (error) {
      logger.error('Static cache middleware error', {
        error: error.message,
        url: req.url
      });
      // Продолжаем выполнение даже в случае ошибки кэширования
      next();
    }
  };
}

/**
 * Генерация ETag для файла (с кэшированием)
 */
async function generateETag(filepath) {
  // Проверяем кэш
  const cacheKey = filepath;
  const cached = etagCache.get(cacheKey);

  if (cached && cached.expires > Date.now()) {
    return cached.etag;
  }

  try {
    // Используем асинхронную проверку файла
    const fullPath = filepath.startsWith('/') ? filepath : `./public${filepath}`;
    const stats = await fs.stat(fullPath);

    // Генерируем ETag на основе пути, размера и времени модификации
    const etag = `"${crypto.createHash('md5')
      .update(`${filepath}-${stats.size}-${stats.mtime.getTime()}`)
      .digest('hex')
      .substring(0, 16)}"`;

    // Сохраняем в кэш
    etagCache.set(cacheKey, {
      etag,
      expires: Date.now() + ETAG_CACHE_TTL
    });

    // Очищаем старые записи из кэша
    if (etagCache.size > ETAG_CACHE_SIZE_LIMIT) {
      const now = Date.now();
      for (const [key, value] of etagCache) {
        if (value.expires < now) {
          etagCache.delete(key);
        }
      }
    }

    return etag;
  } catch (err) {
    // Fallback: используем простой хеш пути
    return `"${crypto.createHash('md5')
      .update(filepath)
      .digest('hex')
      .substring(0, 16)}"`;
  }
}

/**
 * Middleware для обработки favicon запросов
 */
function faviconMiddleware() {
  return (req, res, next) => {
    if (req.url === '/favicon.ico') {
      res.set({
        'Cache-Control': `public, max-age=${CACHE_MAX_AGE_ONE_MONTH}`, // 30 дней
        'Content-Type': 'image/x-icon'
      });
    }
    next();
  };
}

/**
 * Middleware для безопасности статических файлов
 */
function staticSecurityMiddleware() {
  return (req, res, next) => {
    // Блокируем доступ к системным файлам и конфиденциальным данным
    const blockedPatterns = [
      // Конфигурационные файлы
      /\.env/i,
      /\.git/,
      /node_modules/,
      /package\.json/,
      /package-lock\.json/,
      /yarn\.lock/,
      /composer\.json/,
      /composer\.lock/,

      // Системные и временные файлы
      /\.(md|txt|log|bak|tmp|temp)$/i,
      /\.(conf|ini|cfg|config)$/i,
      /\.(key|pem|p12|pfx|crt|cer)$/i,
      /\.(sql|dump|backup)$/i,

      // Директории и файлы разработки
      /\/(\.|__)/, // Скрытые файлы и системные папки
      /\/(src|lib|test|tests|spec|docs)\//,
      /\/(scripts|build|dist)\//,

      // Попытки Directory Traversal
      /\.\./,
      /~/, // Домашние директории
      /proc\//,
      /etc\//,
      /var\//,
      /tmp\//,
      /dev\//,

      // Исполняемые файлы и скрипты
      /\.(sh|bat|cmd|exe|php|py|rb|pl|jsp|asp|aspx)$/i,

      // Небезопасные расширения
      /\.(htaccess|htpasswd|web\.config)$/i
    ];

    if (blockedPatterns.some(pattern => pattern.test(req.url))) {
      return sendError.forbidden(res, { message: 'Доступ запрещен' });
    }

    // Устанавливаем заголовки безопасности для статических файлов
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });

    next();
  };
}

/**
 * Middleware для предварительной загрузки ресурсов
 */
function preloadMiddleware() {
  return (req, res, next) => {
    // Пока отключаем preload до создания соответствующих файлов
    // TODO: включить когда будут созданы CSS/JS файлы
    next();
  };
}

/**
 * Middleware для установки Content-Type на основе расширения
 */
function contentTypeMiddleware() {
  return (req, res, next) => {
    const ext = path.extname(req.url).toLowerCase();

    const contentTypes = {
      '.js': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.html': 'text/html; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.xml': 'application/xml; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.woff': 'font/woff',
      '.woff2': 'font/woff2',
      '.ttf': 'font/ttf',
      '.otf': 'font/otf'
    };

    const contentType = contentTypes[ext];
    if (contentType) {
      res.set('Content-Type', contentType);
    }

    next();
  };
}

/**
 * Создание полного набора middleware для оптимизации статических ресурсов
 */
function createStaticOptimization() {
  return [
    staticSecurityMiddleware(),
    staticCacheMiddleware(),
    contentTypeMiddleware(),
    faviconMiddleware(),
    preloadMiddleware(),
    compressionMiddleware()
  ];
}

/**
 * Статистика по статическим файлам
 */
class StaticStats {
  constructor() {
    this.requests = new Map();
    this.totalRequests = 0;
    this.cacheHits = 0;
  }

  recordRequest(url, cached = false) {
    this.totalRequests++;

    if (cached) {
      this.cacheHits++;
    }

    const count = this.requests.get(url) || 0;
    this.requests.set(url, count + 1);
  }

  getStats() {
    const popularFiles = Array.from(this.requests.entries())
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([url, count]) => ({ url, count }));

    return {
      totalRequests: this.totalRequests,
      cacheHitRate: this.totalRequests > 0 ?
        ((this.cacheHits / this.totalRequests) * 100).toFixed(2) + '%' : '0%',
      popularFiles
    };
  }
}

const staticStats = new StaticStats();

module.exports = {
  compressionMiddleware,
  staticCacheMiddleware,
  staticSecurityMiddleware,
  faviconMiddleware,
  preloadMiddleware,
  contentTypeMiddleware,
  createStaticOptimization,
  staticStats
};