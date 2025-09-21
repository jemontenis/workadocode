// middleware/cache.js - Middleware для кэширования ответов

'use strict';

const { globalCache } = require('../lib/cache-manager');
const { sendError } = require('./error-handler');

const { getLogger } = require('../lib/logger');

const logger = getLogger();

/**
 * Middleware для кэширования GET запросов
 */
function cacheMiddleware(options = {}) {
  const {
    ttl = 300000, // 5 минут по умолчанию
    keyGenerator = (req) => `${req.method}:${req.originalUrl}`,
    condition = (req, _res) => req.method === 'GET',
    vary = [] // Заголовки для учета в ключе кэша
  } = options;

  return (req, res, next) => {
    // Проверяем условие кэширования
    if (!condition(req, res)) {
      return next();
    }

    // Генерируем ключ кэша
    let cacheKey = keyGenerator(req);

    // Добавляем vary заголовки к ключу
    if (vary.length > 0) {
      const varyValues = vary.map(header => `${header}:${req.get(header) || ''}`).join('|');
      cacheKey += `|${varyValues}`;
    }

    // Проверяем кэш
    const cachedResponse = globalCache.get(cacheKey);
    if (cachedResponse) {
      // Устанавливаем заголовки из кэша
      if (cachedResponse.headers) {
        Object.entries(cachedResponse.headers).forEach(([key, value]) => {
          res.set(key, value);
        });
      }

      // Добавляем заголовок о том, что ответ из кэша
      res.set('X-Cache', 'HIT');
      res.set('X-Cache-TTL', Math.floor((cachedResponse.expiresAt - Date.now()) / 1000));

      return res.status(cachedResponse.status).json(cachedResponse.data);
    }

    // Перехватываем оригинальный res.json
    const originalJson = res.json;
    const originalStatus = res.status;
    let statusCode = 200;

    // Перехватываем установку статуса
    res.status = function(code) {
      statusCode = code;
      return originalStatus.call(this, code);
    };

    res.json = function(data) {
      // Кэшируем только успешные ответы
      if (statusCode >= 200 && statusCode < 300) {
        const responseToCache = {
          data,
          status: statusCode,
          headers: {},
          expiresAt: Date.now() + ttl
        };

        // Сохраняем определенные заголовки
        const headersToCache = ['Content-Type', 'Last-Modified', 'ETag'];
        headersToCache.forEach(header => {
          const value = res.get(header);
          if (value) {
            responseToCache.headers[header] = value;
          }
        });

        globalCache.set(cacheKey, responseToCache, ttl);
      }

      // Добавляем заголовок о том, что ответ не из кэша
      res.set('X-Cache', 'MISS');

      return originalJson.call(this, data);
    };

    next();
  };
}

/**
 * Middleware для инвалидации кэша при POST/PUT/DELETE запросах
 */
function invalidateCacheMiddleware(patterns = []) {
  return (req, res, next) => {
    // Сохраняем оригинальные методы
    const originalJson = res.json;
    const originalSend = res.send;

    const invalidateCache = () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        let invalidatedCount = 0;

        // Инвалидируем по паттернам
        patterns.forEach(pattern => {
          const count = globalCache.invalidatePattern(pattern);
          invalidatedCount += count;
        });

        // Автоматическая инвалидация на основе URL
        const baseUrl = req.baseUrl || '';
        const resourcePattern = `GET:${baseUrl}.*`;
        invalidatedCount += globalCache.invalidatePattern(resourcePattern);

        if (invalidatedCount > 0) {
          logger.debug(`Cache invalidated: ${invalidatedCount} entries`, {
            patterns: [...patterns, resourcePattern],
            count: invalidatedCount
          });
        }
      }
    };

    // Перехватываем ответы
    res.json = function(data) {
      invalidateCache();
      return originalJson.call(this, data);
    };

    res.send = function(data) {
      invalidateCache();
      return originalSend.call(this, data);
    };

    next();
  };
}

/**
 * Кэширование для статических данных (системные настройки и т.д.)
 */
function staticCacheMiddleware(ttl = 3600000) { // 1 час по умолчанию
  return cacheMiddleware({
    ttl,
    keyGenerator: (req) => `static:${req.originalUrl}`,
    condition: (req) => req.method === 'GET'
  });
}

/**
 * Пользовательское кэширование (учитывает пользователя)
 */
function userCacheMiddleware(ttl = 300000) { // 5 минут
  return cacheMiddleware({
    ttl,
    keyGenerator: (req) => {
      const userId = req.user?.id || 'anonymous';
      return `user:${userId}:${req.originalUrl}`;
    },
    condition: (req) => req.method === 'GET' && req.user
  });
}

/**
 * Кэширование для admin endpoints
 */
function adminCacheMiddleware(ttl = 120000) { // 2 минуты
  return cacheMiddleware({
    ttl,
    keyGenerator: (req) => `admin:${req.originalUrl}`,
    condition: (req) => req.method === 'GET' && req.user?.is_admin
  });
}

/**
 * Endpoint для получения статистики кэша
 */
function getCacheStats(req, res) {
  const stats = globalCache.getStats();

  res.json({
    cache: stats,
    recommendations: generateCacheRecommendations(stats)
  });
}

/**
 * Endpoint для очистки кэша
 */
function clearCache(req, res) {
  try {
    logger.info('Cache clear request received', {
      method: req.method,
      query: req.query,
      body: req.body,
      url: req.url
    });

    const pattern = req.query.pattern;

    if (pattern) {
      const cleared = globalCache.invalidatePattern(pattern);
      logger.info(`Cache cleared by pattern`, { pattern, cleared });
      res.json({
        message: `Очищено ${cleared} записей по паттерну: ${pattern}`,
        cleared
      });
    } else {
      globalCache.clear();
      logger.info('Full cache cleared');
      res.json({ message: 'Весь кэш очищен' });
    }
  } catch (error) {
    logger.error('Cache clear error', { error: error.message, stack: error.stack });
    sendError.serverError(res, { message: 'Ошибка очистки кэша' });
  }
}

/**
 * Генерация рекомендаций по кэшу
 */
function generateCacheRecommendations(stats) {
  const recommendations = [];

  const hitRate = parseFloat(stats.hitRate);

  if (hitRate < 50) {
    recommendations.push('Низкий hit rate. Рассмотрите увеличение TTL для часто запрашиваемых данных');
  }

  if (stats.evictions > stats.hits * 0.1) {
    recommendations.push('Много вытеснений из кэша. Рассмотрите увеличение размера кэша');
  }

  const memoryMB = parseFloat(stats.memoryUsage.mb);
  if (memoryMB > 100) {
    recommendations.push('Высокое потребление памяти кэшем. Проверьте размеры кэшируемых объектов');
  }

  if (recommendations.length === 0) {
    recommendations.push('Кэш работает эффективно');
  }

  return recommendations;
}

module.exports = {
  cacheMiddleware,
  invalidateCacheMiddleware,
  staticCacheMiddleware,
  userCacheMiddleware,
  adminCacheMiddleware,
  getCacheStats,
  clearCache
};