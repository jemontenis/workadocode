// middleware/performance-monitor.js - Мониторинг производительности

'use strict';

const { globalCache } = require('../lib/cache-manager');
const { getLogger } = require('../lib/logger');

const logger = getLogger();

// Константы для производительности
const MAX_METRICS_COUNT = 500; // Максимум уникальных маршрутов
const MAX_SLOW_QUERIES_COUNT = 100; // Максимум медленных запросов
const MAX_REQUEST_TIMES_COUNT = 1000; // Максимум записей времени запросов
const MAX_STATUS_CODES_PER_METRIC = 10; // Максимум уникальных статус кодов на метрику
const METRICS_RETENTION_MS = 2 * 60 * 60 * 1000; // 2 часа для метрик
const SLOW_QUERY_RETENTION_MS = 24 * 60 * 60 * 1000; // 24 часа для медленных запросов
const REQUEST_TIMES_RETENTION_MS = 30 * 60 * 1000; // 30 минут для времени запросов
const SLOW_REQUEST_THRESHOLD_MS = 2000; // 2 секунды
const VERY_SLOW_REQUEST_THRESHOLD_MS = 5000; // 5 секунд
const QUERY_SIZE_LIMIT = 500; // Максимальный размер query для логирования
const TIMES_ARRAY_LIMIT = 100; // Лимит массива времен
const CLEANUP_INTERVAL_MS = 15 * 60 * 1000; // 15 минут
const MEMORY_MONITOR_INTERVAL_MS = 5 * 60 * 1000; // 5 минут
const HIGH_MEMORY_THRESHOLD_MB = 500; // 500MB
const HEAP_GROWTH_THRESHOLD_MB = 50 * 1024 * 1024; // 50MB
const ITEMS_GROWTH_THRESHOLD = 100;
const MEMORY_LEAK_THRESHOLD_MB = 10 * 1024 * 1024; // 10MB/min
const MEMORY_SHRINK_THRESHOLD_MB = -5 * 1024 * 1024; // -5MB/min
const ETAG_CACHE_SIZE_LIMIT = 1000;

class PerformanceMonitor {
  constructor() {
    this.metrics = new Map();
    this.requestTimes = new Map();
    this.slowQueries = [];

    // Лимиты на размер коллекций для предотвращения утечек памяти
    this.maxMetrics = MAX_METRICS_COUNT;
    this.maxSlowQueries = MAX_SLOW_QUERIES_COUNT;
    this.maxRequestTimes = MAX_REQUEST_TIMES_COUNT;
    this.maxStatusCodesPerMetric = MAX_STATUS_CODES_PER_METRIC;

    // Настройки автоматической очистки
    this.metricsRetentionMs = METRICS_RETENTION_MS;
    this.slowQueryRetentionMs = SLOW_QUERY_RETENTION_MS;
    this.requestTimesRetentionMs = REQUEST_TIMES_RETENTION_MS;
    
    // Счетчики для мониторинга памяти
    this.cleanupStats = {
      totalCleanups: 0,
      lastCleanup: Date.now(),
      itemsRemoved: 0,
      memorySnapshots: []
    };
    
    // Запускаем автоматическую очистку
    this.startAutoCleanup();
  }

  /**
   * Middleware для мониторинга времени выполнения запросов
   */
  requestTimer() {
    return (req, res, next) => {
      const startTime = Date.now();

      // Перехватываем окончание ответа
      const originalEnd = res.end;
      res.end = function(...args) {
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Записываем метрику
        monitor.recordRequest(req, res, duration);

        return originalEnd.apply(this, args);
      };

      next();
    };
  }

  /**
   * Записать метрику запроса
   */
  recordRequest(req, res, duration) {
    const route = this.getRoutePattern(req.route?.path || req.path);
    const method = req.method;
    const statusCode = res.statusCode;
    const key = `${method}:${route}`;

    // Проверяем лимит метрик перед добавлением новых
    if (!this.metrics.has(key) && this.metrics.size >= this.maxMetrics) {
      this.evictOldestMetrics();
    }

    // Обновляем статистику
    if (!this.metrics.has(key)) {
      this.metrics.set(key, {
        method,
        route,
        count: 0,
        totalTime: 0,
        avgTime: 0,
        minTime: Infinity,
        maxTime: 0,
        statusCodes: new Map(),
        lastAccess: Date.now()
      });
    }

    const metric = this.metrics.get(key);
    metric.count++;
    metric.totalTime += duration;
    metric.avgTime = Math.round(metric.totalTime / metric.count);
    metric.minTime = Math.min(metric.minTime, duration);
    metric.maxTime = Math.max(metric.maxTime, duration);
    metric.lastAccess = Date.now();

    // Подсчитываем коды ответов с лимитом
    const statusCount = metric.statusCodes.get(statusCode) || 0;
    metric.statusCodes.set(statusCode, statusCount + 1);
    
    // Ограничиваем количество уникальных статус кодов
    if (metric.statusCodes.size > this.maxStatusCodesPerMetric) {
      this.limitStatusCodes(metric.statusCodes);
    }

    // Записываем время запроса для детального мониторинга
    this.recordRequestTime(key, duration);

    // Записываем медленные запросы (>2 сек)
    if (duration > SLOW_REQUEST_THRESHOLD_MS) {
      this.recordSlowQuery(method, route, duration, req.query, statusCode);
    }

    // Логируем очень медленные запросы
    if (duration > VERY_SLOW_REQUEST_THRESHOLD_MS) {
      logger.logPerformance('slow_request', duration, { method, route });
    }
  }

  /**
   * Получить паттерн маршрута (заменить ID на :id)
   */
  getRoutePattern(path) {
    if (!path) return 'unknown';

    return path
      .replace(/\/[a-zA-Z0-9_-]{12,}(?=\/|$)/g, '/:id')
      .replace(/\/\d+(?=\/|$)/g, '/:id')
      .replace(/\?.*$/, '');
  }

  /**
   * Записать медленный запрос
   */
  recordSlowQuery(method, route, duration, query, statusCode) {
    const slowQuery = {
      method,
      route,
      duration,
      query: JSON.stringify(query).slice(0, QUERY_SIZE_LIMIT), // Ограничиваем размер query для экономии памяти
      statusCode,
      timestamp: Date.now()
    };

    this.slowQueries.unshift(slowQuery);

    // Ограничиваем размер массива и удаляем старые записи
    if (this.slowQueries.length > this.maxSlowQueries) {
      const removed = this.slowQueries.length - this.maxSlowQueries;
      this.slowQueries = this.slowQueries.slice(0, this.maxSlowQueries);
      this.cleanupStats.itemsRemoved += removed;
    }
    
    // Очищаем слишком старые записи
    this.cleanupOldSlowQueries();
  }

  /**
   * Записать время запроса для детального мониторинга
   */
  recordRequestTime(key, duration) {
    if (!this.requestTimes.has(key)) {
      this.requestTimes.set(key, []);
    }
    
    const times = this.requestTimes.get(key);
    times.push({
      duration,
      timestamp: Date.now()
    });
    
    // Ограничиваем размер массива времен
    if (times.length > TIMES_ARRAY_LIMIT) {
      times.shift();
    }
    
    // Проверяем общий лимит requestTimes
    if (this.requestTimes.size > this.maxRequestTimes) {
      this.evictOldestRequestTimes();
    }
  }

  /**
   * Удалить самые старые метрики при достижении лимита
   */
  evictOldestMetrics() {
    const sortedMetrics = Array.from(this.metrics.entries())
      .sort((a, b) => a[1].lastAccess - b[1].lastAccess);
    
    // Удаляем 10% самых старых метрик
    const toRemove = Math.max(1, Math.floor(this.maxMetrics * 0.1));
    for (let i = 0; i < toRemove && i < sortedMetrics.length; i++) {
      this.metrics.delete(sortedMetrics[i][0]);
      this.cleanupStats.itemsRemoved++;
    }
  }

  /**
   * Удалить самые старые записи времени запросов
   */
  evictOldestRequestTimes() {
    const sortedTimes = Array.from(this.requestTimes.entries())
      .sort((a, b) => {
        const lastA = a[1][a[1].length - 1]?.timestamp || 0;
        const lastB = b[1][b[1].length - 1]?.timestamp || 0;
        return lastA - lastB;
      });
    
    // Удаляем 10% самых старых записей
    const toRemove = Math.max(1, Math.floor(this.maxRequestTimes * 0.1));
    for (let i = 0; i < toRemove && i < sortedTimes.length; i++) {
      this.requestTimes.delete(sortedTimes[i][0]);
      this.cleanupStats.itemsRemoved++;
    }
  }

  /**
   * Ограничить количество статус кодов в метрике
   */
  limitStatusCodes(statusCodes) {
    // Сортируем по количеству и оставляем только топ N
    const sorted = Array.from(statusCodes.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.maxStatusCodesPerMetric);
    
    statusCodes.clear();
    sorted.forEach(([code, count]) => statusCodes.set(code, count));
  }

  /**
   * Очистить старые медленные запросы
   */
  cleanupOldSlowQueries() {
    const cutoff = Date.now() - this.slowQueryRetentionMs;
    const originalLength = this.slowQueries.length;
    
    this.slowQueries = this.slowQueries.filter(q => q.timestamp > cutoff);
    
    const removed = originalLength - this.slowQueries.length;
    if (removed > 0) {
      this.cleanupStats.itemsRemoved += removed;
    }
  }

  /**
   * Получить метрики производительности
   */
  getMetrics() {
    const metrics = Array.from(this.metrics.values())
      .sort((a, b) => b.avgTime - a.avgTime)
      .map(metric => ({
        ...metric,
        statusCodes: Object.fromEntries(metric.statusCodes)
      }));

    const summary = {
      totalRequests: Array.from(this.metrics.values()).reduce((sum, m) => sum + m.count, 0),
      avgResponseTime: this.getOverallAvgTime(),
      slowestEndpoints: metrics.slice(0, 10),
      recentSlowQueries: this.slowQueries.slice(0, 20)
    };

    return { summary, metrics };
  }

  /**
   * Получить общее среднее время ответа
   */
  getOverallAvgTime() {
    const metrics = Array.from(this.metrics.values());
    if (metrics.length === 0) return 0;

    const totalTime = metrics.reduce((sum, m) => sum + m.totalTime, 0);
    const totalRequests = metrics.reduce((sum, m) => sum + m.count, 0);

    return totalRequests > 0 ? Math.round(totalTime / totalRequests) : 0;
  }

  /**
   * Очистить старые метрики
   */
  cleanupOldMetrics() {
    const cutoff = Date.now() - this.metricsRetentionMs;
    let removed = 0;

    for (const [key, metric] of this.metrics.entries()) {
      if (metric.lastAccess < cutoff) {
        this.metrics.delete(key);
        removed++;
      }
    }

    if (removed > 0) {
      this.cleanupStats.itemsRemoved += removed;
      logger.info(`Очищено ${removed} старых метрик`);
    }
  }

  /**
   * Очистить старые записи времени запросов
   */
  cleanupOldRequestTimes() {
    const cutoff = Date.now() - this.requestTimesRetentionMs;
    let removed = 0;

    for (const [key, times] of this.requestTimes.entries()) {
      // Фильтруем старые записи в массиве
      const originalLength = times.length;
      const filtered = times.filter(t => t.timestamp > cutoff);
      
      if (filtered.length === 0) {
        // Если все записи старые, удаляем ключ
        this.requestTimes.delete(key);
        removed += originalLength;
      } else if (filtered.length < originalLength) {
        // Обновляем массив без старых записей
        this.requestTimes.set(key, filtered);
        removed += originalLength - filtered.length;
      }
    }

    if (removed > 0) {
      this.cleanupStats.itemsRemoved += removed;
    }
  }

  /**
   * Запустить автоматическую очистку
   */
  startAutoCleanup() {
    // Очистка каждые 15 минут
    this.cleanupInterval = setInterval(() => {
      this.performFullCleanup();
    }, CLEANUP_INTERVAL_MS);

    // Мониторинг памяти каждые 5 минут
    this.memoryMonitorInterval = setInterval(() => {
      this.monitorMemoryUsage();
    }, MEMORY_MONITOR_INTERVAL_MS);
  }

  /**
   * Выполнить полную очистку всех коллекций
   */
  performFullCleanup() {
    const startTime = Date.now();
    const initialItems = this.getTotalItemsCount();

    // Очищаем все коллекции
    this.cleanupOldMetrics();
    this.cleanupOldSlowQueries();
    this.cleanupOldRequestTimes();
    
    // Принудительная сборка мусора если доступна
    if (global.gc) {
      global.gc();
    }

    const endTime = Date.now();
    const finalItems = this.getTotalItemsCount();
    const itemsRemoved = initialItems - finalItems;

    this.cleanupStats.totalCleanups++;
    this.cleanupStats.lastCleanup = Date.now();

    if (itemsRemoved > 0) {
      logger.info('Выполнена очистка памяти PerformanceMonitor', {
        duration: endTime - startTime,
        itemsRemoved,
        totalItems: finalItems,
        metrics: this.metrics.size,
        slowQueries: this.slowQueries.length,
        requestTimes: this.requestTimes.size
      });
    }
  }

  /**
   * Мониторинг использования памяти
   */
  monitorMemoryUsage() {
    const memUsage = process.memoryUsage();
    const memoryInfo = {
      timestamp: Date.now(),
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      rss: memUsage.rss,
      external: memUsage.external,
      monitorStats: {
        metrics: this.metrics.size,
        slowQueries: this.slowQueries.length,
        requestTimes: this.requestTimes.size,
        totalItems: this.getTotalItemsCount()
      }
    };

    // Сохраняем снимок памяти
    this.cleanupStats.memorySnapshots.push(memoryInfo);
    
    // Ограничиваем количество снимков (последние 12 = 1 час при интервале 5 минут)
    if (this.cleanupStats.memorySnapshots.length > 12) {
      this.cleanupStats.memorySnapshots.shift();
    }

    // Проверяем на утечки памяти
    this.detectMemoryLeak();

    // Если используется слишком много памяти, форсируем очистку
    const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
    if (heapUsedMB > HIGH_MEMORY_THRESHOLD_MB) {
      logger.warn('Высокое использование памяти в PerformanceMonitor, запускаем экстренную очистку', {
        heapUsedMB: Math.round(heapUsedMB),
        items: this.getTotalItemsCount()
      });
      this.performAggressiveCleanup();
    }
  }

  /**
   * Обнаружение утечек памяти
   */
  detectMemoryLeak() {
    const snapshots = this.cleanupStats.memorySnapshots;
    if (snapshots.length < 3) return;

    // Анализируем тренд последних снимков
    const recent = snapshots.slice(-3);
    const heapGrowth = recent[2].heapUsed - recent[0].heapUsed;
    const itemsGrowth = recent[2].monitorStats.totalItems - recent[0].monitorStats.totalItems;

    // Если память растет быстрее чем количество элементов
    if (heapGrowth > HEAP_GROWTH_THRESHOLD_MB && itemsGrowth < ITEMS_GROWTH_THRESHOLD) {
      logger.warn('Возможная утечка памяти обнаружена в PerformanceMonitor', {
        heapGrowthMB: Math.round(heapGrowth / 1024 / 1024),
        itemsGrowth,
        currentItems: this.getTotalItemsCount()
      });
    }
  }

  /**
   * Агрессивная очистка при критическом использовании памяти
   */
  performAggressiveCleanup() {
    // Сокращаем лимиты временно
    const originalMaxMetrics = this.maxMetrics;
    const originalMaxSlowQueries = this.maxSlowQueries;
    
    this.maxMetrics = Math.floor(this.maxMetrics * 0.5);
    this.maxSlowQueries = Math.floor(this.maxSlowQueries * 0.5);
    
    // Удаляем 50% самых старых данных
    this.evictMetricsByPercentage(50);
    this.slowQueries = this.slowQueries.slice(0, this.maxSlowQueries);
    this.evictRequestTimesByPercentage(50);
    
    // Восстанавливаем лимиты
    this.maxMetrics = originalMaxMetrics;
    this.maxSlowQueries = originalMaxSlowQueries;
    
    // Форсируем сборку мусора
    if (global.gc) {
      global.gc();
    }
    
    logger.info('Выполнена агрессивная очистка памяти PerformanceMonitor');
  }

  /**
   * Удалить процент метрик
   */
  evictMetricsByPercentage(percentage) {
    const toRemove = Math.floor(this.metrics.size * percentage / 100);
    const sorted = Array.from(this.metrics.entries())
      .sort((a, b) => a[1].lastAccess - b[1].lastAccess);
    
    for (let i = 0; i < toRemove && i < sorted.length; i++) {
      this.metrics.delete(sorted[i][0]);
    }
  }

  /**
   * Удалить процент записей времени
   */
  evictRequestTimesByPercentage(percentage) {
    const toRemove = Math.floor(this.requestTimes.size * percentage / 100);
    const sorted = Array.from(this.requestTimes.keys());
    
    for (let i = 0; i < toRemove && i < sorted.length; i++) {
      this.requestTimes.delete(sorted[i]);
    }
  }

  /**
   * Получить общее количество элементов во всех коллекциях
   */
  getTotalItemsCount() {
    let total = this.metrics.size + this.slowQueries.length;
    
    // Подсчитываем элементы в requestTimes
    for (const times of this.requestTimes.values()) {
      total += times.length;
    }
    
    return total;
  }

  /**
   * Получить рекомендации по производительности
   */
  getPerformanceRecommendations() {
    const recommendations = [];
    const metrics = Array.from(this.metrics.values());

    // Анализируем медленные эндпоинты
    const slowEndpoints = metrics.filter(m => m.avgTime > 1000);
    if (slowEndpoints.length > 0) {
      recommendations.push({
        type: 'slow_endpoints',
        message: `Найдено ${slowEndpoints.length} медленных эндпоинтов (>1сек)`,
        endpoints: slowEndpoints.slice(0, 5).map(e => `${e.method} ${e.route} (${e.avgTime}ms)`)
      });
    }

    // Анализируем частые запросы без кэша
    const frequentEndpoints = metrics
      .filter(m => m.count > 100 && m.avgTime > 500)
      .sort((a, b) => b.count - a.count);

    if (frequentEndpoints.length > 0) {
      recommendations.push({
        type: 'caching_opportunity',
        message: 'Эндпоинты с высокой нагрузкой могут выиграть от кэширования',
        endpoints: frequentEndpoints.slice(0, 3).map(e => `${e.method} ${e.route} (${e.count} запросов, ${e.avgTime}ms)`)
      });
    }

    // Анализируем ошибки
    const errorEndpoints = metrics.filter(m => {
      const errorCount = Array.from(m.statusCodes.entries())
        .filter(([status]) => status >= 400)
        .reduce((sum, [, count]) => sum + count, 0);
      return errorCount > m.count * 0.1; // >10% ошибок
    });

    if (errorEndpoints.length > 0) {
      recommendations.push({
        type: 'high_error_rate',
        message: 'Эндпоинты с высоким процентом ошибок требуют внимания',
        endpoints: errorEndpoints.slice(0, 3).map(e => `${e.method} ${e.route}`)
      });
    }

    return recommendations;
  }

  /**
   * Получить статистику системы
   */
  getSystemStats() {
    try {
      const memUsage = process.memoryUsage() || { rss: 0, heapTotal: 0, heapUsed: 0, external: 0 };
      const uptime = process.uptime() || 0;

      return {
        memory: {
          rss: Math.round(memUsage.rss / 1024 / 1024) + ' MB',
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB',
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
          external: Math.round(memUsage.external / 1024 / 1024) + ' MB',
          heapUsedPercent: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100) + '%'
        },
        uptime: {
          seconds: Math.floor(uptime),
          human: this.formatUptime(uptime)
        },
        cache: globalCache.getStats() || { hits: 0, misses: 0, hitRate: '0.00%', size: 0 },
        monitor: {
          metrics: this.metrics.size,
          slowQueries: this.slowQueries.length,
          requestTimes: this.requestTimes.size,
          totalItems: this.getTotalItemsCount(),
          limits: {
            maxMetrics: this.maxMetrics,
            maxSlowQueries: this.maxSlowQueries,
            maxRequestTimes: this.maxRequestTimes
          },
          cleanup: {
            totalCleanups: this.cleanupStats.totalCleanups,
            lastCleanup: this.cleanupStats.lastCleanup ? 
              new Date(this.cleanupStats.lastCleanup).toISOString() : 'never',
            itemsRemoved: this.cleanupStats.itemsRemoved,
            memorySnapshots: this.cleanupStats.memorySnapshots.length
          }
        }
      };
    } catch (error) {
      return {
        memory: { rss: '0 MB', heapTotal: '0 MB', heapUsed: '0 MB', external: '0 MB', heapUsedPercent: '0%' },
        uptime: { seconds: 0, human: '0с' },
        cache: { hits: 0, misses: 0, hitRate: '0.00%', size: 0 },
        monitor: {
          metrics: 0,
          slowQueries: 0,
          requestTimes: 0,
          totalItems: 0,
          limits: {},
          cleanup: {}
        }
      };
    }
  }

  /**
   * Получить подробную статистику памяти
   */
  getMemoryStats() {
    const snapshots = this.cleanupStats.memorySnapshots;
    if (snapshots.length === 0) {
      return {
        current: this.getCurrentMemoryInfo(),
        trend: 'unknown',
        snapshots: []
      };
    }

    const current = this.getCurrentMemoryInfo();
    const oldest = snapshots[0];
    const heapGrowth = current.heapUsed - oldest.heapUsed;
    const timeElapsed = Date.now() - oldest.timestamp;
    const growthPerMinute = (heapGrowth / (timeElapsed / 60000));

    let trend = 'stable';
    if (growthPerMinute > 10 * 1024 * 1024) { // > 10MB/min
      trend = 'growing';
    } else if (growthPerMinute > 50 * 1024 * 1024) { // > 50MB/min
      trend = 'critical';
    } else if (growthPerMinute < -5 * 1024 * 1024) { // < -5MB/min
      trend = 'shrinking';
    }

    return {
      current,
      trend,
      growthPerMinute: Math.round(growthPerMinute / 1024 / 1024) + ' MB/min',
      snapshots: snapshots.map(s => ({
        timestamp: new Date(s.timestamp).toISOString(),
        heapUsedMB: Math.round(s.heapUsed / 1024 / 1024),
        items: s.monitorStats.totalItems
      }))
    };
  }

  /**
   * Получить текущую информацию о памяти
   */
  getCurrentMemoryInfo() {
    const memUsage = process.memoryUsage();
    return {
      timestamp: Date.now(),
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      rss: memUsage.rss,
      external: memUsage.external,
      monitorStats: {
        metrics: this.metrics.size,
        slowQueries: this.slowQueries.length,
        requestTimes: this.requestTimes.size,
        totalItems: this.getTotalItemsCount()
      }
    };
  }

  /**
   * Форматировать время работы
   */
  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}д`);
    if (hours > 0) parts.push(`${hours}ч`);
    if (minutes > 0) parts.push(`${minutes}м`);
    if (secs > 0 || parts.length === 0) parts.push(`${secs}с`);

    return parts.join(' ');
  }
}

// Глобальный экземпляр монитора
const monitor = new PerformanceMonitor();

// Обработка graceful shutdown
process.on('SIGTERM', () => {
  if (monitor.cleanupInterval) {
    clearInterval(monitor.cleanupInterval);
  }
  if (monitor.memoryMonitorInterval) {
    clearInterval(monitor.memoryMonitorInterval);
  }
});

process.on('SIGINT', () => {
  if (monitor.cleanupInterval) {
    clearInterval(monitor.cleanupInterval);
  }
  if (monitor.memoryMonitorInterval) {
    clearInterval(monitor.memoryMonitorInterval);
  }
});

module.exports = {
  PerformanceMonitor,
  monitor
};