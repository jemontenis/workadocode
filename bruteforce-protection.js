// middleware/bruteforce-protection.js - IP-based брутфорс защита
// Критический модуль безопасности для предотвращения атак перебора паролей

'use strict';

const { globalCache } = require('../lib/cache-manager');
const SecurityValidator = require('../lib/security-validator');
const { getConfig } = require('../lib/config');
const { getLogger } = require('../lib/logger');
const { sendError } = require('./error-handler');

const config = getConfig();
const logger = getLogger();

// Константы для безопасности и лимитов
const MILLISECONDS_IN_SECOND = 1000;
const USER_AGENT_MAX_LENGTH = 100;
const DEFAULT_BLOCK_DURATION = 3600000; // 1 час в миллисекундах

/**
 * BruteforceProtection - система защиты от брутфорс атак
 * 
 * Функции:
 * - Отслеживание неудачных попыток входа по IP
 * - Экспоненциальная блокировка после превышения лимита
 * - Whitelist для доверенных IP
 * - Логирование подозрительной активности
 * - Автоматическая очистка устаревших записей
 */
class BruteforceProtection {
  constructor(options = {}) {
    this.config = {
      ...config.security.bruteforce,
      ...options
    };

    this.cache = globalCache;
    this.cleanupInterval = null;

    // Запускаем периодическую очистку
    if (this.config.enabled) {
      this.startCleanup();
    }

    // Статистика для мониторинга
    this.stats = {
      blockedAttempts: 0,
      failedAttempts: 0,
      whitelistedAttempts: 0,
      suspiciousIPs: new Set()
    };
  }

  /**
   * Middleware для проверки брутфорс атак
   * 
   * @param {string} action - тип действия (login, register, reset_password)
   * @returns {Function} Express middleware
   */
  middleware(action = 'login') {
    return async(req, res, next) => {
      // Пропускаем если защита отключена
      if (!this.config.enabled) {
        return next();
      }

      try {
        // Извлекаем IP клиента
        const clientIP = SecurityValidator.extractClientIP(req, this.config.includeProxyHeaders);
        
        // Сохраняем IP в request для дальнейшего использования
        req.clientIP = clientIP;
        req.bruteforceAction = action;

        // Проверяем whitelist
        if (SecurityValidator.isIPWhitelisted(clientIP, this.config.whitelistIPs)) {
          this.stats.whitelistedAttempts++;
          logger.debug('Bruteforce protection: IP whitelisted', { 
            ip: clientIP, 
            action 
          });
          return next();
        }

        // Проверяем блокировку
        const blockKey = SecurityValidator.generateBruteforceKey(clientIP, action);
        const blockData = await this.cache.get(blockKey);

        if (blockData && blockData.blocked) {
          const remainingTime = blockData.blockedUntil - Date.now();
          
          if (remainingTime > 0) {
            this.stats.blockedAttempts++;
            
            // Логируем заблокированную попытку
            logger.warn('Bruteforce protection: Blocked attempt', {
              ip: clientIP,
              action,
              remainingTime: Math.ceil(remainingTime / MILLISECONDS_IN_SECOND),
              attemptCount: blockData.attemptCount,
              userAgent: req.get('User-Agent')?.substring(0, USER_AGENT_MAX_LENGTH)
            });

            // Отправляем детальную информацию о блокировке
            return sendError.tooManyRequests(res, {
              message: 'IP временно заблокирован из-за подозрительной активности',
              retryAfter: Math.ceil(remainingTime / MILLISECONDS_IN_SECOND),
              blockedUntil: new Date(blockData.blockedUntil).toISOString()
            });
          } else {
            // Блокировка истекла, сбрасываем данные
            await this.resetAttempts(clientIP, action);
          }
        }

        // Проверяем подозрительную активность
        await this.checkSuspiciousActivity(clientIP, req);

        next();
      } catch (error) {
        logger.error('Bruteforce protection error', {
          error: error.message,
          stack: error.stack
        });
        // В случае ошибки пропускаем запрос, чтобы не блокировать легитимных пользователей
        next();
      }
    };
  }

  /**
   * Регистрация неудачной попытки
   * 
   * @param {string} ip - IP адрес клиента
   * @param {string} action - тип действия
   * @param {Object} metadata - дополнительные данные
   */
  async recordFailedAttempt(ip, action = 'login', metadata = {}) {
    if (!this.config.enabled) return;

    try {
      const blockKey = SecurityValidator.generateBruteforceKey(ip, action);
      let blockData = await this.cache.get(blockKey) || {
        attemptCount: 0,
        firstAttempt: Date.now(),
        lastAttempt: Date.now(),
        blocked: false,
        metadata: {}
      };

      blockData.attemptCount++;
      blockData.lastAttempt = Date.now();
      blockData.metadata = {
        ...blockData.metadata,
        ...metadata
      };

      this.stats.failedAttempts++;

      // Проверяем превышение лимита попыток
      if (blockData.attemptCount >= this.config.maxAttempts) {
        // Рассчитываем время блокировки
        const blockDuration = SecurityValidator.calculateBlockDuration(
          blockData.attemptCount,
          this.config.blockDurations
        );

        blockData.blocked = true;
        blockData.blockedAt = Date.now();
        blockData.blockedUntil = Date.now() + blockDuration;

        // Добавляем IP в список подозрительных
        this.stats.suspiciousIPs.add(ip);

        // Логируем блокировку с высоким приоритетом
        logger.error('Bruteforce protection: IP blocked', {
          ip,
          action,
          attemptCount: blockData.attemptCount,
          blockDuration: blockDuration / MILLISECONDS_IN_SECOND,
          metadata,
          userAgent: metadata.userAgent
        });

        // Отправляем алерт если это критическое действие
        if (action === 'login' && blockData.attemptCount >= this.config.suspiciousActivityThreshold) {
          logger.logSecurity('bruteforce_critical', {
            ip,
            attemptCount: blockData.attemptCount,
            action,
            metadata
          });
        }
      } else {
        logger.warn('Bruteforce protection: Failed attempt recorded', {
          ip,
          action,
          attemptCount: blockData.attemptCount,
          remainingAttempts: this.config.maxAttempts - blockData.attemptCount
        });
      }

      // Сохраняем данные в кэш с TTL = tracking window
      await this.cache.set(blockKey, blockData, this.config.trackingWindow);

      return blockData;
    } catch (error) {
      logger.error('Failed to record bruteforce attempt', {
        error: error.message,
        ip,
        action
      });
    }
  }

  /**
   * Регистрация успешной попытки (сброс счетчика)
   * 
   * @param {string} ip - IP адрес клиента
   * @param {string} action - тип действия
   */
  async recordSuccessfulAttempt(ip, action = 'login') {
    if (!this.config.enabled) return;

    try {
      await this.resetAttempts(ip, action);
      
      logger.info('Bruteforce protection: Successful attempt, counter reset', {
        ip,
        action
      });
    } catch (error) {
      logger.error('Failed to record successful attempt', {
        error: error.message,
        ip,
        action
      });
    }
  }

  /**
   * Сброс счетчика попыток для IP
   * 
   * @param {string} ip - IP адрес
   * @param {string} action - тип действия
   */
  async resetAttempts(ip, action = 'login') {
    const blockKey = SecurityValidator.generateBruteforceKey(ip, action);
    await this.cache.delete(blockKey);
  }

  /**
   * Проверка подозрительной активности
   * 
   * @param {string} ip - IP адрес
   * @param {Object} req - Express request
   */
  async checkSuspiciousActivity(ip, req) {
    try {
      // Проверяем множественные действия с одного IP
      const actions = ['login', 'register', 'reset_password'];
      let totalAttempts = 0;

      for (const action of actions) {
        const key = SecurityValidator.generateBruteforceKey(ip, action);
        const data = await this.cache.get(key);
        if (data) {
          totalAttempts += data.attemptCount || 0;
        }
      }

      // Если общее количество попыток подозрительно высокое
      if (totalAttempts >= this.config.suspiciousActivityThreshold) {
        this.stats.suspiciousIPs.add(ip);
        
        logger.warn('Bruteforce protection: Suspicious activity detected', {
          ip,
          totalAttempts,
          userAgent: req.get('User-Agent')?.substring(0, USER_AGENT_MAX_LENGTH),
          fingerprint: SecurityValidator.generateClientFingerprint(req)
        });

        // Можем добавить дополнительные проверки или действия
        // например, требование капчи
        req.requireCaptcha = true;
      }
    } catch (error) {
      logger.error('Failed to check suspicious activity', {
        error: error.message,
        ip
      });
    }
  }

  /**
   * Получение статуса блокировки для IP
   * 
   * @param {string} ip - IP адрес
   * @param {string} action - тип действия
   * @returns {Object} статус блокировки
   */
  async getBlockStatus(ip, action = 'login') {
    try {
      const blockKey = SecurityValidator.generateBruteforceKey(ip, action);
      const blockData = await this.cache.get(blockKey);

      if (!blockData) {
        return {
          blocked: false,
          attemptCount: 0,
          remainingAttempts: this.config.maxAttempts
        };
      }

      const isBlocked = blockData.blocked && blockData.blockedUntil > Date.now();
      
      return {
        blocked: isBlocked,
        attemptCount: blockData.attemptCount,
        remainingAttempts: Math.max(0, this.config.maxAttempts - blockData.attemptCount),
        blockedUntil: blockData.blockedUntil,
        remainingTime: isBlocked ? blockData.blockedUntil - Date.now() : 0
      };
    } catch (error) {
      logger.error('Failed to get block status', {
        error: error.message,
        ip,
        action
      });
      return {
        blocked: false,
        attemptCount: 0,
        remainingAttempts: this.config.maxAttempts
      };
    }
  }

  /**
   * Ручная блокировка IP
   * 
   * @param {string} ip - IP адрес для блокировки
   * @param {number} duration - длительность блокировки в мс
   * @param {string} reason - причина блокировки
   */
  async blockIP(ip, duration = DEFAULT_BLOCK_DURATION, reason = 'Manual block') {
    try {
      const blockKey = SecurityValidator.generateBruteforceKey(ip, 'manual');
      const blockData = {
        attemptCount: this.config.maxAttempts,
        blocked: true,
        blockedAt: Date.now(),
        blockedUntil: Date.now() + duration,
        reason,
        metadata: { manual: true }
      };

      await this.cache.set(blockKey, blockData, duration);
      this.stats.suspiciousIPs.add(ip);

      logger.warn('Bruteforce protection: IP manually blocked', {
        ip,
        duration: duration / MILLISECONDS_IN_SECOND,
        reason
      });

      return true;
    } catch (error) {
      logger.error('Failed to manually block IP', {
        error: error.message,
        ip
      });
      return false;
    }
  }

  /**
   * Снятие блокировки с IP
   * 
   * @param {string} ip - IP адрес
   */
  async unblockIP(ip) {
    try {
      const actions = ['login', 'register', 'reset_password', 'manual'];
      
      for (const action of actions) {
        await this.resetAttempts(ip, action);
      }

      this.stats.suspiciousIPs.delete(ip);

      logger.info('Bruteforce protection: IP unblocked', { ip });
      return true;
    } catch (error) {
      logger.error('Failed to unblock IP', {
        error: error.message,
        ip
      });
      return false;
    }
  }

  /**
   * Периодическая очистка устаревших записей
   */
  startCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.cleanupInterval = setInterval(() => {
      try {
        // Очищаем устаревшие записи через invalidatePattern
        const expiredPattern = 'bruteforce:*';
        const cleaned = this.cache.invalidatePattern(expiredPattern);
        
        if (cleaned > 0) {
          logger.info('Bruteforce protection: Cleanup completed', {
            cleanedEntries: cleaned
          });
        }
      } catch (error) {
        logger.error('Bruteforce cleanup error', {
          error: error.message
        });
      }
    }, this.config.cleanupInterval);

    logger.info('Bruteforce protection: Cleanup scheduler started', {
      interval: this.config.cleanupInterval / MILLISECONDS_IN_SECOND
    });
  }

  /**
   * Остановка очистки
   */
  stopCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
      logger.info('Bruteforce protection: Cleanup scheduler stopped');
    }
  }

  /**
   * Получение статистики
   * 
   * @returns {Object} статистика защиты
   */
  getStats() {
    return {
      ...this.stats,
      suspiciousIPCount: this.stats.suspiciousIPs.size,
      suspiciousIPs: Array.from(this.stats.suspiciousIPs),
      config: {
        enabled: this.config.enabled,
        maxAttempts: this.config.maxAttempts,
        whitelistCount: this.config.whitelistIPs.length
      }
    };
  }

  /**
   * Сброс статистики
   */
  resetStats() {
    this.stats = {
      blockedAttempts: 0,
      failedAttempts: 0,
      whitelistedAttempts: 0,
      suspiciousIPs: new Set()
    };
  }

  /**
   * Уничтожение экземпляра (для graceful shutdown)
   */
  destroy() {
    this.stopCleanup();
    this.resetStats();
    logger.info('Bruteforce protection: Instance destroyed');
  }
}

// Создаем глобальный экземпляр
const bruteforceProtection = new BruteforceProtection();

// Middleware функции для удобного использования
const checkBruteforce = (action = 'login') => bruteforceProtection.middleware(action);

// Helper для интеграции с маршрутами авторизации
const bruteforceHelpers = {
  /**
   * Обработчик неудачной попытки входа
   */
  async handleFailedLogin(req, email) {
    const ip = req.clientIP || SecurityValidator.extractClientIP(req);
    await bruteforceProtection.recordFailedAttempt(ip, 'login', {
      email: email?.substring(0, 3) + '***', // Частично скрываем email
      userAgent: req.get('User-Agent')?.substring(0, 100),
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Обработчик успешного входа
   */
  async handleSuccessfulLogin(req) {
    const ip = req.clientIP || SecurityValidator.extractClientIP(req);
    await bruteforceProtection.recordSuccessfulAttempt(ip, 'login');
  },

  /**
   * Обработчик неудачной регистрации
   */
  async handleFailedRegister(req, reason) {
    const ip = req.clientIP || SecurityValidator.extractClientIP(req);
    await bruteforceProtection.recordFailedAttempt(ip, 'register', {
      reason,
      userAgent: req.get('User-Agent')?.substring(0, 100),
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Обработчик успешной регистрации
   */
  async handleSuccessfulRegister(req) {
    const ip = req.clientIP || SecurityValidator.extractClientIP(req);
    await bruteforceProtection.recordSuccessfulAttempt(ip, 'register');
  }
};

// Graceful shutdown
process.on('SIGINT', () => {
  bruteforceProtection.destroy();
});

process.on('SIGTERM', () => {
  bruteforceProtection.destroy();
});

module.exports = {
  BruteforceProtection,
  bruteforceProtection,
  checkBruteforce,
  bruteforceHelpers
};