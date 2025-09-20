// server.js - Workado Main Server
// КРИТИЧЕСКИЙ ФАЙЛ: Точка входа приложения
// 
// АРХИТЕКТУРА БЕЗОПАСНОСТИ:
// 1. Helmet для базовой защиты HTTP заголовков
// 2. Rate limiting для защиты от DoS
// 3. Валидация входных данных через middleware
// 4. Session security через secure cookies
// 5. CORS настройки для cross-origin запросов
// 
// ПРОИЗВОДИТЕЛЬНОСТЬ:
// - Connection pooling для БД
// - Кэширование статических ресурсов
// - Мониторинг производительности
// - Оптимизация статических файлов

const express = require('express');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const _crypto = require('crypto');
const CryptoUtils = require('./lib/crypto-utils');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body: _body, validationResult: _validationResult } = require('express-validator');
const _fileType = require('file-type');

// Новая система конфигурации и базы данных
const { getConfig } = require('./lib/config');
const DatabaseManager = require('./lib/database');
const EmailService = require('./lib/email');
const GoogleAuth = require('./lib/google-auth');
const _SecurityValidator = require('./lib/security-validator');
const FileSecurityValidator = require('./lib/file-security-validator');
const { createEnhancedFileFilter, postUploadValidation } = require('./middleware/enhanced-file-filter');
const { startPeriodicCleanup } = require('./middleware/file-security');
const validationMiddleware = require('./middleware/validation');
const _OptimizedQueries = require('./lib/optimized-queries');
const cacheMiddleware = require('./middleware/cache');
const { globalCache } = require('./lib/cache-manager');
const { monitor } = require('./middleware/performance-monitor');
const { createStaticOptimization, staticStats } = require('./middleware/static-optimization');
const { HealthChecker, MetricsCollector } = require('./lib/monitoring');
const { getLogger } = require('./lib/logger');
const DateUtils = require('./lib/date-utils');
const { errorHandler, notFoundHandler, sendError } = require('./middleware/error-handler');
const requireEmailVerification = require('./middleware/require-email-verification');
const { getAlertManager } = require('./lib/alert-manager');
// API versioning middleware removed

// Импорт модулей маршрутов
const { router: authRouter, initializeDependencies: initAuthDependencies } = require('./routes/auth');
const { router: authPagesRouter, initializeDependencies: initAuthPagesDependencies } = require('./routes/auth-pages');
const { router: tasksRouter, initializeDependencies: initTasksDependencies } = require('./routes/tasks');
const { router: usersRouter, initializeDependencies: initUsersDependencies } = require('./routes/users');
const { router: paymentsRouter, initializeDependencies: initPaymentsDependencies } = require('./routes/payments');
const { router: paymentCallbacksRouter, initializeDependencies: initPaymentCallbacksDependencies } = require('./routes/payment-callbacks');
const { router: adminRouter, initializeDependencies: initAdminDependencies } = require('./routes/admin');
const { router: supportRouter, initializeDependencies: initSupportDependencies } = require('./routes/support');
const { router: monitoringRouter, initializeDependencies: initMonitoringDependencies } = require('./routes/monitoring');
// const { router: citiesRouter, initializeDependencies: initCitiesDependencies } = require('./routes/cities');
const staticPagesRouter = require('./routes/static-pages');

// Инициализация конфигурации
const config = getConfig();
const dbConfig = config.database;
const dbManager = new DatabaseManager(dbConfig);
const emailService = new EmailService();
const googleAuth = new GoogleAuth(dbManager);
const logger = getLogger();
const alertManager = getAlertManager();

const PORT = config.server.port;
const NODE_ENV = config.server.env;
const PUBLIC_DIR = path.join(__dirname, 'public');
const AVATARS_DIR = config.upload.avatarsDir;
const SUPPORT_UPLOADS_DIR = config.upload.supportDir;
const _PUBLISH_FEE = config.business.publishFee;

// Безопасность: ограничения для production
const MAX_UPLOAD_SIZE = config.upload.maxSize;
const _MAX_CONCURRENT_REQUESTS = config.performance.maxConcurrentRequests;

// how old pending payments become "stale" and should be cancelled (ms)
const _STALE_PAYMENTS_MS = config.payments.stalePayments.timeoutMs;
const _STALE_CHECK_INTERVAL_MS = config.payments.stalePayments.checkIntervalMs;

// Логирование через централизованный logger
const isProduction = NODE_ENV === 'production';

// Централизованная функция для настройки cookies
const getCookieOptions = (req) => {
  const userAgent = req?.get?.('User-Agent') || '';
  const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');

  const options = {
    httpOnly: true,
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
    // Убираем домен полностью для лучшей совместимости
    // domain: isProduction ? 'workado.ru' : undefined
  };

  // Для Safari используем более консервативные настройки
  if (isSafari) {
    options.sameSite = 'none'; // Safari требует 'none' для кросс-доменных cookies
    options.secure = true; // SameSite=None требует Secure=true
  } else {
    options.sameSite = 'lax';
  }

  // В development режиме принудительно используем lax для всех браузеров
  if (!isProduction) {
    options.sameSite = 'lax';
    options.secure = false;
  }

  return options;
};

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(AVATARS_DIR)) fs.mkdirSync(AVATARS_DIR, { recursive: true });

// Rate limiters - используем настройки из config
const loginLimiter = rateLimit({
  windowMs: config.security.rateLimit.login.windowMs,
  max: config.security.rateLimit.login.max,
  message: { error: 'Слишком много попыток входа. Попробуйте через 15 минут.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.logSecurity('rate_limit_exceeded_login', { ip: req.ip, userAgent: req.get('User-Agent') });
    sendError.tooManyRequests(res);
  }
});

// Отдельный лимитер для сброса пароля (более мягкий)
const passwordResetLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 минут
  max: isProduction ? 8 : 20, // разрешаем больше попыток для сброса пароля
  message: { error: 'Слишком много попыток сброса пароля. Попробуйте через 5 минут.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.logSecurity('rate_limit_exceeded_password_reset', { ip: req.ip, userAgent: req.get('User-Agent') });
    sendError.tooManyRequests(res);
  }
});

const apiLimiter = rateLimit({
  windowMs: config.security.rateLimit.api.windowMs,
  max: config.security.rateLimit.api.max,
  message: {
    error: 'Слишком много запросов',
    code: 'RATE_LIMIT_EXCEEDED',
    details: {
      retryAfter: 60,
      suggestion: 'Подождите перед следующим запросом'
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const retryAfter = Math.ceil(req.rateLimit.resetTime / 1000 - Date.now() / 1000);
    res.status(429).json({
      error: 'Слишком много запросов',
      code: 'RATE_LIMIT_EXCEEDED',
      details: {
        retryAfter: retryAfter > 0 ? retryAfter : 60,
        suggestion: 'Подождите перед следующим запросом'
      }
    });
  },
  skip: (req) => {
    // Пропускаем ограничения для авторизованных пользователей при GET запросах
    if (req.method === 'GET' && req.cookies && req.cookies.sessionToken) {
      return true;
    }
    // Временно пропускаем все admin POST запросы для отладки
    if (req.method === 'POST') {
      if (req.url.startsWith('/api/admin/') || req.originalUrl.startsWith('/api/admin/') || (req.path && req.path.startsWith('/api/admin/'))) {
        return true;
      }
    }
    return false;
  }
});

const uploadLimiter = rateLimit({
  windowMs: config.security.rateLimit.upload.windowMs,
  max: config.security.rateLimit.upload.max,
  message: { error: 'Слишком много загрузок файлов. Попробуйте позже.' },
  handler: (req, res) => {
    logger.logSecurity('rate_limit_exceeded_upload', { ip: req.ip, userAgent: req.get('User-Agent') });
    sendError.tooManyRequests(res);
  }
});

// Создаем улучшенные фильтры файлов с проверкой безопасности
const avatarFileFilter = createEnhancedFileFilter({
  allowedMimeTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  maxSize: MAX_UPLOAD_SIZE,
  checkMagicNumbers: true,
  scanForMalware: true,
  quarantine: false,
  alertOnSuspicious: true
});

const fileFilter = avatarFileFilter; // Для обратной совместимости

// multer config for avatar upload с изоляцией файлов
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      // Создаем изолированную структуру директорий
      const isolatedDirs = await FileSecurityValidator.setupIsolatedUploadDir(AVATARS_DIR);
      cb(null, isolatedDirs.subdirs.images);
    } catch (error) {
      logger.error('Failed to setup avatar upload dir', { error: error.message });
      cb(null, AVATARS_DIR);
    }
  },
  filename: (req, file, cb) => {
    // Используем безопасное имя файла
    const safeName = FileSecurityValidator.sanitizeFilename(file.originalname);
    cb(null, safeName);
  }
});

const _upload = multer({
  storage,
  limits: {
    fileSize: MAX_UPLOAD_SIZE,
    files: 1,
    fieldSize: 10 * 1024 * 1024 // 10MB field size limit
  },
  fileFilter,
  onError: (err, next) => {
    logger.error('Multer upload error', { error: err.message, code: err.code });
    next(err);
  }
});

// multer config for support uploads
const supportStorage = multer.diskStorage({
  destination: async (req, file, cb) => {
    try {
      // Создаем изолированную папку по ticketId
      const ticketId = req.params.id;
      const ticketUploadDir = path.join(SUPPORT_UPLOADS_DIR, ticketId);
      
      // Создаем изолированную структуру для тикета
      const isolatedDirs = await FileSecurityValidator.setupIsolatedUploadDir(ticketUploadDir);
      
      // Определяем тип файла для правильной директории
      let targetDir = isolatedDirs.subdirs.documents;
      if (file.mimetype && file.mimetype.startsWith('image/')) {
        targetDir = isolatedDirs.subdirs.images;
      }
      
      cb(null, targetDir);
    } catch (error) {
      logger.error('Failed to setup support upload dir', { 
        error: error.message,
        ticketId: req.params.id 
      });
      // Fallback к базовой директории
      const ticketId = req.params.id;
      const uploadDir = path.join(SUPPORT_UPLOADS_DIR, ticketId);
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    }
  },
  filename: (req, file, cb) => {
    // Генерируем безопасное имя файла
    const safeName = FileSecurityValidator.sanitizeFilename(file.originalname);
    cb(null, safeName);
  }
});

// Фильтр для файлов поддержки с усиленной проверкой
const supportFileFilter = createEnhancedFileFilter({
  allowedMimeTypes: [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf', 'text/plain',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ],
  maxSize: config.upload.maxSupportFileSize,
  checkMagicNumbers: true,
  scanForMalware: true,
  quarantine: true,
  alertOnSuspicious: true
});

const supportUpload = multer({
  storage: supportStorage,
  limits: {
    fileSize: config.upload.maxSupportFileSize, // 10MB
    files: config.upload.maxSupportFiles, // 5 файлов
    fieldSize: 10 * 1024 * 1024
  },
  fileFilter: supportFileFilter,
  onError: (err, next) => {
    logger.error('Support file upload error', { error: err.message, code: err.code });
    next(err);
  }
});

// Database helpers - unified interface for all database types
async function run(sql, params = []) {
  return dbManager.run(sql, params);
}

async function get(sql, params = []) {
  return dbManager.get(sql, params);
}

async function all(sql, params = []) {
  return dbManager.all(sql, params);
}

// Кэш для системных настроек
let settingsCache = {};
let settingsCacheTime = 0;
const SETTINGS_CACHE_TTL = 60000; // 1 минута

// Функция получения системных настроек с кэшированием
async function getSystemSettings() {
  const now = Date.now();

  // Проверяем кэш
  if (settingsCacheTime && now - settingsCacheTime < SETTINGS_CACHE_TTL) {
    return settingsCache;
  }

  try {
    // Получаем все системные настройки из БД
    const settings = await all(`
      SELECT key, value FROM system_settings 
      WHERE key IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      'publish_fee', 'default_task_amount', 'chat_poll_interval', 'notification_duration', 'api_timeout',
      'max_description_length', 'min_title_length', 'tasks_per_page', 'chat_auto_refresh', 'scroll_to_top_threshold',
      'theme_toggle_enabled'
    ]);

    // Преобразуем в объект с дефолтными значениями
    const result = {
      publish_fee: 20,
      default_task_amount: 100,
      chat_poll_interval: 3000,
      notification_duration: 4000,
      api_timeout: 15000,
      max_description_length: 1000,
      min_title_length: 3,
      tasks_per_page: 10,
      chat_auto_refresh: false,
      scroll_to_top_threshold: 1000,
      theme_toggle_enabled: false
    };

    // Применяем значения из БД
    settings.forEach(setting => {
      try {
        // Пытаемся распарсить JSON, если не получается - используем как есть
        let parsedValue;
        try {
          parsedValue = JSON.parse(setting.value);
        } catch {
          parsedValue = setting.value;
        }

        if (setting.key === 'chat_auto_refresh' || setting.key === 'theme_toggle_enabled') {
          result[setting.key] = parsedValue === true || parsedValue === 'true';
        } else {
          const numValue = typeof parsedValue === 'number' ? parsedValue : parseInt(parsedValue);
          result[setting.key] = isNaN(numValue) ? result[setting.key] : numValue;
        }
      } catch (error) {
        logger.warn(`Error parsing setting ${setting.key}:`, { error: error.message, value: setting.value });
      }
    });

    // Обновляем кэш
    settingsCache = result;
    settingsCacheTime = now;

    return result;
  } catch (error) {
    logger.error('Failed to get system settings', { error: error.message, stack: error.stack });
    // Возвращаем дефолтные значения в случае ошибки
    return settingsCache.publish_fee ? settingsCache : {
      publish_fee: 20,
      default_task_amount: 100,
      chat_poll_interval: 3000,
      notification_duration: 4000,
      api_timeout: 15000,
      max_description_length: 1000,
      min_title_length: 3,
      tasks_per_page: 10,
      chat_auto_refresh: false,
      scroll_to_top_threshold: 1000,
      theme_toggle_enabled: false
    };
  }
}

// Функция для сброса кэша настроек (вызывается при изменении настроек)
function resetSettingsCache() {
  settingsCacheTime = 0;
  settingsCache = {};
}

// Экспортируем функцию глобально для использования в роутах
global.resetSettingsCache = resetSettingsCache;
global.clearStopWordsCache = clearStopWordsCache;

function nowIso() { return DateUtils.now(); }

// Хеширование паролей с bcrypt
async function _hashPassword(password) {
  return CryptoUtils.hashPassword(password);
}

async function _verifyPassword(password, hash) {
  return CryptoUtils.verifyPassword(password, hash);
}

// Генерация ID
function generateId() {
  return uuidv4();
}

// Логирование действий администратора
async function _logAdminAction(adminId, adminEmail, action, targetType, targetId, oldValues, newValues, ipAddress, userAgent) {
  try {
    const logId = generateId();
    await run(`
      INSERT INTO admin_logs (id, admin_id, admin_email, action, target_type, target_id, old_values, new_values, ip_address, user_agent, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      logId, adminId, adminEmail, action, targetType, targetId,
      oldValues ? JSON.stringify(oldValues) : null,
      newValues ? JSON.stringify(newValues) : null,
      ipAddress, userAgent, DateUtils.now()
    ]);
  } catch (error) {
    logger.error('Failed to log admin action', { error: error.message, stack: error.stack });
  }
}

// Генерация CSV
function _generateCSV(data, columns) {
  const headers = columns.map(col => `"${col.header}"`).join(',');
  const rows = data.map(row => {
    return columns.map(col => {
      let value = row[col.key];
      if (value === null || value === undefined) {
        value = '';
      }
      // Экранируем кавычки и переносы строк
      value = String(value).replace(/"/g, '""');
      return `"${value}"`;
    }).join(',');
  });

  return [headers, ...rows].join('\n');
}

// Кэш стоп-слов
let stopWordsCache = null;
let stopWordsCacheExpiry = 0;
const STOP_WORDS_CACHE_TTL = 5 * 60 * 1000; // 5 минут
const MAX_STOP_WORDS_CACHE_SIZE = 10000; // Максимальное количество стоп-слов в кэше

// Проверка на стоп-слова
async function checkStopWords(text) {
  try {
    // Кэшируем стоп-слова для уменьшения обращений к БД
    const now = Date.now();
    if (!stopWordsCache || now > stopWordsCacheExpiry) {
      const stopWordsData = await all('SELECT word, category, severity FROM stop_words');

      // Предварительно обрабатываем данные для быстрого поиска
      stopWordsCache = {
        patterns: [],
        map: new Map()
      };

      // Ограничиваем количество стоп-слов для предотвращения memory leak
      const limitedStopWords = stopWordsData.slice(0, MAX_STOP_WORDS_CACHE_SIZE);
      if (stopWordsData.length > MAX_STOP_WORDS_CACHE_SIZE) {
        logger.warn(`Stop words cache size limited to ${MAX_STOP_WORDS_CACHE_SIZE} entries, ${stopWordsData.length - MAX_STOP_WORDS_CACHE_SIZE} entries skipped`);
      }

      for (const stopWord of limitedStopWords) {
        const cleanWord = stopWord.word.replace(/\*/g, '').toLowerCase();
        if (cleanWord.length > 0) {
          stopWordsCache.patterns.push({
            word: cleanWord,
            original: stopWord.word,
            category: stopWord.category,
            severity: stopWord.severity
          });
          stopWordsCache.map.set(cleanWord, stopWord);
        }
      }

      stopWordsCacheExpiry = now + STOP_WORDS_CACHE_TTL;
    }

    const violations = [];
    if (!text) return violations;

    const textLower = text.toLowerCase();

    // Объяснения для разных категорий стоп-слов
    const explanations = {
      illegal_substances: 'Запрещена торговля наркотическими веществами',
      weapons: 'Запрещена торговля оружием',
      adult_content: 'Запрещен контент для взрослых',
      gambling: 'Запрещена азартная деятельность',
      fraud: 'Запрещена мошенническая деятельность',
      suspicious_pricing: 'Избегайте подозрительно низких цен',
      spam_indicators: 'Избегайте спамовых фраз',
      inappropriate_language: 'Используйте вежливые выражения',
      default: 'Данный контент может нарушать правила платформы'
    };

    // Предложения для улучшения контента
    const suggestions = {
      illegal_substances: 'Предлагайте только законные товары и услуги',
      weapons: 'Предлагайте только безопасные и законные предметы',
      adult_content: 'Создавайте семейно-ориентированный контент',
      gambling: 'Предлагайте честные услуги без элементов азарта',
      fraud: 'Будьте честными и прозрачными в своих предложениях',
      suspicious_pricing: 'Указывайте реальные и справедливые цены',
      spam_indicators: 'Используйте естественные и информативные формулировки',
      inappropriate_language: 'Формулируйте предложения вежливо и профессионально',
      default: 'Перефразируйте контент согласно правилам платформы'
    };

    // Оптимизированная проверка с early exit и определением позиции
    const foundWords = new Set(); // Избегаем дублирования одинаковых слов
    for (const pattern of stopWordsCache.patterns) {
      const index = textLower.indexOf(pattern.word);
      if (index !== -1 && !foundWords.has(pattern.word)) {
        foundWords.add(pattern.word);
        violations.push({
          word: pattern.original,
          category: pattern.category,
          severity: pattern.severity,
          position: index,
          explanation: explanations[pattern.category] || explanations.default,
          suggestion: suggestions[pattern.category] || suggestions.default
        });
      }
    }

    return violations;
  } catch (error) {
    logger.error('Failed to check stop words', { error: error.message, stack: error.stack });
    return [];
  }
}

// Функция для принудительной очистки кэша стоп-слов
function clearStopWordsCache() {
  stopWordsCache = null;
  stopWordsCacheExpiry = 0;
  logger.info('Stop words cache cleared manually');
}

// Database schema initialization using DatabaseManager
async function ensureSchema() {
  await dbManager.ensureSchema();
}

// Вспомогательная функция для проверки токена (устраняет дублирование кода)
async function validateSessionToken(sessionToken) {
  if (!sessionToken) {
    return { isValid: false, reason: 'no_token' };
  }

  try {
    // Валидация base64 формата перед декодированием
    if (!sessionToken.match(/^[A-Za-z0-9+/]*={0,2}$/)) {
      return { isValid: false, reason: 'invalid_base64_format' };
    }

    const decoded = Buffer.from(sessionToken, 'base64').toString('utf8');

    // Проверяем что результат содержит только ASCII символы
    if (!decoded.match(/^[\x20-\x7E]+$/)) {
      return { isValid: false, reason: 'invalid_decoded_content' };
    }

    const parts = decoded.split(':');
    if (parts.length !== 2) {
      return { isValid: false, reason: 'invalid_token_structure' };
    }

    const [userId, token] = parts;
    if (!userId || !token) {
      return { isValid: false, reason: 'missing_token_parts' };
    }

    const user = await dbManager.get(`SELECT * FROM users WHERE id = ? AND token = ?`, [userId, token]);
    if (!user) {
      return { isValid: false, reason: 'user_not_found' };
    }

    return {
      isValid: true,
      user,
      userId: user.id,
      isAdmin: user.is_admin
    };
  } catch (e) {
    return { isValid: false, reason: 'token_decode_error', error: e.message };
  }
}

// auth middleware для cookies
async function authMiddleware(req, res, next) {
  const sessionToken = req.cookies && req.cookies.sessionToken;

  const validation = await validateSessionToken(sessionToken);

  if (!validation.isValid) {
    logger.debug('Auth middleware: Token validation failed', {
      path: req.path,
      reason: validation.reason,
      cookies: Object.keys(req.cookies || {}),
      userAgent: req.get('User-Agent')?.substring(0, 100)
    });
    return sendError.unauthorized(res, { reason: validation.reason });
  }

  // Проверяем, заблокирован ли пользователь
  if (validation.user.is_blocked) {
    return sendError.forbidden(res, {
      message: 'Аккаунт заблокирован',
      blocked: true,
      reason: validation.user.blocked_reason || 'Причина не указана',
      blocked_at: validation.user.blocked_at
    });
  }

  try {
    // Update last_online
    await dbManager.run(`UPDATE users SET last_online = ? WHERE id = ?`, [nowIso(), validation.userId]);
    req.user = validation.user;

    logger.debug('Auth middleware: User authenticated successfully', {
      path: req.path,
      userId: validation.user.id,
      email: validation.user.email,
      userAgent: req.get('User-Agent')?.substring(0, 100)
    });

    next();
  } catch (err) {
    logger.error('Auth middleware error', { error: err.message, stack: err.stack });
    sendError.serverError(res);
  }
}


const CITIES = ['Абакан', 'Азов', 'Александров', 'Алексин', 'Альметьевск', 'Анапа', 'Ангарск', 'Анжеро-Судженск', 'Апатиты', 'Арзамас', 'Армавир', 'Арсеньев', 'Артем', 'Архангельск', 'Асбест', 'Астрахань', 'Ачинск', 'Балаково', 'Балахна', 'Балашиха', 'Балашов', 'Барнаул', 'Батайск', 'Белгород', 'Белебей', 'Белово', 'Белогорск', 'Белорецк', 'Белореченск', 'Бердск', 'Березники', 'Березовский', 'Бийск', 'Биробиджан', 'Благовещенск', 'Бор', 'Борисоглебск', 'Боровичи', 'Братск', 'Брянск', 'Бугульма', 'Буденновск', 'Бузулук', 'Буйнакск', 'Великие Луки', 'Великий Новгород', 'Верхняя Пышма', 'Видное', 'Владивосток', 'Владикавказ', 'Владимир', 'Волгоград', 'Волгодонск', 'Волжский', 'Вологда', 'Вольск', 'Воркута', 'Воронеж', 'Воскресенск', 'Воткинск', 'Всеволожск', 'Выборг', 'Выкса', 'Вязьма', 'Гатчина', 'Геленджик', 'Георгиевск', 'Глазов', 'Горно-Алтайск', 'Грозный', 'Губкин', 'Гудермес', 'Гуково', 'Гусь-Хрустальный', 'Дербент', 'Дзержинск', 'Димитровград', 'Дмитров', 'Долгопрудный', 'Домодедово', 'Донской', 'Дубна', 'Евпатория', 'Егорьевск', 'Ейск', 'Екатеринбург', 'Елабуга', 'Елец', 'Ессентуки', 'Железногорск', 'Жигулевск', 'Жуковский', 'Заречный', 'Зеленогорск', 'Зеленодольск', 'Златоуст', 'Иваново', 'Ивантеевка', 'Ижевск', 'Избербаш', 'Иркутск', 'Искитим', 'Ишим', 'Ишимбай', 'Йошкар-Ола', 'Казань', 'Калининград', 'Калуга', 'Каменск-Уральский', 'Каменск-Шахтинский', 'Камышин', 'Канск', 'Каспийск', 'Кемерово', 'Керчь', 'Кинешма', 'Кириши', 'Киров', 'Кирово-Чепецк', 'Киселевск', 'Кисловодск', 'Клин', 'Клинцы', 'Ковров', 'Когалым', 'Коломна', 'Комсомольск-на-Амуре', 'Копейск', 'Королев', 'Кострома', 'Котлас', 'Красногорск', 'Краснодар', 'Краснокаменск', 'Краснокамск', 'Краснотурьинск', 'Красноярск', 'Кропоткин', 'Крымск', 'Кстово', 'Кузнецк', 'Кумертау', 'Кунгур', 'Курган', 'Курск', 'Кызыл', 'Лабинск', 'Лениногорск', 'Ленинск-Кузнецкий', 'Лесосибирск', 'Липецк', 'Лиски', 'Лобня', 'Лысьва', 'Лыткарино', 'Люберцы', 'Магадан', 'Магнитогорск', 'Майкоп', 'Махачкала', 'Междуреченск', 'Мелеуз', 'Миасс', 'Минеральные Воды', 'Минусинск', 'Михайловск', 'Мичуринск', 'Москва', 'Мурманск', 'Муром', 'Мытищи', 'Набережные Челны', 'Назрань', 'Нальчик', 'Наро-Фоминск', 'Находка', 'Невинномысск', 'Нерюнгри', 'Нефтекамск', 'Нефтеюганск', 'Нижневартовск', 'Нижнекамск', 'Нижний Новгород', 'Нижний Тагил', 'Новоалтайск', 'Новокузнецк', 'Новокуйбышевск', 'Новомосковск', 'Новороссийск', 'Новосибирск', 'Новотроицк', 'Новоуральск', 'Новочебоксарск', 'Новочеркасск', 'Новошахтинск', 'Новый Уренгой', 'Ногинск', 'Норильск', 'Ноябрьск', 'Нягань', 'Обнинск', 'Одинцово', 'Озерск', 'Октябрьский', 'Омск', 'Орел', 'Оренбург', 'Орехово-Зуево', 'Орск', 'Павлово', 'Павловский Посад', 'Пенза', 'Первоуральск', 'Пермь', 'Петрозаводск', 'Петропавловск-Камчатский', 'Подольск', 'Полевской', 'Прокопьевск', 'Прохладный', 'Псков', 'Пушкино', 'Пятигорск', 'Раменское', 'Ревда', 'Реутов', 'Ржев', 'Рославль', 'Ростов-на-Дону', 'Рубцовск', 'Рыбинск', 'Рязань', 'Салават', 'Сальск', 'Самара', 'Санкт-Петербург', 'Саранск', 'Сарапул', 'Саратов', 'Саров', 'Севастополь', 'Северодвинск', 'Северск', 'Сергиев Посад', 'Серпухов', 'Сертолово', 'Сибай', 'Симферополь', 'Славянск-на-Кубани', 'Смоленск', 'Соликамск', 'Солнечногорск', 'Сосновый Бор', 'Сочи', 'Ставрополь', 'Старый Оскол', 'Стерлитамак', 'Ступино', 'Сургут', 'Сызрань', 'Сыктывкар', 'Таганрог', 'Тамбов', 'Тверь', 'Тимашёвск', 'Тобольск', 'Тольятти', 'Томск', 'Троицк', 'Туапсе', 'Тула', 'Тюмень', 'Узловая', 'Улан-Удэ', 'Ульяновск', 'Урус-Мартан', 'Усолье-Сибирское', 'Уссурийск', 'Усть-Илимск', 'Уфа', 'Ухта', 'Феодосия', 'Фрязино', 'Хабаровск', 'Ханты-Мансийск', 'Хасавюрт', 'Химки', 'Чайковский', 'Чапаевск', 'Чебоксары', 'Челябинск', 'Черемхово', 'Череповец', 'Черкесск', 'Черногорск', 'Чехов', 'Чистополь', 'Чита', 'Шадринск', 'Шали', 'Шахты', 'Шuya', 'Щекино', 'Щёлково', 'Электросталь', 'Элиста', 'Энгельс', 'Южно-Сахалинск', 'Юрга', 'Якутск', 'Ялта', 'Ярославль'].sort((a, b) => a.localeCompare(b, 'ru'));

// Валидация helpers
const _sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return input.trim().replace(/[<>]/g, '');
};

// Admin middleware
async function adminMiddleware(req, res, next) {
  try {
    // Сначала проверяем авторизацию
    await new Promise((resolve, reject) => {
      authMiddleware(req, res, (err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    // Проверяем админские права
    if (!req.user || !req.user.is_admin) {
      // Если это запрос HTML файла, перенаправляем авторизованных пользователей в /app/
      if (req.path.endsWith('.html') || req.accepts('html')) {
        // Если пользователь авторизован, но не админ - перенаправляем в /app/
        if (req.user) {
          return res.redirect('/app/');
        }
        // Если не авторизован - на главную
        return res.redirect('/');
      }
      // Для API запросов возвращаем JSON ошибку
      return sendError.forbidden(res, { message: 'Доступ запрещен' });
    }

    // Добавляем информацию об админе в request для логирования
    req.adminId = req.user.id;
    req.adminEmail = req.user.email;

    next();
  } catch (error) {
    // Если authMiddleware уже отправил ответ, не отправляем еще один
    if (res.headersSent) return;
    // Если это запрос HTML файла, перенаправляем
    if (req.path.endsWith('.html') || req.accepts('html')) {
      // Если пользователь авторизован, но не админ - перенаправляем в /app/
      if (req.user) {
        return res.redirect('/app/');
      }
      // Если не авторизован - на главную
      return res.redirect('/');
    }
    // Для API запросов возвращаем JSON ошибку
    return sendError.unauthorized(res, { message: 'Нет доступа' });
  }
}

async function main() {
  const app = express();

  // Настройка доверия прокси для корректной работы за Nginx
  app.set('trust proxy', 1);

  // Подключение к базе данных через DatabaseManager
  await dbManager.connect();
  await ensureSchema();

  // Инициализация HealthChecker и MetricsCollector
  const logger = getLogger();
  const healthChecker = new HealthChecker(dbManager, logger);
  const metricsCollector = new MetricsCollector();

  // Делаем их доступными для роутов
  app.locals.healthChecker = healthChecker;
  app.locals.metricsCollector = metricsCollector;
  global.healthChecker = healthChecker;
  global.metricsCollector = metricsCollector;

  // Запускаем системный мониторинг для алертов (только в production)
  if (isProduction) {
    alertManager.startSystemMonitoring();
    logger.info('Alert system initialized for production');
  }

  // --- MANDATORY MIDDLEWARES (order matters) ---
  // Performance monitoring (должно быть первым для точного измерения)
  app.use(monitor.requestTimer());

  // Compression (должно быть рано в цепочке middleware)
  app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    }
  }));

  // Parse JSON / form bodies (нужно для express-validator и req.body)
  app.use(express.json({ limit: '10mb' }));

  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Parse cookies (ВАЖНО: должно быть до middleware, которое читает req.cookies)
  app.use(cookieParser());

  // Отладочный middleware для cookies (только в development)
  if (!isProduction) {
    app.use((req, res, next) => {
      if (req.path.startsWith('/api/')) {
        logger.debug(`${req.method} ${req.path}`, {
          cookies: req.cookies,
          userAgent: req.get('User-Agent'),
          origin: req.get('Origin'),
          referer: req.get('Referer'),
          sessionToken: req.cookies?.sessionToken ? `${req.cookies.sessionToken.substring(0, 8)}...` : 'none'
        });
      }
      next();
    });
  }

  // CORS настройки для лучшей совместимости с Safari
  app.use((req, res, next) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') ||
      (config.server.environment === 'production' ? ['https://workado.ru'] : ['http://localhost:3000', 'http://127.0.0.1:3000']);

    const origin = req.get('Origin');
    const allowedOrigin = allowedOrigins.includes(origin) ? origin : (config.server.environment === 'production' ? allowedOrigins[0] : origin);

    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Origin', allowedOrigin || allowedOrigins[0]);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cookie');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // Session middleware для Passport
  app.use(session({
    secret: config.security.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
      sameSite: 'lax',
      domain: isProduction ? '.workado.ru' : undefined
    }
  }));

  // Passport middleware
  app.use(googleAuth.initialize());
  app.use(googleAuth.session());
  
  // ----------------------------------------------

  // Security middleware - улучшенный для production
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ['\'self\''],
        styleSrc: ['\'self\'', '\'unsafe-inline\'', 'https://api.yookassa.ru', 'https://checkout.yookassa.ru'],
        scriptSrc: ['\'self\'', '\'unsafe-inline\'', 'https://api.yookassa.ru', 'https://checkout.yookassa.ru', 'https://accounts.google.com', 'https://*.googleapis.com', 'https://mc.yandex.ru', 'https://*.yandex.ru', 'https://mc.yandex.com', 'https://*.yandex.com'],
        scriptSrcAttr: ['\'unsafe-inline\''], // Разрешаем inline event handlers для админ-панели
        imgSrc: ['\'self\'', 'data:', 'https:'],
        connectSrc: ['\'self\'', 'https://api.yookassa.ru', 'https://checkout.yookassa.ru', 'https://accounts.google.com', 'https://*.googleapis.com', 'https://mc.yandex.ru', 'https://*.yandex.ru', 'https://mc.yandex.com', 'https://*.yandex.com'],
        fontSrc: ['\'self\''],
        objectSrc: ['\'none\''],
        mediaSrc: ['\'self\''],
        frameSrc: ['\'self\'', 'https://api.yookassa.ru', 'https://checkout.yookassa.ru', 'https://accounts.google.com', 'https://mc.yandex.ru', 'https://*.yandex.ru', 'https://mc.yandex.com', 'https://*.yandex.com'],
        formAction: ['\'self\'', 'https://api.yookassa.ru', 'https://checkout.yookassa.ru', 'https://accounts.google.com'],
        upgradeInsecureRequests: null
      }
    },
    hsts: isProduction ? {
      maxAge: 31536000, // 1 год
      includeSubDomains: true,
      preload: true
    } : false,
    noSniff: true,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  }));

  // Глобальные security middleware
  app.use(validationMiddleware.validateClientIP());

  app.use(validationMiddleware.validateSecurityHeaders());

  app.use(validationMiddleware.validateBodySize(5 * 1024 * 1024)); // 5MB max

  // Дополнительные security headers
  app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Workado');
    res.setHeader('Server', 'Workado/1.0');
    if (isProduction) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
  });

  // Middleware для проверки авторизации и редиректов
  app.use(async(req, res, next) => {
    try {
      // Статические файлы и API пропускаем
      if (req.path.startsWith('/api/') || req.path.startsWith('/avatars/') || req.path.startsWith('/uploads/') ||
          req.path.startsWith('/admin/') && req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i) ||
          req.path.endsWith('.css') || req.path.endsWith('.js') || req.path === '/favicon.ico' ||
          req.path.startsWith('/app/') && req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i)) {
        return next();
      }

      // Проверяем авторизацию через cookie
      const sessionToken = req.cookies && req.cookies.sessionToken;
      const validation = await validateSessionToken(sessionToken);
      const isAuthenticated = validation.isValid;

      // Редиректы на основе авторизации
      if (req.path === '/' && isAuthenticated) {
        return res.redirect('/app/');
      } else if (req.path.startsWith('/app') && !isAuthenticated) {
        return res.redirect('/');
      }

      next();
    } catch (err) {
      // Не даём падать серверу из-за ошибок в редирект-мидлваре
      logger.error('redirect middleware error', { error: err.message, stack: err.stack });
      next();
    }
  });

  // Middleware для проверки режима обслуживания (ДОЛЖЕН БЫТЬ ПОСЛЕ РЕДИРЕКТОВ!)
  app.use(async(req, res, next) => {
    try {
      // Пропускаем админку и админские API
      if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin')) {
        return next();
      }

      // Пропускаем API endpoint для загрузки сообщения техобслуживания
      if (req.path === '/api/maintenance/message') {
        return next();
      }

      // Пропускаем API авторизации - даже в режиме техобслуживания нужно позволить логин/регистрацию
      if (req.path.startsWith('/api/auth/') || req.path.startsWith('/auth/')) {
        return next();
      }

      // Пропускаем статические файлы (favicon, avatars, etc.)
      if (req.path.match(/\.(ico|jpg|jpeg|png|gif|svg|css|js|woff|woff2|ttf|eot)$/i)) {
        return next();
      }

      // Проверяем режим обслуживания
      const maintenanceMode = await get('SELECT value FROM system_settings WHERE key = ?', ['maintenance_mode']);

      let isMaintenanceEnabled = false;
      if (maintenanceMode && maintenanceMode.value) {
        try {
          const parsed = JSON.parse(maintenanceMode.value);
          isMaintenanceEnabled = parsed.enabled === true;
        } catch (e) {
          // Fallback для старого формата
          isMaintenanceEnabled = maintenanceMode.value === 'true';
        }
      }

      if (isMaintenanceEnabled) {
        // Проверяем, является ли пользователь администратором
        const sessionToken = req.cookies.sessionToken;
        const validation = await validateSessionToken(sessionToken);
        const isAdmin = validation.isValid && validation.isAdmin;

        // Если не админ, показываем страницу обслуживания
        if (!isAdmin) {
          return res.status(503).sendFile(path.join(PUBLIC_DIR, 'maintenance.html'));
        }
      }

      next();
    } catch (error) {
      logger.error('Maintenance mode check error:', { error: error.message, stack: error.stack });
      next();
    }
  });

  // Дополнительное логирование перед rate limiter
  app.use('/api/admin', (req, res, next) => {
    next();
  });

  // Apply rate limiting
  app.use('/api/', apiLimiter);

  // ИСПРАВЛЕНО: Стандартизированная инициализация зависимостей
  // Создаем единый объект зависимостей для всех роутеров
  const commonDependencies = {
    // Основные зависимости
    dbManager,
    logger: getLogger(),
    alertManager: getAlertManager(),
    healthChecker,

    // Middleware аутентификации
    authMiddleware,
    adminMiddleware,
    requireEmailVerification,

    // Rate limiting
    rateLimit: {
      loginLimiter,
      apiLimiter,
      uploadLimiter,
      passwordResetLimiter
    },

    // Специальные зависимости
    emailService,
    googleAuth,
    checkStopWords,

    // Кэширование
    cacheMiddleware,
    globalCache,

    // Загрузка файлов
    storage,
    fileFilter,
    supportUpload,
    postUploadValidation // Middleware для постпроверки файлов
  };

  // Инициализируем все роутеры с единым интерфейсом
  try {
    initAuthDependencies(commonDependencies);
    initAuthPagesDependencies(commonDependencies);
    initTasksDependencies(commonDependencies);
    initUsersDependencies(commonDependencies);
    initPaymentsDependencies(commonDependencies);
    initPaymentCallbacksDependencies(commonDependencies);
    initAdminDependencies(commonDependencies);
    initSupportDependencies(commonDependencies);
    initMonitoringDependencies(commonDependencies);
    // initCitiesDependencies(commonDependencies);

    logger.info('All route dependencies initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize route dependencies', {
      error: error.message,
      stack: error.stack
    });
    throw error;
  }

  // API версионирование middleware
  // Legacy redirect middleware removed
  // API versioning middleware removed

  // API versions endpoint removed

  // Основные API маршруты

  // Основные API маршруты
  app.use('/api/auth', authRouter);
  app.use('/api/tasks', tasksRouter);
  app.use('/api/users', usersRouter);
  app.use('/api/payments', paymentsRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api/support', supportRouter);
  // app.use('/api/cities', citiesRouter);
  app.use('/', monitoringRouter); // Мониторинг для API endpoints

  // Маршруты страниц авторизации (не API, без версионирования)
  app.use('/auth', authPagesRouter);
  app.use('/', authPagesRouter); // для /verify-email и /reset-password

  // Статические страницы (не API, без версионирования)
  app.use('/', staticPagesRouter);

  // Payment callbacks (не API, без версионирования)
  app.use('/topup', paymentCallbacksRouter);
  app.use('/api/payment', paymentCallbacksRouter);

  // Cities endpoint - кэш на 1 час
  app.get('/api/cities', cacheMiddleware.cacheMiddleware(3600), (req, res) => {
    res.json(CITIES);
  });

  // Кэшируем данные городов в памяти
  let cachedCitiesData = null;

  function loadCitiesData() {
    if (!cachedCitiesData) {
      try {
        const fs = require('fs');
        cachedCitiesData = JSON.parse(fs.readFileSync(path.join(__dirname, 'public/data/russia-cities.json'), 'utf8'));
        logger.info(`Загружено ${cachedCitiesData.length} городов России`);
      } catch (error) {
        logger.error('Ошибка загрузки данных городов:', error);
        cachedCitiesData = [];
      }
    }
    return cachedCitiesData;
  }

  // Функция для сброса кэша городов (для разработки)
  function reloadCitiesData() {
    cachedCitiesData = null;
    return loadCitiesData();
  }

  // Cities search API - поиск из JSON файла с кэшированием
  app.get('/api/cities/search', cacheMiddleware.cacheMiddleware(300), async (req, res) => {
    const { q, limit = 10 } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Параметр q обязателен' });
    }

    try {
      const searchTerm = q.toLowerCase();
      const searchLimit = Math.min(Math.max(1, parseInt(limit) || 10), 50);

      // Получаем кэшированные данные городов
      const citiesData = loadCitiesData();

      if (!citiesData || citiesData.length === 0) {
        return res.status(500).json({ error: 'Данные городов не загружены' });
      }

      // Фильтруем города по запросу (ищем по названию города и региону)
      const filteredCities = citiesData
        .filter(city => {
          const cityName = city.name.toLowerCase();
          const regionName = city.region.name.toLowerCase();
          return cityName.includes(searchTerm) || regionName.includes(searchTerm);
        })
        .sort((a, b) => {
          // Сортируем по релевантности: сначала точные совпадения в начале названия
          const aStartsWith = a.name.toLowerCase().startsWith(searchTerm);
          const bStartsWith = b.name.toLowerCase().startsWith(searchTerm);
          if (aStartsWith && !bStartsWith) return -1;
          if (!aStartsWith && bStartsWith) return 1;
          // Затем по населению (больше = выше)
          return (b.population || 0) - (a.population || 0);
        })
        .slice(0, searchLimit)
        .map(city => ({
          name: city.name,
          region: `${city.region.name} ${city.region.type}`,
          population: city.population || 0,
          fullName: `${city.name}, ${city.region.name} ${city.region.type}`
        }));

      res.json({
        query: q,
        results: filteredCities,
        total: citiesData.length
      });

    } catch (error) {
      logger.error('Cities search error:', error);
      res.status(500).json({ error: 'Ошибка поиска городов' });
    }
  });



  // System settings endpoint - кэш на 5 минут
  app.get('/api/settings', cacheMiddleware.cacheMiddleware(300), async(req, res) => {
    try {
      const systemSettings = await getSystemSettings();
      // Возвращаем только публичные настройки, которые нужны фронтенду
      res.json({
        publish_fee: systemSettings.publish_fee,
        max_description_length: systemSettings.max_description_length,
        min_title_length: systemSettings.min_title_length,
        chat_poll_interval: systemSettings.chat_poll_interval,
        notification_duration: systemSettings.notification_duration,
        default_task_amount: systemSettings.default_task_amount,
        tasks_per_page: systemSettings.tasks_per_page,
        chat_auto_refresh: systemSettings.chat_auto_refresh,
        scroll_to_top_threshold: systemSettings.scroll_to_top_threshold,
        theme_toggle_enabled: systemSettings.theme_toggle_enabled,
        maintenance_mode: systemSettings.maintenance_mode
      });
    } catch (error) {
      logger.error('Error fetching public settings:', { error: error.message, stack: error.stack });
      sendError.serverError(res, { message: 'Ошибка получения настроек' });
    }
  });


  // Maintenance message endpoint
  app.get('/api/maintenance/message', async(req, res) => {
    try {
      const maintenanceMode = await get('SELECT value FROM system_settings WHERE key = ?', ['maintenance_mode']);

      let message = 'На сайте проводятся технические работы. Пожалуйста, зайдите позже.';

      if (maintenanceMode && maintenanceMode.value) {
        try {
          const parsed = JSON.parse(maintenanceMode.value);
          if (parsed.message) {
            message = parsed.message;
          }
        } catch (e) {
          // Игнорируем ошибки парсинга JSON
        }
      }

      res.json({ message });
    } catch (error) {
      logger.error('Error fetching maintenance message:', { error: error.message, stack: error.stack });
      res.json({ message: 'На сайте проводятся технические работы. Пожалуйста, зайдите позже.' });
    }
  });

  // users router already added above

  // Редиректы убраны - все маршруты теперь прямые

  app.get('/api/:userId', (req, res, next) => {
    // Только если это похоже на userId (не api путь)
    if (req.params.userId && req.params.userId.length > 10 && !req.params.userId.includes('-')) {
      return next(); // Пропускаем, не userId
    }
    res.redirect(`/api/users/${req.params.userId}`);
  });


  // Static files optimization middleware
  app.use(createStaticOptimization());

  // Static files - с исключением для корневого пути
  app.use((req, res, next) => {
    // Пропускаем статический middleware для корневого пути
    // чтобы сработал middleware редиректа для авторизованных пользователей
    if (req.path === '/') {
      return next();
    }

    express.static(PUBLIC_DIR, {
      etag: true,
      lastModified: true,
      setHeaders: (res, path) => {
        // Записываем статистику запросов
        staticStats.recordRequest(path);
      }
    })(req, res, next);
  });


  // Serve app from /app directory with selective authentication
  app.use('/app', (req, res, next) => {
    // Для CSS, JS и других статических файлов пропускаем аутентификацию
    if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i)) {
      return express.static(path.join(__dirname, 'public/app'), {
        etag: true,
        lastModified: true,
        setHeaders: (res, path) => {
          staticStats.recordRequest(path);
        }
      })(req, res, next);
    }
    // Для HTML файлов и других запросов требуем авторизацию
    authMiddleware(req, res, () => {
      express.static(path.join(__dirname, 'public/app'), {
        etag: true,
        lastModified: true,
        setHeaders: (res, path) => {
          staticStats.recordRequest(path);
        }
      })(req, res, next);
    });
  });

  // Serve admin panel from /admin directory - проверяем права только для HTML файлов
  app.use('/admin', (req, res, next) => {
    // Для CSS и JS файлов пропускаем без проверки
    if (req.path.match(/\.(css|js)$/i)) {
      return express.static(path.join(PUBLIC_DIR, 'admin'), {
        etag: true,
        lastModified: true,
        setHeaders: (res, path) => {
          staticStats.recordRequest(path);
        }
      })(req, res, next);
    }
    // Для HTML файлов требуем авторизацию
    adminMiddleware(req, res, () => {
      express.static(path.join(PUBLIC_DIR, 'admin'), {
        etag: true,
        lastModified: true
      })(req, res, next);
    });
  });

  // Static uploads directory
  app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads'), {
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
      staticStats.recordRequest(path);
    }
  }));

  // Главная страница - отдаем index.html только неавторизованным пользователям
  app.get('/', (req, res) => {
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }
    res.status(404).send('Главная страница не найдена');
  });

  // Static avatars directory
  app.use('/avatars', express.static(AVATARS_DIR, {
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
      staticStats.recordRequest(path);
    }
  }));

  app.post('/', (req, res) => {
    return res.redirect('/');
  });

  app.get('/favicon.ico', (req, res) => {
    const f = path.join(PUBLIC_DIR, 'favicon.ico');
    if (fs.existsSync(f)) return res.sendFile(f);
    return res.status(204).end();
  });

  // Test button page
  app.get('/test-button', (req, res) => {
    const f = path.join(__dirname, 'test-button.html');
    if (fs.existsSync(f)) return res.sendFile(f);
    res.status(404).send('Test page not found');
  });

  // Google OAuth routes
  app.get('/auth/google', (req, res, next) => {
    logger.info('Google OAuth route hit');
    try {
      return googleAuth.authenticate()(req, res, next);
    } catch (error) {
      logger.error('Google OAuth authenticate error:', error);
      res.status(500).send('Google OAuth error: ' + error.message);
    }
  });

  // Google OAuth callback
  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/?error=google_auth_failed' }),
    async(req, res) => {
      try {
        logger.info('Google OAuth callback hit', { user: req.user ? req.user.id : 'no user' });

        // Устанавливаем cookie для пользователя после успешной аутентификации
        if (req.user && req.user.token) {
          const sessionToken = Buffer.from(`${req.user.id}:${req.user.token}`).toString('base64');
          res.cookie('sessionToken', sessionToken, getCookieOptions(req));
          logger.info('Google OAuth successful - cookie set', {
            userId: req.user.id,
            email: req.user.email,
            tokenPreview: req.user.token ? req.user.token.substring(0, 10) + '...' : 'no token'
          });
          res.redirect('/?google_auth=success');
        } else {
          logger.error('Google OAuth callback: No user or token', { user: req.user });
          res.redirect('/?error=google_auth_no_user');
        }
      } catch (error) {
        logger.error('Google OAuth callback error:', error);
        res.redirect('/?error=google_auth_error');
      }
    }
  );

  // Google OAuth тест (только в development)
  if (!isProduction) {
    app.get('/test-google-oauth', (req, res) => {
      const f = path.join(__dirname, 'test-google-oauth.html');
      if (fs.existsSync(f)) return res.sendFile(f);
      return res.status(404).send('Test file not found');
    });

    // Тестовый роут для проверки авторизации
    app.get('/debug-auth', async(req, res) => {
      try {
        const sessionToken = req.cookies.sessionToken;
        let authInfo = { loggedIn: false };

        if (sessionToken) {
          const validation = await validateSessionToken(sessionToken);
          if (validation.isValid) {
            authInfo = {
              loggedIn: true,
              user: {
                id: validation.user.id,
                name: validation.user.name,
                email: validation.user.email,
                google_id: validation.user.google_id,
                email_verified: validation.user.email_verified
              }
            };
          }
        }

        res.json({
          cookies: req.cookies,
          session: req.session,
          user: req.user,
          authInfo
        });
      } catch (error) {
        sendError.serverError(res, { message: error.message  });
      }
    });
  }












  // Comprehensive health check endpoint
  app.get('/health', async(req, res) => {
    const startTime = Date.now();
    const systemStats = monitor.getSystemStats();
    const performanceMetrics = monitor.getMetrics();

    const health = {
      status: 'OK',
      timestamp: DateUtils.now(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: NODE_ENV,
      checks: {},
      system: systemStats,
      performance: {
        totalRequests: performanceMetrics.summary.totalRequests,
        avgResponseTime: performanceMetrics.summary.avgResponseTime,
        slowQueries: performanceMetrics.summary.recentSlowQueries.length,
        memoryUsage: process.memoryUsage()
      }
    };

    // 1. Database Health Check
    try {
      const dbStart = Date.now();
      await dbManager.get('SELECT 1 as test');
      const dbTime = Date.now() - dbStart;

      health.checks.database = {
        status: 'OK',
        responseTime: dbTime,
        message: 'Database connection successful'
      };
    } catch (error) {
      health.checks.database = {
        status: 'ERROR',
        error: error.message,
        message: 'Database connection failed'
      };
      health.status = 'DEGRADED';
    }

    // 2. Email Service Health Check
    try {
      if (emailService && emailService.transporter) {
        health.checks.email = {
          status: 'OK',
          message: 'Email service configured'
        };
      } else {
        health.checks.email = {
          status: 'WARNING',
          message: 'Email service not configured'
        };
      }
    } catch (error) {
      health.checks.email = {
        status: 'ERROR',
        error: error.message,
        message: 'Email service check failed'
      };
    }

    // 3. Cache Health Check
    try {
      const cacheStats = globalCache.getStats();
      health.checks.cache = {
        status: 'OK',
        stats: cacheStats,
        message: `Cache operational with ${cacheStats.size} entries`
      };
    } catch (error) {
      health.checks.cache = {
        status: 'ERROR',
        error: error.message,
        message: 'Cache check failed'
      };
    }

    // 4. File System Health Check
    try {
      const fs = require('fs');
      const testPath = path.join(config.upload.avatarsDir, '.health-check');

      // Test write
      fs.writeFileSync(testPath, 'health-check-' + Date.now());
      // Test read
      fs.readFileSync(testPath);
      // Cleanup
      fs.unlinkSync(testPath);

      health.checks.filesystem = {
        status: 'OK',
        message: 'File system read/write successful'
      };
    } catch (error) {
      health.checks.filesystem = {
        status: 'ERROR',
        error: error.message,
        message: 'File system check failed'
      };
      health.status = 'DEGRADED';
    }

    // 5. External APIs Health Check (optional)
    health.checks.external_apis = {
      status: 'OK',
      services: {
        yookassa: config.payments ? 'CONFIGURED' : 'NOT_CONFIGURED'
      },
      message: 'External API configurations checked'
    };

    // 6. Performance Checks
    if (performanceMetrics.summary.avgResponseTime > 2000) {
      health.status = health.status === 'OK' ? 'SLOW' : health.status;
      health.checks.performance = {
        status: 'WARNING',
        avgResponseTime: performanceMetrics.summary.avgResponseTime,
        message: 'Average response time exceeds 2 seconds'
      };
    } else {
      health.checks.performance = {
        status: 'OK',
        avgResponseTime: performanceMetrics.summary.avgResponseTime,
        message: 'Performance within acceptable limits'
      };
    }

    // 7. Memory Check
    const memUsage = process.memoryUsage();
    const memUsedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    const memLimitMB = Math.round(memUsage.heapTotal / 1024 / 1024);

    if (memUsedMB > 500) { // Alert if using more than 500MB
      health.checks.memory = {
        status: 'WARNING',
        usedMB: memUsedMB,
        limitMB: memLimitMB,
        message: `High memory usage: ${memUsedMB}MB`
      };
      if (health.status === 'OK') health.status = 'WARNING';
    } else {
      health.checks.memory = {
        status: 'OK',
        usedMB: memUsedMB,
        limitMB: memLimitMB,
        message: 'Memory usage normal'
      };
    }

    // Calculate overall health check duration
    health.healthCheckDuration = Date.now() - startTime;

    // Determine HTTP status code
    let httpStatus = 200;
    if (health.status === 'DEGRADED') httpStatus = 503;
    else if (health.status === 'WARNING') httpStatus = 200;
    else if (health.status === 'SLOW') httpStatus = 200;

    // Add summary
    const checks = Object.values(health.checks);
    health.summary = {
      total: checks.length,
      ok: checks.filter(c => c.status === 'OK').length,
      warning: checks.filter(c => c.status === 'WARNING').length,
      error: checks.filter(c => c.status === 'ERROR').length
    };

    res.status(httpStatus).json(health);
  });

  // Chrome DevTools endpoint
  app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
    res.status(404).json({
      success: false,
      error: 'Ресурс не найден',
      code: 'NOT_FOUND'
    });
  });

  // Error handling middleware (должно быть в самом конце)
  app.use(notFoundHandler);
  app.use(errorHandler);

  // Graceful shutdown handling
  const server = app.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
      logger.error('Server failed to start', { error: err.message, port: PORT });
      process.exit(1);
    }
    logger.info('Workado server started', {
      port: PORT,
      env: NODE_ENV,
      pid: process.pid,
      host: '0.0.0.0'
    });
    
    // Запускаем периодическую очистку временных файлов
    startPeriodicCleanup(6 * 60 * 60 * 1000); // Каждые 6 часов
    logger.info('File cleanup scheduler started');
  });

  // Функция для генерации рекомендаций по БД
  function _generateDbRecommendations(indexStats) {
    const recommendations = [];

    // Найти неиспользуемые индексы
    const unusedIndexes = indexStats.filter(stat => stat.idx_scan === '0');
    if (unusedIndexes.length > 0) {
      recommendations.push({
        type: 'warning',
        message: `Найдено ${unusedIndexes.length} неиспользуемых индексов`,
        details: unusedIndexes.map(idx => idx.indexname)
      });
    }

    // Найти часто используемые индексы
    const heavilyUsedIndexes = indexStats.filter(stat => parseInt(stat.idx_scan) > 10000);
    if (heavilyUsedIndexes.length > 0) {
      recommendations.push({
        type: 'info',
        message: `${heavilyUsedIndexes.length} индексов активно используются`,
        details: heavilyUsedIndexes.map(idx => `${idx.indexname} (${idx.idx_scan} сканирований)`)
      });
    }

    if (recommendations.length === 0) {
      recommendations.push({
        type: 'success',
        message: 'Индексы БД используются эффективно'
      });
    }

    return recommendations;
  }

  // Улучшенный graceful shutdown
  let shutdownInProgress = false;
  const gracefulShutdown = async(signal) => {
    if (shutdownInProgress) {
      logger.warn(`Shutdown already in progress, ignoring ${signal}`);
      return;
    }

    shutdownInProgress = true;
    logger.info(`Received ${signal}. Starting graceful shutdown...`);

    // Таймаут для принудительного завершения (уменьшен до 15 секунд)
    const forceExitTimeout = setTimeout(() => {
      logger.error('Graceful shutdown timeout exceeded, forcing exit');
      process.exit(1);
    }, 15000);

    try {
      // Этап 1: Прекращаем принимать новые подключения
      await new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) {
            reject(err);
          } else {
            logger.info('HTTP server closed');
            resolve();
          }
        });
      });

      // Этап 2: Даём время завершиться текущим запросам (3 секунды)
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Этап 3: Закрываем соединения с БД
      if (dbManager && typeof dbManager.close === 'function') {
        await dbManager.close();
        logger.info('Database connections closed');
      }

      clearTimeout(forceExitTimeout);
      logger.info('Graceful shutdown completed');
      process.exit(0);

    } catch (err) {
      clearTimeout(forceExitTimeout);
      logger.error('Error during graceful shutdown', {
        error: err.message,
        stack: err.stack
      });
      process.exit(1);
    }
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);

  // Глобальная обработка необработанных ошибок
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise
    });
  });

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
      error: error.message,
      stack: error.stack
    });
    // Не завершаем процесс сразу, дадим время для graceful shutdown
    setTimeout(() => process.exit(1), 1000);
  });
}

// Экспортируем функции для тестирования
module.exports = {
  validateSessionToken,
  authMiddleware,
  adminMiddleware
};

main().catch(err => {
  logger.error('Fatal error', { error: err.message, stack: err.stack });
  process.exit(1);
});
