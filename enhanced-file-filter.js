// middleware/enhanced-file-filter.js - Улучшенный фильтр файлов для multer

'use strict';

const fs = require('fs').promises;
const FileSecurityValidator = require('../lib/file-security-validator');
const { getLogger } = require('../lib/logger');
const { getAlertManager } = require('../lib/alert-manager');

const logger = getLogger();
const alertManager = getAlertManager();

/**
 * Создает улучшенный фильтр файлов для multer с проверкой magic numbers
 * 
 * @param {Object} options - Опции фильтрации
 * @returns {Function} Функция фильтра для multer
 */
function createEnhancedFileFilter(options = {}) {
  const {
    allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    maxSize = 5 * 1024 * 1024,
    checkMagicNumbers = true,
    scanForMalware = true,
    quarantine = false,
    alertOnSuspicious = true
  } = options;

  return async (req, file, cb) => {
    try {
      // Базовая проверка MIME типа
      if (!allowedMimeTypes.includes(file.mimetype)) {
        logger.warn('File rejected by MIME type', {
          filename: file.originalname,
          mimetype: file.mimetype,
          allowed: allowedMimeTypes
        });
        return cb(new Error(`Недопустимый тип файла. Разрешены: ${allowedMimeTypes.join(', ')}`), false);
      }

      // Проверка расширения файла
      const path = require('path');
      const ext = path.extname(file.originalname).toLowerCase();
      const allowedExtensions = getAllowedExtensions(allowedMimeTypes);
      
      if (!allowedExtensions.includes(ext)) {
        logger.warn('File rejected by extension', {
          filename: file.originalname,
          extension: ext,
          allowed: allowedExtensions
        });
        return cb(new Error(`Недопустимое расширение файла. Разрешены: ${allowedExtensions.join(', ')}`), false);
      }

      // Если у нас есть буфер (multer.memoryStorage), проводим полную проверку
      if (file.buffer) {
        const validationResult = await FileSecurityValidator.validateFile(file, {
          allowedMimeTypes,
          maxSize,
          checkMagicNumbers,
          scanForMalware,
          quarantineSuspicious: quarantine
        });

        if (!validationResult.valid) {
          const errorMsg = validationResult.errors[0] || 'Файл не прошел проверку безопасности';
          
          // Логируем детали
          logger.warn('File failed security validation', {
            filename: file.originalname,
            errors: validationResult.errors,
            warnings: validationResult.warnings,
            suspiciousPatterns: validationResult.suspiciousPatterns
          });

          // Отправляем алерт если нашли критические проблемы
          if (alertOnSuspicious && validationResult.suspiciousPatterns?.length > 0) {
            const critical = validationResult.suspiciousPatterns.filter(p => p.severity === 'critical');
            if (critical.length > 0) {
              await alertManager.sendAlert('security', {
                title: 'Заблокирован подозрительный файл',
                message: `Файл ${file.originalname} содержит критические угрозы безопасности`,
                severity: 'critical',
                metadata: {
                  filename: file.originalname,
                  patterns: critical,
                  userId: req.user?.id,
                  ip: req.ip
                }
              });
            }
          }

          return cb(new Error(errorMsg), false);
        }

        // Добавляем метаданные валидации
        file.securityMetadata = validationResult.metadata;
        
        // Логируем успешную проверку с предупреждениями
        if (validationResult.warnings?.length > 0) {
          logger.info('File accepted with warnings', {
            filename: file.originalname,
            warnings: validationResult.warnings
          });
        }
      }

      // Файл прошел все проверки
      cb(null, true);
      
    } catch (error) {
      logger.error('Enhanced file filter error', { 
        error: error.message,
        filename: file.originalname 
      });
      cb(new Error('Ошибка проверки файла'), false);
    }
  };
}

/**
 * Получить разрешенные расширения на основе MIME типов
 */
function getAllowedExtensions(mimeTypes) {
  const extensionMap = {
    'image/jpeg': ['.jpg', '.jpeg', '.jpe'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/webp': ['.webp'],
    'image/bmp': ['.bmp'],
    'image/svg+xml': ['.svg'],
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt', '.text'],
    'application/msword': ['.doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.ms-excel': ['.xls'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/zip': ['.zip'],
    'application/json': ['.json']
  };

  const extensions = new Set();
  for (const mimeType of mimeTypes) {
    const exts = extensionMap[mimeType];
    if (exts) {
      exts.forEach(ext => extensions.add(ext));
    }
  }

  return Array.from(extensions);
}

/**
 * Middleware для проверки файлов после загрузки на диск
 * Используется для multer.diskStorage
 */
async function postUploadValidation(req, res, next) {
  try {
    const filesToValidate = [];
    
    // Собираем все файлы для проверки
    if (req.file) {
      filesToValidate.push(req.file);
    }
    if (req.files) {
      if (Array.isArray(req.files)) {
        filesToValidate.push(...req.files);
      } else {
        // Для fields() метода multer
        Object.values(req.files).forEach(fileArray => {
          filesToValidate.push(...fileArray);
        });
      }
    }

    if (filesToValidate.length === 0) {
      return next();
    }

    // Определяем параметры проверки по пути
    const isAvatar = req.path?.includes('avatar');
    const isSupport = req.path?.includes('support');
    
    let validationOptions = {
      checkMagicNumbers: true,
      scanForMalware: true
    };

    if (isAvatar) {
      validationOptions.allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
      validationOptions.maxSize = 5 * 1024 * 1024;
    } else if (isSupport) {
      validationOptions.allowedMimeTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      ];
      validationOptions.maxSize = 10 * 1024 * 1024;
      validationOptions.quarantineSuspicious = true;
    }

    // Проверяем каждый файл
    const validFiles = [];
    const invalidFiles = [];

    for (const file of filesToValidate) {
      // Читаем файл с диска для проверки
      if (file.path && !file.buffer) {
        try {
          file.buffer = await fs.readFile(file.path);
        } catch (error) {
          logger.error('Failed to read uploaded file', {
            path: file.path,
            error: error.message
          });
          invalidFiles.push({
            file,
            error: 'Не удалось прочитать файл для проверки'
          });
          continue;
        }
      }

      const validationResult = await FileSecurityValidator.validateFile(file, validationOptions);
      
      if (validationResult.valid) {
        file.securityValidation = validationResult;
        validFiles.push(file);
        
        // Очищаем буфер после проверки для экономии памяти
        delete file.buffer;
      } else {
        invalidFiles.push({
          file,
          errors: validationResult.errors,
          patterns: validationResult.suspiciousPatterns
        });
        
        // Удаляем невалидный файл
        if (file.path) {
          try {
            await fs.unlink(file.path);
            logger.info('Deleted invalid file', { path: file.path });
          } catch (error) {
            logger.error('Failed to delete invalid file', {
              path: file.path,
              error: error.message
            });
          }
        }
      }
    }

    // Обработка результатов
    if (invalidFiles.length > 0 && validFiles.length === 0) {
      // Все файлы невалидные
      const errors = invalidFiles.map(f => 
        `${f.file.originalname}: ${f.errors?.join(', ') || 'Проверка не пройдена'}`
      );
      
      return res.status(400).json({
        error: 'Файлы не прошли проверку безопасности',
        details: errors
      });
    }

    // Обновляем req с валидными файлами
    if (req.file && invalidFiles.find(f => f.file === req.file)) {
      delete req.file;
    }
    
    if (req.files) {
      if (Array.isArray(req.files)) {
        req.files = validFiles.filter(f => req.files.includes(f));
      }
    }

    // Добавляем информацию об отклоненных файлах
    if (invalidFiles.length > 0) {
      req.rejectedFiles = invalidFiles.map(f => ({
        filename: f.file.originalname,
        errors: f.errors,
        patterns: f.patterns
      }));
      
      logger.warn('Some files were rejected', {
        accepted: validFiles.length,
        rejected: invalidFiles.length,
        rejectedFiles: req.rejectedFiles
      });
    }

    next();
    
  } catch (error) {
    logger.error('Post upload validation error', { error: error.message });
    return res.status(500).json({
      error: 'Ошибка проверки загруженных файлов'
    });
  }
}

module.exports = {
  createEnhancedFileFilter,
  postUploadValidation,
  getAllowedExtensions
};