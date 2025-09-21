// middleware/file-security.js - Middleware для проверки безопасности загружаемых файлов

'use strict';

const fs = require('fs').promises;
const path = require('path');
const FileSecurityValidator = require('../lib/file-security-validator');
const { getLogger } = require('../lib/logger');
const { sendError } = require('./error-handler');
const { getAlertManager } = require('../lib/alert-manager');

const logger = getLogger();
const alertManager = getAlertManager();

/**
 * Middleware для дополнительной проверки файлов после загрузки multer
 * Проверяет файлы на диске, включая magic numbers и подозрительные паттерны
 */
async function validateUploadedFile(req, res, next) {
  try {
    // Проверяем одиночный файл
    if (req.file) {
      const validationResult = await validateSingleFile(req.file, req);
      
      if (!validationResult.valid) {
        // Удаляем файл если он не прошел проверку
        await cleanupFile(req.file);
        
        return sendError.badRequest(res, {
          message: 'Файл не прошел проверку безопасности',
          errors: validationResult.errors
        });
      }
      
      // Добавляем метаданные безопасности к файлу
      req.file.securityValidation = validationResult;
    }
    
    // Проверяем множественные файлы
    if (req.files) {
      const validFiles = [];
      const invalidFiles = [];
      
      // Обрабатываем массив файлов
      const filesToCheck = Array.isArray(req.files) ? req.files : Object.values(req.files).flat();
      
      for (const file of filesToCheck) {
        const validationResult = await validateSingleFile(file, req);
        
        if (validationResult.valid) {
          file.securityValidation = validationResult;
          validFiles.push(file);
        } else {
          invalidFiles.push({
            filename: file.originalname,
            errors: validationResult.errors,
            file: file
          });
        }
      }
      
      // Если есть невалидные файлы, удаляем их
      if (invalidFiles.length > 0) {
        for (const invalidFile of invalidFiles) {
          await cleanupFile(invalidFile.file);
        }
        
        // Если все файлы невалидные, возвращаем ошибку
        if (validFiles.length === 0) {
          return sendError.badRequest(res, {
            message: 'Ни один файл не прошел проверку безопасности',
            errors: invalidFiles.map(f => `${f.filename}: ${f.errors.join(', ')}`)
          });
        }
        
        // Обновляем список файлов только валидными
        if (Array.isArray(req.files)) {
          req.files = validFiles;
        }
        
        // Добавляем информацию об отклоненных файлах
        req.rejectedFiles = invalidFiles;
      }
    }
    
    next();
  } catch (error) {
    logger.error('File security middleware error', { error: error.message, stack: error.stack });
    return sendError.serverError(res, { message: 'Ошибка проверки безопасности файлов' });
  }
}

/**
 * Валидация одного файла
 */
async function validateSingleFile(file, req) {
  try {
    // Определяем опции валидации на основе типа загрузки
    const isAvatarUpload = req.path && req.path.includes('avatar');
    const isSupportUpload = req.path && req.path.includes('support');
    
    let validationOptions = {
      checkMagicNumbers: true,
      scanForMalware: true,
      quarantineSuspicious: false
    };
    
    if (isAvatarUpload) {
      validationOptions.allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
      validationOptions.maxSize = 5 * 1024 * 1024; // 5MB
      validationOptions.quarantineSuspicious = false;
    } else if (isSupportUpload) {
      validationOptions.allowedMimeTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain',
        'application/msword', 
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      ];
      validationOptions.maxSize = 10 * 1024 * 1024; // 10MB
      validationOptions.quarantineSuspicious = true;
      validationOptions.quarantineDir = path.join(process.cwd(), 'public', 'uploads', 'quarantine');
    }
    
    // Читаем файл с диска если нет буфера
    if (!file.buffer && file.path) {
      file.buffer = await fs.readFile(file.path);
    }
    
    // Выполняем валидацию
    const validationResult = await FileSecurityValidator.validateFile(file, validationOptions);
    
    // Логируем результат
    if (!validationResult.valid) {
      logger.warn('File validation failed', {
        filename: file.originalname,
        path: file.path,
        errors: validationResult.errors,
        suspiciousPatterns: validationResult.suspiciousPatterns
      });
      
      // Отправляем алерт для критических находок
      if (validationResult.suspiciousPatterns?.some(p => p.severity === 'critical')) {
        await alertManager.sendAlert('security', {
          title: 'Обнаружен подозрительный файл',
          message: `Файл ${file.originalname} содержит критические проблемы безопасности`,
          severity: 'critical',
          metadata: {
            filename: file.originalname,
            path: file.path,
            patterns: validationResult.suspiciousPatterns,
            userId: req.user?.id,
            ip: req.ip
          }
        });
      }
    }
    
    return validationResult;
  } catch (error) {
    logger.error('Error validating single file', { 
      error: error.message,
      filename: file?.originalname 
    });
    
    return {
      valid: false,
      errors: ['Внутренняя ошибка валидации файла']
    };
  }
}

/**
 * Удаление файла с диска
 */
async function cleanupFile(file) {
  if (!file || !file.path) return;
  
  try {
    await fs.unlink(file.path);
    logger.info('Deleted invalid file', { path: file.path });
  } catch (error) {
    logger.error('Failed to delete invalid file', { 
      error: error.message,
      path: file.path 
    });
  }
}

/**
 * Middleware для периодической очистки временных файлов
 */
async function cleanupTempFiles() {
  try {
    const tempDirs = [
      path.join(process.cwd(), 'public', 'uploads', 'temp'),
      path.join(process.cwd(), 'public', 'avatars', 'temp'),
      path.join(process.cwd(), 'public', 'uploads', 'support', 'temp')
    ];
    
    const maxAge = 24 * 60 * 60 * 1000; // 24 часа
    
    for (const tempDir of tempDirs) {
      try {
        await FileSecurityValidator.cleanupOldFiles(tempDir, maxAge);
      } catch (error) {
        // Игнорируем ошибки для несуществующих директорий
        if (error.code !== 'ENOENT') {
          logger.error('Error cleaning temp directory', { 
            error: error.message,
            dir: tempDir 
          });
        }
      }
    }
    
    logger.info('Temp files cleanup completed');
  } catch (error) {
    logger.error('Temp files cleanup error', { error: error.message });
  }
}

/**
 * Запуск периодической очистки
 */
function startPeriodicCleanup(intervalMs = 6 * 60 * 60 * 1000) { // Каждые 6 часов
  setInterval(cleanupTempFiles, intervalMs);
  
  // Запускаем первую очистку через 5 минут после старта
  setTimeout(cleanupTempFiles, 5 * 60 * 1000);
  
  logger.info('File cleanup scheduler started', { interval: intervalMs });
}

module.exports = {
  validateUploadedFile,
  cleanupTempFiles,
  startPeriodicCleanup
};