'use strict';

const { sendError } = require('./error-handler');

// Middleware для проверки подтверждения email
function requireEmailVerification(req, res, next) {
  // Проверяем наличие пользователя
  if (!req.user) {
    return sendError.unauthorized(res, {
      message: 'Требуется авторизация'
    });
  }

  if (!req.user.email_verified) {
    return sendError.forbidden(res, {
      message: 'Для выполнения этого действия необходимо подтвердить email',
      email_verification_required: true
    });
  }

  next();
}

module.exports = requireEmailVerification;