const express = require('express');
const path = require('path');
const multer = require('multer');
const { analyseFile, SUPPORTED_EXTENSIONS } = require('./duplicate-checker');

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
  }
});

const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/supported-formats', (req, res) => {
  res.json({
    formats: SUPPORTED_EXTENSIONS
  });
});

app.post('/api/check', upload.single('codeFile'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: 'Файл не получен. Пожалуйста, выберите файл с кодом для проверки.'
    });
  }

  try {
    const analysis = analyseFile({
      buffer: req.file.buffer,
      originalName: req.file.originalname
    });

    const extension = path.extname(req.file.originalname).toLowerCase();
    const supported = SUPPORTED_EXTENSIONS.includes(extension);
    const warnings = [];

    if (!supported) {
      warnings.push(
        'Расширение файла не входит в перечень самых популярных языков, поддерживается общий режим анализа.'
      );
    }

    return res.json({
      fileName: req.file.originalname,
      supported,
      warnings,
      ...analysis
    });
  } catch (error) {
    return res.status(500).json({
      error: 'Не удалось проанализировать файл. Убедитесь, что загружаемый файл содержит текст.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'Файл слишком большой. Максимальный размер — 5MB.'
    });
  }

  return res.status(500).json({
    error: 'Внутренняя ошибка сервера',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Code duplication analyser is running on http://localhost:${PORT}`);
});
