const crypto = require('crypto');
const path = require('path');

const LANGUAGE_DEFINITIONS = {
  '.js': { language: 'JavaScript', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.jsx': { language: 'JavaScript (JSX)', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.ts': { language: 'TypeScript', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.tsx': { language: 'TypeScript (TSX)', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.mjs': { language: 'JavaScript Module', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.cjs': { language: 'CommonJS', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.py': { language: 'Python', singleLine: ['#'], multiLine: [["\"\"\"", "\"\"\""], ["'''", "'''"]] },
  '.java': { language: 'Java', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.c': { language: 'C', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.h': { language: 'C Header', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.hpp': { language: 'C++ Header', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.hh': { language: 'C++ Header', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.cpp': { language: 'C++', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.cc': { language: 'C++', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.cs': { language: 'C#', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.php': { language: 'PHP', singleLine: ['//', '#'], multiLine: [['/*', '*/']] },
  '.rb': { language: 'Ruby', singleLine: ['#'], multiLine: [] },
  '.go': { language: 'Go', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.rs': { language: 'Rust', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.swift': { language: 'Swift', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.kt': { language: 'Kotlin', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.kts': { language: 'Kotlin Script', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.scala': { language: 'Scala', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.m': { language: 'Objective-C', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.mm': { language: 'Objective-C++', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.sh': { language: 'Shell', singleLine: ['#'], multiLine: [] },
  '.bash': { language: 'Bash', singleLine: ['#'], multiLine: [] },
  '.zsh': { language: 'Zsh', singleLine: ['#'], multiLine: [] },
  '.ps1': { language: 'PowerShell', singleLine: ['#'], multiLine: [['<#', '#>']] },
  '.pl': { language: 'Perl', singleLine: ['#'], multiLine: [] },
  '.r': { language: 'R', singleLine: ['#'], multiLine: [] },
  '.lua': { language: 'Lua', singleLine: ['--'], multiLine: [['--[[', ']]']] },
  '.sql': { language: 'SQL', singleLine: ['--'], multiLine: [['/*', '*/']] },
  '.html': { language: 'HTML', singleLine: [], multiLine: [['<!--', '-->']] },
  '.xml': { language: 'XML', singleLine: [], multiLine: [['<!--', '-->']] },
  '.json': { language: 'JSON', singleLine: [], multiLine: [] },
  '.yaml': { language: 'YAML', singleLine: ['#'], multiLine: [] },
  '.yml': { language: 'YAML', singleLine: ['#'], multiLine: [] },
  '.css': { language: 'CSS', singleLine: [], multiLine: [['/*', '*/']] },
  '.scss': { language: 'SCSS', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.less': { language: 'Less', singleLine: ['//'], multiLine: [['/*', '*/']] },
  '.vue': { language: 'Vue Single File Component', singleLine: ['//'], multiLine: [['/*', '*/'], ['<!--', '-->']] },
  '.svelte': { language: 'Svelte Component', singleLine: ['//'], multiLine: [['/*', '*/'], ['<!--', '-->']] },
  '.md': { language: 'Markdown', singleLine: [], multiLine: [] },
  '.txt': { language: 'Plain text', singleLine: [], multiLine: [] }
};

const DEFAULT_DEFINITION = {
  language: 'Generic text',
  singleLine: ['//', '#', '--'],
  multiLine: [['/*', '*/'], ['<!--', '-->']]
};

const SUPPORTED_EXTENSIONS = Object.keys(LANGUAGE_DEFINITIONS);

function getLanguageDefinition(extension) {
  if (!extension) {
    return DEFAULT_DEFINITION;
  }

  return LANGUAGE_DEFINITIONS[extension] || DEFAULT_DEFINITION;
}

function stripBom(content) {
  if (content.charCodeAt(0) === 0xfeff) {
    return content.slice(1);
  }

  return content;
}

function preprocessContent(rawContent, extension) {
  const definition = getLanguageDefinition(extension);
  const content = stripBom(rawContent).replace(/\r\n?/g, '\n');
  const rawLines = content.split('\n');
  const normalizedLines = [];

  let activeBlock = null;

  rawLines.forEach((line, index) => {
    let processed = line;

    if (activeBlock) {
      const endIndex = processed.indexOf(activeBlock.end);
      if (endIndex !== -1) {
        processed = processed.slice(endIndex + activeBlock.end.length);
        activeBlock = null;
      } else {
        return;
      }
    }

    if (!activeBlock && definition.multiLine.length) {
      let search = true;
      while (search) {
        search = false;

        for (const [startToken, endToken] of definition.multiLine) {
          const startIndex = processed.indexOf(startToken);
          if (startIndex !== -1) {
            const endIndex = processed.indexOf(endToken, startIndex + startToken.length);
            if (endIndex !== -1) {
              processed = processed.slice(0, startIndex) + processed.slice(endIndex + endToken.length);
              search = true;
              break;
            } else {
              processed = processed.slice(0, startIndex);
              activeBlock = { start: startToken, end: endToken };
              break;
            }
          }
        }
      }
    }

    if (definition.singleLine.length) {
      for (const token of definition.singleLine) {
        const commentIndex = processed.indexOf(token);
        if (commentIndex !== -1) {
          processed = processed.slice(0, commentIndex);
        }
      }
    }

    const normalized = processed.replace(/\s+/g, ' ').trim();

    if (normalized) {
      normalizedLines.push({
        content: normalized,
        originalLine: index + 1
      });
    }
  });

  return {
    language: definition.language,
    normalizedLines,
    totalLines: rawLines.length
  };
}

function determineWindowSize(lineCount) {
  if (lineCount <= 4) {
    return Math.max(2, lineCount);
  }

  if (lineCount < 15) {
    return 3;
  }

  if (lineCount < 50) {
    return 4;
  }

  if (lineCount < 200) {
    return 5;
  }

  return 6;
}

function hashSequence(sequence) {
  return crypto.createHash('sha1').update(sequence).digest('hex').slice(0, 12);
}

function collectDuplicateLineStats(groups) {
  const uniqueLines = new Set();

  groups.forEach((group) => {
    group.instances.forEach((instance) => {
      instance.lines.forEach((line) => uniqueLines.add(line.originalLine));
    });
  });

  return uniqueLines;
}

function analyse(contentBuffer, extension) {
  const textContent = Buffer.isBuffer(contentBuffer)
    ? contentBuffer.toString('utf8')
    : String(contentBuffer || '');

  const normalized = preprocessContent(textContent, extension);
  const { normalizedLines } = normalized;

  if (!normalizedLines.length) {
    return {
      metadata: {
        fileExtension: extension || 'unknown',
        language: normalized.language,
        totalLines: normalized.totalLines,
        normalizedLineCount: 0,
        windowSize: 0,
        duplicateGroups: 0,
        duplicationPercentage: 0
      },
      duplicates: [],
      suggestions: ['В файле недостаточно кода для анализа или он содержит только комментарии.']
    };
  }

  const windowSize = determineWindowSize(normalizedLines.length);

  const sequences = new Map();

  for (let i = 0; i <= normalizedLines.length - windowSize; i += 1) {
    const slice = normalizedLines.slice(i, i + windowSize);
    const key = slice.map((line) => line.content).join('\n');
    const fingerprint = hashSequence(key);
    const instance = {
      startLine: slice[0].originalLine,
      endLine: slice[slice.length - 1].originalLine,
      lines: slice.map((line) => ({
        content: line.content,
        originalLine: line.originalLine
      }))
    };

    if (!sequences.has(fingerprint)) {
      sequences.set(fingerprint, {
        key,
        instances: [instance]
      });
    } else {
      sequences.get(fingerprint).instances.push(instance);
    }
  }

  const duplicateGroups = [];

  for (const [fingerprint, entry] of sequences.entries()) {
    if (entry.instances.length > 1) {
      duplicateGroups.push({
        fingerprint,
        occurrenceCount: entry.instances.length,
        snippet: entry.instances[0].lines.map((line) => line.content).join('\n'),
        instances: entry.instances.sort((a, b) => a.startLine - b.startLine)
      });
    }
  }

  duplicateGroups.sort((a, b) => b.occurrenceCount - a.occurrenceCount);

  const duplicateLineNumbers = collectDuplicateLineStats(duplicateGroups);
  const duplicationPercentage = normalizedLines.length
    ? Math.min(100, ((duplicateLineNumbers.size / normalizedLines.length) * 100))
    : 0;

  const suggestions = [];
  if (!duplicateGroups.length) {
    suggestions.push('Повторяющихся блоков кода не обнаружено. Отличная работа!');
  } else {
    suggestions.push('Рассмотрите возможность вынесения дублированных фрагментов в отдельные функции или модули.');
    suggestions.push('Проверьте, можно ли переиспользовать общие структуры данных или конфигурации.');
  }

  return {
    metadata: {
      fileExtension: extension || 'unknown',
      language: normalized.language,
      totalLines: normalized.totalLines,
      normalizedLineCount: normalizedLines.length,
      windowSize,
      duplicateGroups: duplicateGroups.length,
      duplicationPercentage: Number(duplicationPercentage.toFixed(2))
    },
    duplicates: duplicateGroups,
    suggestions
  };
}

function analyseFile({ buffer, originalName }) {
  const extension = originalName ? path.extname(originalName).toLowerCase() : '';
  return analyse(buffer, extension);
}

module.exports = {
  analyse,
  analyseFile,
  preprocessContent,
  determineWindowSize,
  SUPPORTED_EXTENSIONS
};
