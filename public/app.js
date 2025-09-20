document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('upload-form');
  const fileInput = document.getElementById('file-input');
  const resultSection = document.getElementById('result');
  const statusEl = document.getElementById('status');
  const summaryEl = document.getElementById('summary');
  const warningsEl = document.getElementById('warnings');
  const duplicatesEl = document.getElementById('duplicates');
  const suggestionsEl = document.getElementById('suggestions');
  const formatsContainer = document.getElementById('formats-list');
  const duplicateTemplate = document.getElementById('duplicate-template');

  async function loadFormats() {
    try {
      const response = await fetch('/api/supported-formats');
      if (!response.ok) {
        throw new Error('Не удалось получить список форматов');
      }
      const data = await response.json();
      if (Array.isArray(data.formats)) {
        formatsContainer.innerHTML = '';
        data.formats.forEach((format) => {
          const span = document.createElement('span');
          span.textContent = format;
          formatsContainer.appendChild(span);
        });
        if (data.formats.length && fileInput) {
          fileInput.setAttribute('accept', data.formats.join(','));
        }
      }
    } catch (error) {
      const span = document.createElement('span');
      span.textContent = 'Не удалось загрузить форматы. Попробуйте позже.';
      formatsContainer.appendChild(span);
      console.error(error);
    }
  }

  function showResultSection() {
    resultSection.classList.remove('hidden');
    statusEl.textContent = '';
    summaryEl.innerHTML = '';
    warningsEl.innerHTML = '';
    duplicatesEl.innerHTML = '';
    suggestionsEl.innerHTML = '';
  }

  function renderSummary(data) {
    const { metadata, fileName } = data;

    if (!metadata) {
      return;
    }
    const summary = document.createElement('div');
    summary.innerHTML = `
      <p><strong>Файл:</strong> ${fileName}</p>
      <p><strong>Язык:</strong> ${metadata.language}</p>
      <p><strong>Всего строк:</strong> ${metadata.totalLines}</p>
      <p><strong>Строк в анализе:</strong> ${metadata.normalizedLineCount}</p>
      <p><strong>Размер окна:</strong> ${metadata.windowSize}</p>
      <p><strong>Групп дубликатов:</strong> ${metadata.duplicateGroups}</p>
      <p><strong>Доля повторов:</strong> ${metadata.duplicationPercentage}%</p>
    `;
    summaryEl.appendChild(summary);
  }

  function renderWarnings(warnings) {
    if (!warnings || !warnings.length) {
      return;
    }

    const fragment = document.createDocumentFragment();
    warnings.forEach((warning) => {
      const p = document.createElement('p');
      p.textContent = warning;
      fragment.appendChild(p);
    });
    warningsEl.appendChild(fragment);
  }

  function renderSuggestions(suggestions) {
    if (!suggestions || !suggestions.length) {
      return;
    }

    const fragment = document.createDocumentFragment();
    const title = document.createElement('p');
    title.innerHTML = '<strong>Рекомендации:</strong>';
    fragment.appendChild(title);

    suggestions.forEach((suggestion) => {
      const p = document.createElement('p');
      p.textContent = suggestion;
      fragment.appendChild(p);
    });

    suggestionsEl.appendChild(fragment);
  }

  function renderDuplicates(groups) {
    if (!groups || !groups.length) {
      const p = document.createElement('p');
      p.textContent = 'Повторяющихся фрагментов не найдено.';
      duplicatesEl.appendChild(p);
      return;
    }

    groups.forEach((group, index) => {
      const clone = duplicateTemplate.content.firstElementChild.cloneNode(true);
      clone.querySelector('h3').textContent = `Фрагмент #${index + 1}`;
      clone.querySelector('.occurrences').textContent = `Повторений: ${group.occurrenceCount}`;
      clone.querySelector('.snippet').textContent = group.snippet;

      const occurrencesList = clone.querySelector('.occurrence-list');
      group.instances.forEach((instance) => {
        const li = document.createElement('li');
        li.textContent = `Строки ${instance.startLine}–${instance.endLine}`;
        occurrencesList.appendChild(li);
      });

      duplicatesEl.appendChild(clone);
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const file = fileInput.files[0];

    if (!file) {
      alert('Сначала выберите файл для проверки.');
      return;
    }

    showResultSection();
    statusEl.textContent = 'Выполняется анализ…';

    const formData = new FormData();
    formData.append('codeFile', file);

    try {
      const response = await fetch('/api/check', {
        method: 'POST',
        body: formData
      });

      const payload = await response.json();

      if (!response.ok) {
        statusEl.textContent = payload.error || 'Произошла ошибка во время анализа.';
        return;
      }

      statusEl.textContent = 'Анализ успешно завершён';
      renderSummary(payload);
      renderWarnings(payload.warnings);
      renderDuplicates(payload.duplicates);
      renderSuggestions(payload.suggestions);
    } catch (error) {
      console.error(error);
      statusEl.textContent = 'Произошла непредвиденная ошибка. Попробуйте ещё раз.';
    }
  });

  loadFormats();
});
