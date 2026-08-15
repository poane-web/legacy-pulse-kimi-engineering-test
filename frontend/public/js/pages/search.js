'use strict';

import { el, clear, emptyState, loadingState } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';

const TYPE_LABEL = { memory: 'Memory', story: 'Story', instruction: 'Instruction', life_event: 'Life Event', document: 'Document', beneficiary: 'Beneficiary' };

export function renderSearch(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Search', 'Search across your memories, stories, timeline, documents, and beneficiaries.'));

  const input = el('input', { type: 'search', placeholder: 'Search your legacy...' });
  const resultsBox = el('div', { class: 'mt-2' });

  let debounceTimer;
  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runSearch(input.value, resultsBox), 300);
  });

  outlet.appendChild(el('div', { class: 'card' }, [
    el('div', { class: 'field' }, [input]),
  ]));
  outlet.appendChild(resultsBox);
}

async function runSearch(q, resultsBox) {
  clear(resultsBox);
  if (!q || q.trim().length === 0) return;
  resultsBox.appendChild(loadingState('Searching...'));
  try {
    const data = await apiRequest(`/search?q=${encodeURIComponent(q)}`);
    clear(resultsBox);
    const card = el('div', { class: 'card' });
    if (data.results.length === 0) {
      card.appendChild(emptyState('🔍', `No results for "${q}"`, ''));
    } else {
      data.results.forEach((r) => {
        card.appendChild(el('div', { class: 'list-item' }, [
          el('div', {}, [
            el('div', { class: 'title', text: r.title }),
            el('div', { class: 'meta', text: r.snippet || '' }),
          ]),
          el('span', { class: 'badge owner', text: TYPE_LABEL[r.type] || r.type }),
        ]));
      });
    }
    resultsBox.appendChild(card);
  } catch (err) {
    clear(resultsBox);
    resultsBox.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
  }
}
