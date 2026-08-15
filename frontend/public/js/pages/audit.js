'use strict';

import { el, clear, loadingState, emptyState, formatDateTime } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';

export async function renderAudit(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('My Activity Log', 'A record of security-relevant actions on your account.'));
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest('/audit/me');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const card = el('div', { class: 'card' });
  if (data.logs.length === 0) {
    card.appendChild(emptyState('📜', 'No activity yet', ''));
  } else {
    data.logs.forEach((log) => {
      card.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: log.action }),
          el('div', { class: 'meta', text: `${formatDateTime(log.createdAt)}${log.ip ? ' · ' + log.ip : ''}${log.targetType ? ' · ' + log.targetType + ' #' + log.targetId : ''}` }),
        ]),
      ]));
    });
  }
  outlet.appendChild(card);
}
