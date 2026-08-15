'use strict';

import { el, clear, loadingState, emptyState, formatDateTime } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { toast } from '../components/toast.js';

export async function renderInbox(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Messages For Me', 'Legacy messages that have been released to you as a beneficiary.'));
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest('/legacy-messages/inbox');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const card = el('div', { class: 'card' });
  if (data.messages.length === 0) {
    card.appendChild(emptyState('📥', 'No messages yet', 'When someone releases a legacy message addressed to you, it will appear here.'));
  } else {
    data.messages.forEach((m) => {
      const bodyBox = el('div', { class: 'body-text', style: 'display:none;' });
      card.appendChild(el('div', { class: 'list-item' }, [
        el('div', { style: 'flex:1;min-width:0;' }, [
          el('div', { class: 'title', text: m.title }),
          el('div', { class: 'meta', text: `Released ${formatDateTime(m.releasedAt)}` }),
          bodyBox,
        ]),
        el('button', { class: 'btn small', text: 'Read', onclick: async (e) => {
          if (bodyBox.style.display === 'block') { bodyBox.style.display = 'none'; e.target.textContent = 'Read'; return; }
          try {
            const full = await apiRequest(`/legacy-messages/${m.id}/read`);
            bodyBox.textContent = full.message.body;
            bodyBox.style.display = 'block';
            e.target.textContent = 'Hide';
          } catch (err) {
            toast(err.message, 'error');
          }
        } }),
      ]));
    });
  }
  outlet.appendChild(card);
}
