'use strict';

import { el, clear, loadingState, emptyState, formatDateTime } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';

export async function renderNotifications(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Notifications', 'Updates about your account and legacy content.'));
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest('/notifications');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const card = el('div', { class: 'card' });
  if (data.notifications.length === 0) {
    card.appendChild(emptyState('🔔', 'No notifications', 'You are all caught up.'));
  } else {
    data.notifications.forEach((n) => {
      card.appendChild(el('div', { class: 'list-item', style: n.read ? '' : 'background:#faf6ee;' }, [
        el('div', { style: 'flex:1;min-width:0;' }, [
          el('div', { class: 'title', text: n.message }),
          el('div', { class: 'meta', text: formatDateTime(n.createdAt) }),
        ]),
        !n.read ? el('button', { class: 'btn small secondary', text: 'Mark read', onclick: async (e) => {
          await apiRequest(`/notifications/${n.id}/read`, { method: 'PUT' });
          e.target.closest('.list-item').style.background = '';
          e.target.remove();
        } }) : null,
      ]));
    });
  }
  outlet.appendChild(card);
}
