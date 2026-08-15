'use strict';

import { el, clear, loadingState, formatDate } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { getUser } from '../state.js';
import { navigate } from '../router.js';

export async function renderDashboard(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader(`Welcome back, ${(getUser().fullName || '').split(' ')[0]}`, 'Here is what is happening with your legacy.'));
  outlet.appendChild(loadingState('Loading your dashboard...'));

  try {
    const [memoriesRes, eventsRes, docsRes, photosRes, messagesRes, beneficiariesRes, inboxRes] = await Promise.all([
      apiRequest('/memories'),
      apiRequest('/timeline'),
      apiRequest('/documents'),
      apiRequest('/photos'),
      apiRequest('/legacy-messages'),
      apiRequest('/beneficiaries'),
      apiRequest('/legacy-messages/inbox'),
    ]);

    clear(outlet);
    outlet.appendChild(pageHeader(`Welcome back, ${(getUser().fullName || '').split(' ')[0]}`, 'Here is what is happening with your legacy.'));

    const stats = [
      ['Memories & stories', memoriesRes.memories.length, '/memories'],
      ['Life events', eventsRes.events.length, '/timeline'],
      ['Documents', docsRes.documents.length, '/documents'],
      ['Photos', photosRes.photos.length, '/photos'],
      ['Legacy messages', messagesRes.messages.length, '/legacy-messages'],
      ['Beneficiaries', beneficiariesRes.beneficiaries.length, '/beneficiaries'],
    ];

    outlet.appendChild(el('div', { class: 'grid cols-3' }, stats.map(([label, value, path]) =>
      el('div', { class: 'card stat-card', style: 'cursor:pointer;', onclick: () => navigate(path) }, [
        el('div', { class: 'value', text: String(value) }),
        el('div', { class: 'label', text: label }),
      ])
    )));

    if (inboxRes.messages.length > 0) {
      outlet.appendChild(el('div', { class: 'card mt-2' }, [
        el('div', { class: 'section-header' }, [el('h2', { text: '📥 You have messages waiting' })]),
        ...inboxRes.messages.slice(0, 3).map((m) => el('div', { class: 'list-item' }, [
          el('div', {}, [
            el('div', { class: 'title', text: m.title }),
            el('div', { class: 'meta', text: `Released ${formatDate(m.releasedAt)}` }),
          ]),
          el('button', { class: 'btn small', text: 'Read', onclick: () => navigate('/inbox') }),
        ])),
      ]));
    }

    const pendingMessages = messagesRes.messages.filter((m) => m.status === 'pending');
    outlet.appendChild(el('div', { class: 'card mt-2' }, [
      el('div', { class: 'section-header' }, [
        el('h2', { text: 'Upcoming legacy messages' }),
        el('button', { class: 'btn small secondary', text: 'Manage all', onclick: () => navigate('/legacy-messages') }),
      ]),
      pendingMessages.length
        ? el('div', {}, pendingMessages.slice(0, 5).map((m) => el('div', { class: 'list-item' }, [
            el('div', {}, [
              el('div', { class: 'title', text: m.title }),
              el('div', { class: 'meta', text: m.releaseType === 'scheduled_date' ? `Releases ${formatDate(m.releaseAt)}` : 'Releases on confirmed passing' }),
            ]),
            el('span', { class: `badge ${m.status}`, text: m.status }),
          ])))
        : el('div', { class: 'text-muted', text: 'No pending legacy messages yet.' }),
    ]));
  } catch (err) {
    clear(outlet);
    outlet.appendChild(pageHeader('Dashboard', ''));
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { class: 'text-muted', text: `Could not load dashboard: ${err.message}` })]));
  }
}
