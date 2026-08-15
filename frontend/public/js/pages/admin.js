'use strict';

import { el, clear, loadingState, formatDate, formatBytes, formatDateTime, emptyState } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { toast } from '../components/toast.js';
import { confirmDialog } from '../components/modal.js';

export async function renderAdminDashboard(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Platform Dashboard', 'Operational metadata only — admins never see decrypted owner content.'));
  outlet.appendChild(loadingState());

  let stats, users;
  try {
    [{ stats }, { users }] = await Promise.all([apiRequest('/admin/stats'), apiRequest('/admin/users')]);
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const statEntries = [
    ['Owner accounts', stats.users],
    ['Admin accounts', stats.admins],
    ['Beneficiaries', stats.beneficiaries],
    ['Memories/stories/instructions', stats.memories],
    ['Documents', stats.documents],
    ['Photos', stats.photos],
    ['Pending legacy messages', stats.legacyMessagesPending],
    ['Released legacy messages', stats.legacyMessagesReleased],
    ['Storage used', formatBytes(stats.storageBytesUsed)],
  ];
  outlet.appendChild(el('div', { class: 'grid cols-3' }, statEntries.map(([label, value]) =>
    el('div', { class: 'card stat-card' }, [el('div', { class: 'value', text: String(value) }), el('div', { class: 'label', text: label })])
  )));

  const usersCard = el('div', { class: 'card mt-2' }, [
    el('h2', { style: 'font-size:1.05rem;margin-top:0;', text: 'Users' }),
  ]);
  if (users.length === 0) {
    usersCard.appendChild(emptyState('👤', 'No users', ''));
  } else {
    users.forEach((u) => {
      usersCard.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: u.fullName }),
          el('div', { class: 'meta', text: `${u.email} · joined ${formatDate(u.createdAt)}` }),
        ]),
        el('div', { class: 'actions' }, [
          el('span', { class: `badge ${u.role}`, text: u.role }),
          el('span', { class: `badge ${u.status}`, text: u.status }),
          u.role !== 'admin' ? el('button', {
            class: `btn small ${u.status === 'active' ? 'danger' : 'secondary'}`,
            text: u.status === 'active' ? 'Disable' : 'Enable',
            onclick: () => {
              confirmDialog({
                title: `${u.status === 'active' ? 'Disable' : 'Enable'} ${u.fullName}?`,
                message: u.status === 'active' ? 'This immediately signs them out and blocks login.' : 'This restores their ability to log in.',
                danger: u.status === 'active',
                onConfirm: async () => {
                  await apiRequest(`/admin/users/${u.id}/status`, { method: 'PUT', body: { status: u.status === 'active' ? 'disabled' : 'active' } });
                  toast('Updated', 'success');
                  renderAdminDashboard(outlet);
                },
              });
            },
          }) : null,
        ]),
      ]));
    });
  }
  outlet.appendChild(usersCard);
}

export async function renderAdminAuditLogs(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Platform Audit Logs', 'Append-only record of security-relevant events across the platform.'));
  outlet.appendChild(loadingState());

  let data;
  try {
    data = await apiRequest('/admin/audit-logs?pageSize=50');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  const card = el('div', { class: 'card' });
  if (data.logs.length === 0) {
    card.appendChild(emptyState('📜', 'No audit events yet', ''));
  } else {
    data.logs.forEach((log) => {
      card.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: log.action }),
          el('div', { class: 'meta', text: `${log.actorEmail || 'system'} · ${formatDateTime(log.createdAt)}${log.ip ? ' · ' + log.ip : ''}` }),
        ]),
      ]));
    });
  }
  outlet.appendChild(card);
}
