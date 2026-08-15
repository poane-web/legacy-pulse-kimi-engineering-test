'use strict';

import { el, clear, loadingState, emptyState } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { openModal, confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderTrustedContacts(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Trusted Contacts', 'People who can confirm a release-trigger event (e.g. your passing). Two independent confirmations are required before condition-based legacy messages release — no single person can act alone.', [
    el('button', { class: 'btn', text: '+ Add Trusted Contact', onclick: () => openAddModal(outlet) }),
  ]));
  outlet.appendChild(loadingState());
  await loadList(outlet);
}

async function loadList(outlet) {
  let data;
  try {
    data = await apiRequest('/trusted-contacts');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  const existing = outlet.querySelector('#tc-list');
  const target = existing || el('div', { class: 'card', id: 'tc-list' });
  clear(target);

  if (data.trustedContacts.length === 0) {
    target.appendChild(emptyState('🤝', 'No trusted contacts yet', 'Add at least two people who can confirm a release-trigger event on your behalf.'));
  } else {
    data.trustedContacts.forEach((c) => {
      target.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: c.fullName }),
          el('div', { class: 'meta', text: c.email }),
        ]),
        el('div', { class: 'actions' }, [
          el('span', { class: `badge ${c.status}`, text: c.status }),
          el('button', { class: 'btn small danger', text: 'Revoke', onclick: () => {
            confirmDialog({
              title: `Revoke ${c.fullName}?`,
              message: 'They will no longer be able to confirm release-trigger events for your account.',
              onConfirm: async () => {
                await apiRequest(`/trusted-contacts/${c.id}`, { method: 'DELETE' });
                toast('Trusted contact revoked', 'success');
                await loadList(outlet);
              },
            });
          } }),
        ]),
      ]));
    });
  }
  if (!existing) {
    const loading = outlet.querySelector('.loading-state');
    if (loading) loading.replaceWith(target); else outlet.appendChild(target);
  }
}

function openAddModal(outlet) {
  openModal({
    title: 'Add a trusted contact',
    submitLabel: 'Send Invite',
    fields: [
      { name: 'fullName', label: 'Full name' },
      { name: 'email', label: 'Email address', type: 'email' },
    ],
    onSubmit: async (values) => {
      const res = await apiRequest('/trusted-contacts', { method: 'POST', body: values });
      toast(`Invite created for ${values.fullName}.`, 'success');
      await loadList(outlet);
      const full = `${window.location.origin}${res.inviteLink}`;
      const backdrop = el('div', { class: 'modal-backdrop' });
      const input = el('input', { type: 'text', value: full, readonly: 'readonly' });
      const modal = el('div', { class: 'modal' }, [
        el('h3', { text: 'Invite link' }),
        el('p', { class: 'text-muted', text: 'Share this link with your trusted contact so they can claim the role after creating an account.' }),
        el('div', { class: 'field' }, [input]),
        el('div', { class: 'modal-actions' }, [el('button', { class: 'btn', text: 'Close', onclick: () => backdrop.remove() })]),
      ]);
      backdrop.appendChild(modal);
      document.body.appendChild(backdrop);
    },
  });
}
