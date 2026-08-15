'use strict';

import { el, clear, loadingState, emptyState } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { openModal, confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderBeneficiaries(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Beneficiaries', 'People you want to preserve memories and messages for.', [
    el('button', { class: 'btn', text: '+ Add Beneficiary', onclick: () => openAddModal(outlet) }),
  ]));
  outlet.appendChild(loadingState());
  await loadList(outlet);
}

async function loadList(outlet) {
  let data;
  try {
    data = await apiRequest('/beneficiaries');
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  const listCard = outlet.querySelector('#beneficiaries-list-card');
  const target = listCard || el('div', { class: 'card', id: 'beneficiaries-list-card' });
  clear(target);

  if (data.beneficiaries.length === 0) {
    target.appendChild(emptyState('👪', 'No beneficiaries yet', 'Add someone who should receive your memories and legacy messages.'));
  } else {
    data.beneficiaries.forEach((b) => {
      target.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: b.fullName }),
          el('div', { class: 'meta', text: `${b.relationship || 'Beneficiary'} · ${b.email}` }),
        ]),
        el('div', { class: 'actions' }, [
          el('span', { class: `badge ${b.linked ? 'claimed' : 'pending'}`, text: b.linked ? 'Linked' : 'Invite pending' }),
          el('button', { class: 'btn small danger', text: 'Remove', onclick: () => {
            confirmDialog({
              title: `Remove ${b.fullName}?`,
              message: 'They will no longer be able to receive legacy messages addressed to them.',
              onConfirm: async () => {
                await apiRequest(`/beneficiaries/${b.id}`, { method: 'DELETE' });
                toast('Beneficiary removed', 'success');
                await loadList(outlet);
              },
            });
          } }),
        ]),
      ]));
    });
  }
  if (!listCard) {
    const loading = outlet.querySelector('.loading-state');
    if (loading) loading.replaceWith(target); else outlet.appendChild(target);
  }
}

function openAddModal(outlet) {
  openModal({
    title: 'Add a beneficiary',
    submitLabel: 'Send Invite',
    fields: [
      { name: 'fullName', label: 'Full name' },
      { name: 'email', label: 'Email address', type: 'email' },
      { name: 'relationship', label: 'Relationship (e.g. Daughter, Spouse)' },
    ],
    onSubmit: async (values) => {
      const res = await apiRequest('/beneficiaries', { method: 'POST', body: values });
      toast(`Invite created for ${values.fullName}. Since this demo has no email delivery, share the invite link with them directly.`, 'success');
      await loadList(outlet);
      showInviteLink(res.inviteLink);
    },
  });
}

function showInviteLink(link) {
  const full = `${window.location.origin}${link}`;
  const backdrop = el('div', { class: 'modal-backdrop' });
  const input = el('input', { type: 'text', value: full, readonly: 'readonly' });
  const modal = el('div', { class: 'modal' }, [
    el('h3', { text: 'Invite link' }),
    el('p', { class: 'text-muted', text: 'This MVP does not send real emails (see README). Share this link with the invitee so they can claim access after creating an account with the matching email.' }),
    el('div', { class: 'field' }, [input]),
    el('div', { class: 'modal-actions' }, [el('button', { class: 'btn', text: 'Close', onclick: () => backdrop.remove() })]),
  ]);
  backdrop.appendChild(modal);
  document.body.appendChild(backdrop);
}
