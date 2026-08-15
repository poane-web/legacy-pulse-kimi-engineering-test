'use strict';

import { el, clear, loadingState, emptyState, formatDate } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { openModal, confirmDialog } from '../components/modal.js';
import { toast } from '../components/toast.js';

export async function renderLegacyMessages(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('Legacy Messages', 'Messages for specific beneficiaries, released under conditions you control.', [
    el('button', { class: 'btn', text: '+ New Message', onclick: () => openEditor(outlet) }),
  ]));
  outlet.appendChild(loadingState());

  let messagesRes, beneficiariesRes;
  try {
    [messagesRes, beneficiariesRes] = await Promise.all([apiRequest('/legacy-messages'), apiRequest('/beneficiaries')]);
  } catch (err) {
    outlet.querySelector('.loading-state')?.remove();
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: err.message })]));
    return;
  }
  outlet.querySelector('.loading-state')?.remove();

  if (beneficiariesRes.beneficiaries.length === 0) {
    outlet.appendChild(el('div', { class: 'card' }, [
      emptyState('👪', 'Add a beneficiary first', 'Legacy messages must be addressed to a beneficiary. Add one from the Beneficiaries page.'),
    ]));
    return;
  }

  const card = el('div', { class: 'card' });
  if (messagesRes.messages.length === 0) {
    card.appendChild(emptyState('💌', 'No legacy messages yet', 'Write your first message to a beneficiary.'));
  } else {
    const beneficiaryById = Object.fromEntries(beneficiariesRes.beneficiaries.map((b) => [b.id, b]));
    messagesRes.messages.forEach((m) => {
      const beneficiary = beneficiaryById[m.beneficiaryId];
      card.appendChild(el('div', { class: 'list-item' }, [
        el('div', { style: 'flex:1;min-width:0;' }, [
          el('div', { class: 'title', text: m.title }),
          el('div', { class: 'meta', text: `To: ${beneficiary ? beneficiary.fullName : 'Unknown'} · ${releaseLabel(m)}` }),
          m.status === 'released' ? el('div', { class: 'body-text', text: m.body }) : el('div', { class: 'text-muted mt-1', text: '(Content hidden until released — this is a preview of your own message.)' }),
        ]),
        el('div', { class: 'actions' }, [
          el('span', { class: `badge ${m.status}`, text: m.status }),
          m.status === 'pending' ? el('button', { class: 'btn small secondary', text: 'Edit', onclick: () => openEditor(outlet, m, beneficiariesRes.beneficiaries) }) : null,
          m.status === 'pending' ? el('button', { class: 'btn small danger', text: 'Delete', onclick: () => {
            confirmDialog({
              title: `Delete "${m.title}"?`,
              message: 'This cannot be undone.',
              onConfirm: async () => {
                await apiRequest(`/legacy-messages/${m.id}`, { method: 'DELETE' });
                toast('Deleted', 'success');
                renderLegacyMessages(outlet);
              },
            });
          } }) : null,
        ]),
      ]));
    });
  }
  outlet.appendChild(card);
}

function releaseLabel(m) {
  if (m.releaseType === 'immediate') return 'Released immediately';
  if (m.releaseType === 'scheduled_date') return `Releases ${formatDate(m.releaseAt)}`;
  return `Releases after ${m.requiredConfirmations} trusted contacts confirm`;
}

function openEditor(outlet, existing, beneficiaries) {
  openModal({
    title: existing ? 'Edit Legacy Message' : 'New Legacy Message',
    submitLabel: existing ? 'Save Changes' : 'Create Message',
    initialValues: existing ? { title: existing.title, body: existing.body, beneficiaryId: existing.beneficiaryId, releaseType: existing.releaseType, releaseAt: existing.releaseAt ? existing.releaseAt.slice(0, 10) : '' } : {},
    fields: [
      { name: 'title', label: 'Title' },
      { name: 'beneficiaryId', label: 'Beneficiary', type: 'select', options: (beneficiaries || []).map((b) => ({ value: b.id, label: `${b.fullName} (${b.relationship || 'Beneficiary'})` })) },
      { name: 'releaseType', label: 'Release condition', type: 'select', options: [
        { value: 'scheduled_date', label: 'On a specific date' },
        { value: 'trusted_contact_confirmation', label: 'When trusted contacts confirm my passing' },
        { value: 'immediate', label: 'Release immediately' },
      ] },
      { name: 'releaseAt', label: 'Release date (if applicable)', type: 'date' },
      { name: 'body', label: 'Message', type: 'textarea', rows: 8 },
    ],
    onSubmit: async (values, { setFieldError }) => {
      if (values.releaseType === 'scheduled_date' && !values.releaseAt) {
        setFieldError('releaseAt', 'Required for a date-based release');
        throw new Error('validation');
      }
      const body = {
        title: values.title,
        body: values.body,
        beneficiaryId: Number(values.beneficiaryId),
        releaseType: values.releaseType,
        releaseAt: values.releaseType === 'scheduled_date' ? new Date(values.releaseAt).toISOString() : null,
      };
      if (existing) {
        await apiRequest(`/legacy-messages/${existing.id}`, { method: 'PUT', body: { title: body.title, body: body.body, releaseAt: body.releaseAt } });
      } else {
        await apiRequest('/legacy-messages', { method: 'POST', body });
      }
      toast(existing ? 'Updated' : 'Message created', 'success');
      renderLegacyMessages(outlet);
    },
  });
}
