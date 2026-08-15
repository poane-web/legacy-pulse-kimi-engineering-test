'use strict';

import { el, clear } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { toast } from '../components/toast.js';

export function renderClaimInvite(outlet) {
  clear(outlet);
  const params = new URLSearchParams(window.location.hash.split('?')[1] || '');
  const type = params.get('type') === 'trusted_contact' ? 'trusted_contact' : 'beneficiary';
  const token = params.get('token') || '';

  outlet.appendChild(pageHeader('Claim Your Invite', type === 'trusted_contact'
    ? 'Confirm you are a trusted contact for someone using Legacy Pulse.'
    : 'Confirm you are a beneficiary for someone using Legacy Pulse.'));

  const tokenInput = el('input', { type: 'text', value: token });
  const btn = el('button', { class: 'btn', text: 'Claim Invite', onclick: async () => {
    btn.disabled = true;
    try {
      const path = type === 'trusted_contact' ? '/trusted-contacts/claim' : '/beneficiaries/claim';
      const res = await apiRequest(path, { method: 'POST', body: { token: tokenInput.value } });
      toast(res.message, 'success');
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  } });

  outlet.appendChild(el('div', { class: 'card' }, [
    el('p', { class: 'text-muted', text: 'You must be logged in with the email address the invite was sent to.' }),
    el('div', { class: 'field' }, [el('label', { text: 'Invite token' }), tokenInput]),
    btn,
  ]));
}
