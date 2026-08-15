'use strict';

import { el, clear, loadingState, formatDateTime } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { toast } from '../components/toast.js';
import { confirmDialog } from '../components/modal.js';

export async function renderSecurity(outlet, onForceLogout) {
  clear(outlet);
  outlet.appendChild(pageHeader('Security Settings', 'Manage your password and active sessions.'));

  const currentPw = el('input', { type: 'password', autocomplete: 'current-password' });
  const newPw = el('input', { type: 'password', autocomplete: 'new-password' });
  const pwErr = el('div', { class: 'error-text', style: 'display:none' });
  const pwBtn = el('button', { class: 'btn', type: 'submit', text: 'Update Password' });

  const pwForm = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      pwErr.style.display = 'none';
      pwBtn.disabled = true;
      pwBtn.textContent = 'Updating...';
      try {
        await apiRequest('/users/password', { method: 'PUT', body: { currentPassword: currentPw.value, newPassword: newPw.value } });
        toast('Password updated. Other sessions were signed out.', 'success');
        currentPw.value = '';
        newPw.value = '';
      } catch (err) {
        pwErr.textContent = err.message;
        pwErr.style.display = 'block';
      } finally {
        pwBtn.disabled = false;
        pwBtn.textContent = 'Update Password';
      }
    },
  }, [
    el('div', { class: 'field' }, [el('label', { text: 'Current password' }), currentPw]),
    el('div', { class: 'field' }, [el('label', { text: 'New password' }), newPw, el('div', { class: 'hint', text: 'At least 10 characters, including a letter and a number.' })]),
    pwErr,
    pwBtn,
  ]);

  outlet.appendChild(el('div', { class: 'card' }, [
    el('h2', { style: 'font-size:1.05rem;margin-top:0;', text: 'Change Password' }),
    pwForm,
  ]));

  const sessionsCard = el('div', { class: 'card mt-2' }, [loadingState('Loading sessions...')]);
  outlet.appendChild(sessionsCard);

  try {
    const data = await apiRequest('/security/sessions');
    clear(sessionsCard);
    sessionsCard.appendChild(el('div', { class: 'section-header' }, [
      el('h2', { text: 'Active Sessions' }),
      el('button', { class: 'btn small danger', text: 'Sign out everywhere', onclick: () => {
        confirmDialog({
          title: 'Sign out of all sessions?',
          message: "You'll be signed out of every device, including this one.",
          onConfirm: async () => {
            await apiRequest('/security/sessions/revoke-all', { method: 'POST' });
            toast('Signed out everywhere.', 'success');
            onForceLogout();
          },
        });
      } }),
    ]));
    data.sessions.forEach((s) => {
      sessionsCard.appendChild(el('div', { class: 'list-item' }, [
        el('div', {}, [
          el('div', { class: 'title', text: 'Active session' }),
          el('div', { class: 'meta', text: `Started ${formatDateTime(s.createdAt)} · Expires ${formatDateTime(s.expiresAt)}` }),
        ]),
      ]));
    });
  } catch (err) {
    clear(sessionsCard);
    sessionsCard.appendChild(el('div', { text: err.message }));
  }
}
