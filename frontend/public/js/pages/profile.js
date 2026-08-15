'use strict';

import { el, clear, loadingState } from '../dom.js';
import { apiRequest } from '../api.js';
import { pageHeader } from '../layout.js';
import { toast } from '../components/toast.js';
import { setUser, getUser } from '../state.js';
import { confirmDialog } from '../components/modal.js';

export async function renderProfile(outlet) {
  clear(outlet);
  outlet.appendChild(pageHeader('My Profile', 'This information is private to your account.'));
  outlet.appendChild(loadingState());

  let profile;
  try {
    const res = await apiRequest('/users/profile');
    profile = res.profile;
  } catch (err) {
    clear(outlet);
    outlet.appendChild(el('div', { class: 'card' }, [el('div', { text: `Could not load profile: ${err.message}` })]));
    return;
  }

  clear(outlet);
  outlet.appendChild(pageHeader('My Profile', 'This information is private to your account.'));

  const nameInput = el('input', { type: 'text', value: profile.fullName || '' });
  const dobInput = el('input', { type: 'date', value: profile.dateOfBirth ? profile.dateOfBirth.slice(0, 10) : '' });
  const phoneInput = el('input', { type: 'tel', value: profile.phone || '' });
  const bioInput = el('textarea', { rows: 4 }, [profile.bio || '']);
  bioInput.value = profile.bio || '';
  const saveBtn = el('button', { class: 'btn', type: 'submit', text: 'Save Changes' });

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';
      try {
        await apiRequest('/users/profile', {
          method: 'PUT',
          body: { fullName: nameInput.value, dateOfBirth: dobInput.value || null, phone: phoneInput.value || null, bio: bioInput.value || null },
        });
        setUser({ ...getUser(), fullName: nameInput.value });
        toast('Profile updated', 'success');
      } catch (err) {
        toast(err.message, 'error');
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Changes';
      }
    },
  }, [
    el('div', { class: 'form-row' }, [
      el('div', { class: 'field' }, [el('label', { text: 'Full name' }), nameInput]),
      el('div', { class: 'field' }, [el('label', { text: 'Date of birth' }), dobInput]),
    ]),
    el('div', { class: 'field' }, [el('label', { text: 'Phone' }), phoneInput]),
    el('div', { class: 'field' }, [el('label', { text: 'Bio' }), bioInput]),
    saveBtn,
  ]);

  outlet.appendChild(el('div', { class: 'card' }, [form]));

  outlet.appendChild(el('div', { class: 'card mt-2' }, [
    el('h2', { style: 'font-size:1.05rem;margin-top:0;', text: 'Account email' }),
    el('div', { class: 'text-muted', text: profile.email }),
    el('div', { class: 'text-muted mt-1', text: `Member since ${new Date(profile.createdAt).toLocaleDateString()}` }),
  ]));

  outlet.appendChild(el('div', { class: 'card mt-2', style: 'border-color:#e3c9c9;' }, [
    el('h2', { style: 'font-size:1.05rem;margin-top:0;color:#a13f3f;', text: 'Danger zone' }),
    el('p', { class: 'text-muted', text: 'Deleting your account permanently removes your memories, documents, photos, timeline, and legacy messages. This cannot be undone.' }),
    el('button', {
      class: 'btn danger', text: 'Delete my account',
      onclick: () => {
        confirmDialog({
          title: 'Delete your account?',
          message: 'This action is permanent. Type your password to confirm on the next screen.',
          confirmLabel: 'Continue',
          onConfirm: () => promptPasswordAndDelete(),
        });
      },
    }),
  ]));
}

function promptPasswordAndDelete() {
  const backdrop = el('div', { class: 'modal-backdrop' });
  const pwInput = el('input', { type: 'password', placeholder: 'Current password' });
  const errBox = el('div', { class: 'error-text', style: 'display:none' });
  const modal = el('div', { class: 'modal' }, [
    el('h3', { text: 'Confirm account deletion' }),
    el('div', { class: 'field' }, [el('label', { text: 'Password' }), pwInput]),
    errBox,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn secondary', text: 'Cancel', onclick: () => backdrop.remove() }),
      el('button', { class: 'btn danger', text: 'Permanently delete', onclick: async () => {
        try {
          await apiRequest('/users/me', { method: 'DELETE', body: { password: pwInput.value } });
          toast('Account deleted.', 'success');
          window.location.reload();
        } catch (err) {
          errBox.textContent = err.message;
          errBox.style.display = 'block';
        }
      } }),
    ]),
  ]);
  backdrop.appendChild(modal);
  document.body.appendChild(backdrop);
}
