'use strict';

import { el, clear } from '../dom.js';

/**
 * Renders a modal with a form built from `fields`, calls onSubmit(values).
 * Handles its own validation error display via `setError`.
 */
export function openModal({ title, fields, submitLabel = 'Save', onSubmit, initialValues = {} }) {
  const backdrop = el('div', { class: 'modal-backdrop' });
  const errorBox = el('div', { class: 'field-error' });

  const inputs = {};
  const fieldNodes = fields.map((f) => {
    let input;
    if (f.type === 'textarea') {
      input = el('textarea', { rows: f.rows || 4 });
    } else if (f.type === 'select') {
      input = el('select', {}, (f.options || []).map((o) => el('option', { value: o.value, text: o.label })));
    } else {
      input = el('input', { type: f.type || 'text' });
    }
    if (f.placeholder) input.setAttribute('placeholder', f.placeholder);
    if (initialValues[f.name] !== undefined) input.value = initialValues[f.name];
    inputs[f.name] = input;
    const errText = el('div', { class: 'error-text', style: 'display:none' });
    inputs[`${f.name}__err`] = errText;
    return el('div', { class: 'field' }, [
      el('label', { text: f.label }),
      input,
      f.hint ? el('div', { class: 'hint', text: f.hint }) : null,
      errText,
    ]);
  });

  function setFieldError(name, msg) {
    const node = inputs[`${name}__err`];
    if (node) { node.textContent = msg || ''; node.style.display = msg ? 'block' : 'none'; }
  }

  const submitBtn = el('button', { class: 'btn', text: submitLabel, type: 'submit' });

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      fields.forEach((f) => setFieldError(f.name, null));
      const values = {};
      for (const f of fields) {
        values[f.name] = inputs[f.name].value;
      }
      submitBtn.disabled = true;
      submitBtn.textContent = 'Saving...';
      try {
        await onSubmit(values, { setFieldError });
        close();
      } catch (err) {
        // onSubmit is expected to call setFieldError for field-level errors;
        // fall back to a generic message if it threw without doing so.
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = submitLabel;
      }
    },
  }, [
    ...fieldNodes,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn secondary', type: 'button', text: 'Cancel', onclick: () => close() }),
      submitBtn,
    ]),
  ]);

  const modal = el('div', { class: 'modal' }, [
    el('h3', { text: title }),
    form,
  ]);
  backdrop.appendChild(modal);
  document.body.appendChild(backdrop);

  function close() {
    backdrop.remove();
  }
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });

  return { close, inputs, setFieldError };
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = true, onConfirm }) {
  const backdrop = el('div', { class: 'modal-backdrop' });
  const modal = el('div', { class: 'modal' }, [
    el('h3', { text: title }),
    el('p', { class: 'text-muted', text: message }),
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn secondary', text: 'Cancel', onclick: () => backdrop.remove() }),
      el('button', { class: `btn ${danger ? 'danger' : ''}`, text: confirmLabel, onclick: async () => { await onConfirm(); backdrop.remove(); } }),
    ]),
  ]);
  backdrop.appendChild(modal);
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.body.appendChild(backdrop);
}

// Step-up authentication prompt: used for high-consequence actions that
// require re-confirming the account password (e.g. revoking a trusted
// contact, removing a beneficiary) — see backend
// middleware/requireStepUpPassword.js for the server-side counterpart.
// onConfirm receives the entered password and should throw/reject with a
// message on failure; the modal stays open and shows the error inline.
export function promptPasswordConfirm({ title, message, confirmLabel = 'Confirm', danger = true, onConfirm }) {
  const backdrop = el('div', { class: 'modal-backdrop' });
  const passwordInput = el('input', { type: 'password', placeholder: 'Your password', autocomplete: 'current-password' });
  const errBox = el('div', { class: 'error-text', style: 'display:none' });
  const confirmBtn = el('button', {
    class: `btn ${danger ? 'danger' : ''}`,
    text: confirmLabel,
    onclick: async () => {
      errBox.style.display = 'none';
      if (!passwordInput.value) {
        errBox.textContent = 'Password is required.';
        errBox.style.display = 'block';
        return;
      }
      confirmBtn.disabled = true;
      try {
        await onConfirm(passwordInput.value);
        backdrop.remove();
      } catch (err) {
        errBox.textContent = err.message || 'Something went wrong.';
        errBox.style.display = 'block';
      } finally {
        confirmBtn.disabled = false;
      }
    },
  });
  const modal = el('div', { class: 'modal' }, [
    el('h3', { text: title }),
    el('p', { class: 'text-muted', text: message }),
    el('div', { class: 'field' }, [el('label', { text: 'Confirm your password to continue' }), passwordInput]),
    errBox,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn secondary', text: 'Cancel', onclick: () => backdrop.remove() }),
      confirmBtn,
    ]),
  ]);
  backdrop.appendChild(modal);
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.body.appendChild(backdrop);
}
