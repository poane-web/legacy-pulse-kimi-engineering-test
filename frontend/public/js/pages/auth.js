'use strict';

import { el, clear } from '../dom.js';
import { apiRequest, setAccessToken, ApiError } from '../api.js';
import { setUser } from '../state.js';
import { toast } from '../components/toast.js';

function fieldError(container) {
  return el('div', { class: 'error-text', style: 'display:none' });
}

export function renderLogin(onSuccess, onShowRegister) {
  const app = document.getElementById('app');
  clear(app);

  const emailInput = el('input', { type: 'email', autocomplete: 'email', required: 'required' });
  const passwordInput = el('input', { type: 'password', autocomplete: 'current-password', required: 'required' });
  const errBox = el('div', { class: 'error-text', style: 'display:none;margin-bottom:0.75rem;' });
  const submitBtn = el('button', { class: 'btn block', type: 'submit', text: 'Log In' });

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      errBox.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Logging in...';
      try {
        const data = await apiRequest('/auth/login', { method: 'POST', skipAuth: true, body: { email: emailInput.value, password: passwordInput.value } });
        setAccessToken(data.accessToken);
        setUser(data.user);
        toast(`Welcome back, ${data.user.fullName.split(' ')[0]}.`, 'success');
        onSuccess();
      } catch (err) {
        errBox.textContent = err.message || 'Login failed';
        errBox.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Log In';
      }
    },
  }, [
    el('div', { class: 'field' }, [el('label', { text: 'Email' }), emailInput]),
    el('div', { class: 'field' }, [el('label', { text: 'Password' }), passwordInput]),
    errBox,
    submitBtn,
  ]);

  app.appendChild(el('div', { class: 'auth-shell' }, [
    el('div', { class: 'auth-card' }, [
      el('div', { class: 'brand' }, [el('span', { class: 'dot' }), el('span', { text: 'Legacy Pulse' })]),
      el('p', { class: 'text-muted', text: 'Sign in to preserve and manage your legacy.' }),
      form,
      el('div', { class: 'switch-link' }, [
        'New here? ',
        el('a', { href: '#', text: 'Create an account', onclick: (e) => { e.preventDefault(); onShowRegister(); } }),
      ]),
      el('div', { class: 'card mt-3', style: 'background:#faf8f4;' }, [
        el('div', { style: 'font-weight:600;font-size:0.85rem;', text: 'Demo accounts (seeded)' }),
        el('div', { class: 'text-muted', style: 'font-size:0.8rem;line-height:1.6;', text: 'owner@demo.legacypulse.test / DemoPass123!\nbeneficiary@demo.legacypulse.test / DemoPass123!\nadmin@demo.legacypulse.test / DemoPass123!' }),
      ]),
    ]),
  ]));
}

export function renderRegister(onSuccess, onShowLogin) {
  const app = document.getElementById('app');
  clear(app);

  const nameInput = el('input', { type: 'text', required: 'required' });
  const emailInput = el('input', { type: 'email', required: 'required' });
  const passwordInput = el('input', { type: 'password', required: 'required' });
  const errBox = el('div', { class: 'error-text', style: 'display:none;margin-bottom:0.75rem;' });
  const submitBtn = el('button', { class: 'btn block', type: 'submit', text: 'Create Account' });

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      errBox.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating account...';
      try {
        const data = await apiRequest('/auth/register', { method: 'POST', skipAuth: true, body: { fullName: nameInput.value, email: emailInput.value, password: passwordInput.value } });
        setAccessToken(data.accessToken);
        setUser(data.user);
        toast('Account created. Welcome to Legacy Pulse.', 'success');
        onSuccess();
      } catch (err) {
        errBox.textContent = err.message || 'Registration failed';
        errBox.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Account';
      }
    },
  }, [
    el('div', { class: 'field' }, [el('label', { text: 'Full name' }), nameInput]),
    el('div', { class: 'field' }, [el('label', { text: 'Email' }), emailInput]),
    el('div', { class: 'field' }, [
      el('label', { text: 'Password' }),
      passwordInput,
      el('div', { class: 'hint', text: 'At least 10 characters, including a letter and a number.' }),
    ]),
    errBox,
    submitBtn,
  ]);

  app.appendChild(el('div', { class: 'auth-shell' }, [
    el('div', { class: 'auth-card' }, [
      el('div', { class: 'brand' }, [el('span', { class: 'dot' }), el('span', { text: 'Legacy Pulse' })]),
      el('p', { class: 'text-muted', text: 'Create your account to start preserving your legacy.' }),
      form,
      el('div', { class: 'switch-link' }, [
        'Already have an account? ',
        el('a', { href: '#', text: 'Log in', onclick: (e) => { e.preventDefault(); onShowLogin(); } }),
      ]),
    ]),
  ]));
}
