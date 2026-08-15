// DOM helpers. `el()` builds elements from a lightweight hyperscript-style
// call, always assigning text content via `.textContent`, never
// `.innerHTML`, when the value is user-supplied — this is the app's XSS
// mitigation for stored content (see docs/THREAT_MODEL.md T14).
'use strict';

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'html_TRUSTED_ONLY') node.innerHTML = value; // used only for static, hard-coded icon markup, never user data
    else node.setAttribute(key, value);
  }
  const kids = Array.isArray(children) ? children : [children];
  for (const child of kids) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch (e) {
    return iso;
  }
}

export function formatDateTime(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return iso;
  }
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export function loadingState(label = 'Loading...') {
  return el('div', { class: 'loading-state' }, [
    el('div', { class: 'spinner' }),
    el('div', { text: label }),
  ]);
}

export function emptyState(icon, title, subtitle) {
  return el('div', { class: 'empty-state' }, [
    el('div', { class: 'icon', text: icon }),
    el('div', { text: title }),
    subtitle ? el('div', { class: 'text-muted mt-1', text: subtitle }) : null,
  ]);
}
