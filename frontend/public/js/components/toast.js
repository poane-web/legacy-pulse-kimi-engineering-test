'use strict';

import { el } from '../dom.js';

export function toast(message, type = 'info') {
  const region = document.getElementById('toast-region');
  const node = el('div', { class: `toast ${type}`, text: message });
  region.appendChild(node);
  setTimeout(() => {
    node.remove();
  }, 4200);
}
