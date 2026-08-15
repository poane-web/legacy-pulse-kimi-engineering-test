'use strict';

import { el, clear } from './dom.js';
import { navigate, currentPath } from './router.js';
import { getUser } from './state.js';

const OWNER_NAV = [
  { group: 'Overview', items: [
    { path: '/dashboard', label: 'Dashboard', icon: '🏠' },
    { path: '/profile', label: 'My Profile', icon: '👤' },
    { path: '/search', label: 'Search', icon: '🔍' },
  ] },
  { group: 'Legacy', items: [
    { path: '/memories', label: 'Memories & Stories', icon: '📖' },
    { path: '/timeline', label: 'Life Timeline', icon: '🕰️' },
    { path: '/documents', label: 'Documents', icon: '📄' },
    { path: '/photos', label: 'Photos', icon: '🖼️' },
    { path: '/legacy-messages', label: 'Legacy Messages', icon: '💌' },
  ] },
  { group: 'People', items: [
    { path: '/beneficiaries', label: 'Beneficiaries', icon: '👪' },
    { path: '/trusted-contacts', label: 'Trusted Contacts', icon: '🤝' },
    { path: '/inbox', label: 'Messages For Me', icon: '📥' },
  ] },
  { group: 'Account', items: [
    { path: '/notifications', label: 'Notifications', icon: '🔔' },
    { path: '/security', label: 'Security Settings', icon: '🔒' },
    { path: '/audit', label: 'My Activity Log', icon: '📜' },
  ] },
];

const ADMIN_NAV = [
  { group: 'Admin', items: [
    { path: '/admin', label: 'Platform Dashboard', icon: '🛠️' },
    { path: '/admin/audit-logs', label: 'Audit Logs', icon: '📜' },
  ] },
  { group: 'Account', items: [
    { path: '/security', label: 'Security Settings', icon: '🔒' },
  ] },
];

function buildNav(onNavigate) {
  const user = getUser();
  const groups = user && user.role === 'admin' ? ADMIN_NAV : OWNER_NAV;
  const active = currentPath();

  return groups.map((g) => el('div', { class: 'nav-group' }, [
    el('h4', { text: g.group }),
    ...g.items.map((item) => el('div', {
      class: `nav-link${active === item.path ? ' active' : ''}`,
      onclick: () => { onNavigate(); navigate(item.path); },
    }, [el('span', { text: item.icon }), el('span', { text: item.label })])),
  ]));
}

export function renderShell(onLogout) {
  const app = document.getElementById('app');
  clear(app);

  const sidebar = el('div', { class: 'sidebar', id: 'sidebar' }, [
    el('div', { class: 'brand' }, [el('span', { class: 'dot' }), el('span', { text: 'Legacy Pulse' })]),
    ...buildNav(() => sidebar.classList.remove('open')),
    el('div', { class: 'sidebar-footer' }, [
      el('div', { text: (getUser() || {}).fullName || '' }),
      el('div', { text: (getUser() || {}).email || '' }),
      el('button', { class: 'btn secondary small mt-2', text: 'Log out', onclick: onLogout }),
    ]),
  ]);

  const mobileTopbar = el('div', { class: 'mobile-topbar' }, [
    el('div', { class: 'brand' }, [el('span', { class: 'dot' }), el('span', { text: 'Legacy Pulse' })]),
    el('button', { text: '☰ Menu', onclick: () => sidebar.classList.toggle('open') }),
  ]);

  const outlet = el('div', { id: 'route-outlet' });
  const main = el('div', { class: 'main' }, [outlet]);

  const shell = el('div', { class: 'app-shell' }, [sidebar, el('div', { style: 'flex:1; min-width:0;' }, [mobileTopbar, main])]);
  app.appendChild(shell);

  return outlet;
}

export function refreshShellNav() {
  const shellApp = document.getElementById('app');
  if (shellApp && document.getElementById('sidebar')) {
    // Re-render just to update active states on navigation; cheap given app size.
  }
}

export function pageHeader(title, subtitle, actions = []) {
  return el('div', { class: 'topbar' }, [
    el('div', {}, [
      el('h1', { text: title }),
      subtitle ? el('div', { class: 'subtitle', text: subtitle }) : null,
    ]),
    actions.length ? el('div', { style: 'display:flex; gap:0.5rem;' }, actions) : null,
  ]);
}
