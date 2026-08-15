'use strict';

const routes = [];

export function registerRoute(pattern, handler) {
  routes.push({ pattern, handler });
}

function matchRoute(hash) {
  for (const r of routes) {
    if (r.pattern instanceof RegExp) {
      const m = hash.match(r.pattern);
      if (m) return { handler: r.handler, params: m.slice(1) };
    } else if (r.pattern === hash) {
      return { handler: r.handler, params: [] };
    }
  }
  return null;
}

export function navigate(hash) {
  if (window.location.hash === hash) {
    render();
  } else {
    window.location.hash = hash;
  }
}

function render() {
  const hash = window.location.hash.replace(/^#/, '') || '/dashboard';
  const match = matchRoute(hash);
  const outlet = document.getElementById('route-outlet');
  if (!match) {
    if (outlet) outlet.textContent = 'Page not found.';
    return;
  }
  match.handler(...match.params);
}

export function startRouter() {
  window.addEventListener('hashchange', render);
  render();
}

export function currentPath() {
  return window.location.hash.replace(/^#/, '') || '/dashboard';
}
