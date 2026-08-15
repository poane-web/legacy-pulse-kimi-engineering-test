'use strict';

import { apiRequest, setAccessToken, setUnauthorizedHandler } from './api.js';
import { getUser, setUser, onUserChange } from './state.js';
import { registerRoute, startRouter, navigate, currentPath } from './router.js';
import { renderShell } from './layout.js';
import { renderLogin, renderRegister } from './pages/auth.js';
import { renderDashboard } from './pages/dashboard.js';
import { renderProfile } from './pages/profile.js';
import { renderBeneficiaries } from './pages/beneficiaries.js';
import { renderTrustedContacts } from './pages/trustedContacts.js';
import { renderMemories } from './pages/memories.js';
import { renderTimeline } from './pages/timeline.js';
import { renderDocuments } from './pages/documents.js';
import { renderPhotos } from './pages/photos.js';
import { renderLegacyMessages } from './pages/legacyMessages.js';
import { renderInbox } from './pages/inbox.js';
import { renderNotifications } from './pages/notifications.js';
import { renderSecurity } from './pages/security.js';
import { renderAudit } from './pages/audit.js';
import { renderSearch } from './pages/search.js';
import { renderAdminDashboard, renderAdminAuditLogs } from './pages/admin.js';
import { renderClaimInvite } from './pages/claimInvite.js';

let authScreen = 'login'; // 'login' | 'register'

function showAuthedApp() {
  const outlet = renderShell(logout);
  registerAppRoutes(outlet);
  startRouter();
}

function registerAppRoutes(outlet) {
  registerRoute('/dashboard', () => renderDashboard(outlet));
  registerRoute('/profile', () => renderProfile(outlet));
  registerRoute('/beneficiaries', () => renderBeneficiaries(outlet));
  registerRoute('/trusted-contacts', () => renderTrustedContacts(outlet));
  registerRoute('/memories', () => renderMemories(outlet));
  registerRoute('/timeline', () => renderTimeline(outlet));
  registerRoute('/documents', () => renderDocuments(outlet));
  registerRoute('/photos', () => renderPhotos(outlet));
  registerRoute('/legacy-messages', () => renderLegacyMessages(outlet));
  registerRoute('/inbox', () => renderInbox(outlet));
  registerRoute('/notifications', () => renderNotifications(outlet));
  registerRoute('/security', () => renderSecurity(outlet, logout));
  registerRoute('/audit', () => renderAudit(outlet));
  registerRoute('/search', () => renderSearch(outlet));
  registerRoute(/^\/claim-invite/, () => renderClaimInvite(outlet));
  registerRoute('/admin', () => {
    if (getUser().role !== 'admin') return navigate('/dashboard');
    renderAdminDashboard(outlet);
  });
  registerRoute('/admin/audit-logs', () => {
    if (getUser().role !== 'admin') return navigate('/dashboard');
    renderAdminAuditLogs(outlet);
  });
}

function showLogin() {
  authScreen = 'login';
  renderLogin(() => { showAuthedApp(); navigate('/dashboard'); }, () => { showRegister(); });
}
function showRegister() {
  authScreen = 'register';
  renderRegister(() => { showAuthedApp(); navigate('/dashboard'); }, () => { showLogin(); });
}

async function logout() {
  try { await apiRequest('/auth/logout', { method: 'POST' }); } catch (e) { /* best effort */ }
  setAccessToken(null);
  setUser(null);
  window.location.hash = '';
  showLogin();
}

setUnauthorizedHandler(() => {
  setAccessToken(null);
  setUser(null);
  showLogin();
});

async function bootstrap() {
  // Attempt a silent refresh on load — if the user has a valid refresh
  // cookie from a previous session, this restores their session without
  // requiring them to log in again.
  try {
    const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include', headers: { 'X-Legacy-Pulse-Client': '1' } });
    if (res.ok) {
      const data = await res.json();
      setAccessToken(data.accessToken);
      const me = await apiRequest('/auth/me');
      setUser(me.user);
      showAuthedApp();
      return;
    }
  } catch (e) { /* fall through to login */ }
  showLogin();
}

bootstrap();
