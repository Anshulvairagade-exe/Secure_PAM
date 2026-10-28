/**
 * Entry point for the static portfolio demo (built with vite.demo.config.ts).
 * Routes every API call to the in-browser demo adapter, then boots the normal app unchanged.
 */

import apiClient from '@/api/client';
import { demoAdapter } from './adapter';
import { DEMO_PASSWORD } from './data';

apiClient.defaults.adapter = demoAdapter;

// KeycloakProvider asks /auth/config with plain fetch; answer "dev mode" so the demo sign-in form shows.
const realFetch = window.fetch.bind(window);
window.fetch = (input, init) => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
  if (url.endsWith('/api/v1/auth/config')) {
    return Promise.resolve(new Response(JSON.stringify({ dev_mode: true }), { headers: { 'Content-Type': 'application/json' } }));
  }
  return realFetch(input, init);
};

const banner = document.createElement('div');
banner.setAttribute('role', 'note');
banner.style.cssText =
  'position:fixed;bottom:12px;left:50%;transform:translateX(-50%);z-index:9999;max-width:calc(100% - 32px);' +
  'padding:8px 14px;border-radius:999px;background:#1e293b;color:#f8fafc;font:500 12px/1.4 Inter,system-ui,sans-serif;' +
  'box-shadow:0 4px 16px rgba(0,0,0,.25);text-align:center';
banner.textContent =
  `Live demo with sample data · sign in as admin, operator, approver or auditor · password "${DEMO_PASSWORD}"`;
document.body.appendChild(banner);

void import('../main');
