/**
 * Static portfolio demo build: `npx vite build --config vite.demo.config.ts`.
 * Same app, but booted from src/demo/main.tsx so every API call is answered in the browser.
 * The regular dev server and build (vite.config.ts) are untouched.
 */
import { defineConfig, mergeConfig } from 'vite';
import baseConfig from './vite.config';

export default mergeConfig(
  baseConfig,
  defineConfig({
    plugins: [
      {
        name: 'securepam-demo-entry',
        transformIndexHtml: { order: 'pre', handler: (html) => html.replace('/src/main.tsx', '/src/demo/main.tsx') },
      },
    ],
    build: { outDir: 'dist-demo' },
  }),
);
