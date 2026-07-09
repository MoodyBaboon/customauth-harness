import { defineConfig } from 'vite';

// GitHub Pages serves from https://<user>.github.io/<repo>/ , so the Pages build must resolve
// assets under /<repo>/. Set PAGES_BASE only for that build:  PAGES_BASE=/my-repo/ npm run build
// Dev (npm run dev) and any root-hosted deploy use '/', so localhost:5173 stays clean.
export default defineConfig({
  base: process.env.PAGES_BASE || '/',
  build: { target: 'es2022' },
  server: { port: 5173, strictPort: true },
});
