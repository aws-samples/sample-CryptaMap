import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    // Dev-only convenience: forward /api/* to a locally running
    // `cryptamap serve --demo --port 8787` (or --dir ./out --port 8787) so
    // `npm run dev` gets live-reload for the dashboard while still exercising
    // the real AI Agent backend. Not used in production — the built dashboard
    // is served BY cryptamap serve itself, same-origin, no proxy involved.
    proxy: {
      '/api': 'http://127.0.0.1:8787',
    },
  },
  build: {
    outDir: 'dist',
    // Do not ship source maps in production builds — they expose full app
    // source. Opt in for local debugging via VITE_SOURCEMAP=true.
    sourcemap: process.env.VITE_SOURCEMAP === 'true',
    rollupOptions: {
      output: {
        manualChunks: {
          // Split the large Cloudscape bundle off the main app chunk.
          // (html2pdf.js is already code-split via its dynamic import in
          // ExportButton, so it lands in its own async chunk on demand.)
          cloudscape: [
            '@cloudscape-design/components',
            '@cloudscape-design/global-styles',
            '@cloudscape-design/collection-hooks',
          ],
          react: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
});
