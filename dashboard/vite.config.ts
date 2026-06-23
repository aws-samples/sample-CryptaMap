import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
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
