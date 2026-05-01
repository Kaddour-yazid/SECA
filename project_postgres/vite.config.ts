import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: false,
    watch: {
      ignored: [
        '**/backend/**',
        '**/desktop/**',
        '**/desktop-release/**',
        '**/docs/**',
        '**/dist/**',
        '**/.meilisearch-data/**',
        '**/__pycache__/**',
        '**/*.log',
        '**/*.pyc',
      ],
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: false,
  },
  optimizeDeps: {
    exclude: ['lucide-react'],
  },
});
