import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The browser is never the sandbox: all API calls use relative /api paths and
// Vite proxies them to Django in development. In production nginx does it.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    // The preview host is not localhost, so the dev server must accept it.
    allowedHosts: true,
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  preview: { host: '0.0.0.0', port: 4173, allowedHosts: true },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
