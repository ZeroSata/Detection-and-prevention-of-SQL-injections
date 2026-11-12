import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Прокси /api -> backend: в dev-режиме на http://127.0.0.1:8000,
// в docker compose nginx делает то же самое (frontend/nginx/nginx.conf).
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
  preview: {
    host: true,
    port: 4173,
    proxy: { '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true } },
  },
})
