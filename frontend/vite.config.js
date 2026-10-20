import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import process from 'node:process'

const backendTarget = process.env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000'
const apiProxy = { '/api': backendTarget }

export default defineConfig({
  plugins: [react()],
  server: { proxy: apiProxy },
  preview: { proxy: apiProxy },
})
