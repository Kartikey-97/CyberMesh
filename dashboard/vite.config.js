import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/events': 'http://localhost:8080',
      '/metrics': 'http://localhost:8080',
      '/policy': 'http://localhost:8080',
      '/mode': 'http://localhost:8080',
      '/revoke': 'http://localhost:8080'
    }
  }
})
