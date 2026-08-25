import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // Core React + Router
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          // Recharts (large charting library)
          'vendor-charts': ['recharts'],
          // ReactFlow (graph visualization)
          'vendor-graph': ['@xyflow/react'],
          // Zustand (state management)
          'vendor-store': ['zustand'],
        },
      },
    },
  },
})
