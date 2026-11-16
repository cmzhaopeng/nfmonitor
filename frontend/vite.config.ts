import {defineConfig} from 'vite'
import react from '@vitejs/plugin-react'

// 开发时先跑 `nfmonitor serve`，/api 代理过去。
export default defineConfig({
  plugins: [react()],
  server: {proxy: {'/api': 'http://127.0.0.1:8787'}},
})
