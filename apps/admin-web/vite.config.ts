import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 管理后台仅通过独立管理面域名/端口提供服务；开发时代理到本地 Go API。
// 代理前缀必须是 ^/admin/v1（精确到版本段）：
//   若用 /admin 前缀，会把 SPA 路由 /admins（管理员页）也转发到 API 导致裸 404。
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '^/admin/v1': {
        target: 'http://127.0.0.1:8081',
        changeOrigin: false,
      },
    },
  },
})
