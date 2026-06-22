import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,            // 监听 0.0.0.0，让容器/远程可访问（同 --host）
    allowedHosts: true,    // 允许任意 Host 头（部署到 quchiai 等内部平台需要）
    // 远程平台用域名访问前端时，Vite 默认只放行 localhost 会拦截；这里放开。
  },
});
