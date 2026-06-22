import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// base 路径：远程平台通过 /proxy/<port>/ 反代时，必须让资源 URL 带上此前缀，
// 否则浏览器按绝对路径 /src/main.jsx 请求会丢前缀 → 404 → 白屏。
//
// 配置方式（任选，优先级从高到低）：
//   1. 环境变量 BASE_URL （shell 导出）
//   2. frontend/.env 里的 BASE_URL= （推荐，避免命令行被 shell 路径转换污染）
// 本地开发不设（默认 '/'）；远程平台在 .env 写 BASE_URL=/proxy/5173/
function resolveBase(mode) {
  const env = loadEnv(mode, process.cwd(), '');
  let base = (process.env.BASE_URL || env.BASE_URL || '/').trim();
  // 防御：Windows Git Bash 会把 /proxy/5173/ 误展开成 C:\Program Files\Git\proxy\5173\
  // 检测并剥离这种污染，还原成纯净的反代前缀
  const m = base.match(/[A-Z]:\\[^/]*\\((?:proxy|src|assets).*)/i);
  if (m) base = '/' + m[1].replace(/\\/g, '/');
  if (base !== '/' && !base.startsWith('/')) base = '/' + base;
  if (base !== '/' && !base.endsWith('/')) base += '/';
  return base;
}

export default defineConfig(({ mode }) => ({
  base: resolveBase(mode),
  plugins: [react()],
  server: {
    host: true,            // 监听 0.0.0.0，让容器/远程可访问（同 --host）
    allowedHosts: true,    // 允许任意 Host 头（部署到 quchiai 等内部平台需要）
  },
}));
