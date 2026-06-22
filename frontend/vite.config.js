import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// 解析 base 路径（资源 URL 前缀）。
// 远程平台常通过 https://<域名>/proxy/<port>/ 反代 dev server。
//   · 本地直接访问 http://localhost:5173       → BASE_URL=/
//   · 远程平台反代 .../proxy/5173/             → BASE_URL=/proxy/5173/
// 配置从 frontend/.env 的 BASE_URL 读（避免 shell 路径转换污染）。
function resolveBase(mode) {
  const env = loadEnv(mode, process.cwd(), '');
  let base = (process.env.BASE_URL || env.BASE_URL || '/').trim();
  // 防御：Windows Git Bash 会把 /proxy/5173/ 误展开成 C:\Program Files\Git\proxy\5173\
  const m = base.match(/[A-Z]:\\[^/]*\\((?:proxy|src|assets).*)/i);
  if (m) base = '/' + m[1].replace(/\\/g, '/');
  if (base !== '/' && !base.startsWith('/')) base = '/' + base;
  if (base !== '/' && !base.endsWith('/')) base += '/';
  return base;
}

// 远程反代兼容插件：平台（如 quchiai）通过 /proxy/<port>/ 反代时，
// 转发给 Vite 的请求会带着这个前缀（/proxy/5173/src/main.jsx）。
// Vite 默认把它当未知路由 → 回退返回 index.html → 浏览器拿 HTML 当 JS → 白屏。
// 本中间件在 Vite 处理前剥离前缀，让 Vite 按 /src/main.jsx 正常响应。
// 剥离前缀由 PROXY_PREFIX 指定（默认从 BASE_URL 推导），与 base 解耦——
// 即使 base=/ 也能剥离，适配「平台自动重写绝对路径」的场景。
function stripBasePrefixPlugin(base, explicitPrefix) {
  let prefix = (explicitPrefix || base || '/').trim();
  if (prefix.endsWith('/')) prefix = prefix.slice(0, -1); // '/proxy/5173'
  return {
    name: 'strip-base-prefix',
    configureServer(server) {
      if (!prefix || prefix === '/') return;
      server.middlewares.use((req, res, next) => {
        const url = req.url || '';
        if (url.startsWith(prefix + '/')) {
          req.url = url.slice(prefix.length) || '/';
        } else if (url === prefix) {
          req.url = '/';
        }
        next();
      });
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const base = resolveBase(mode);
  // PROXY_PREFIX 单独控制请求剥离前缀；不填则用 base 推导。
  // 适配「base=/（让平台重写绝对路径）+ 平台转发带前缀请求」的组合：
  //   PROXY_PREFIX=/proxy/5173  BASE_URL=/
  const proxyPrefix = process.env.PROXY_PREFIX || env.PROXY_PREFIX || base;
  return {
    base,
    plugins: [react(), stripBasePrefixPlugin(base, proxyPrefix)],
    server: {
      host: true,            // 监听 0.0.0.0，让容器/远程可访问（同 --host）
      allowedHosts: true,    // 允许任意 Host 头（部署到 quchiai 等内部平台需要）
    },
  };
});
