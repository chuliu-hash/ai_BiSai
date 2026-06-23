// 后端 API 客户端。
// BASE 地址从 frontend/.env 的 VITE_API_BASE 读取（Vite 注入），未配置时回退到本机默认。
// 改后端端口/换部署机器时，改 frontend/.env 即可，无需动代码。

const BASE = (import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000').replace(/\/+$/, '');

export function getBase() {
  return BASE;
}

async function handle(res) {
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (!res.ok) {
    const detail = (body && body.detail) || `HTTP ${res.status}`;
    const err = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

export async function health() {
  // 超时短一些，连接状态指示用
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 4000);
  try {
    const res = await fetch(`${getBase()}/`, { signal: ctrl.signal });
    return await handle(res);
  } finally {
    clearTimeout(t);
  }
}

export async function listGroups() {
  const res = await fetch(`${getBase()}/api/groups`);
  const body = await handle(res);
  return body.groups || [];
}

// 攻击：上传 JSON → 返回解析出的样本列表（每项含 user_prompt/context/judge_rule）
// limit: 0 = 不截断拿全量（交由前端分批）；>0 = 截断到前 N 条
export async function uploadAttack(file, limit = 0) {
  const fd = new FormData();
  fd.append('file', file);
  const url = new URL(`${getBase()}/api/upload/attack`);
  url.searchParams.set('limit', String(limit));
  const res = await fetch(url, { method: 'POST', body: fd });
  return handle(res);
}

// 攻击：单条测试。sample = {user_prompt, context, judge_rule}
export async function attackNoDefense(sample) {
  const { user_prompt, context = '', judge_rule = '' } = sample;
  const res = await fetch(`${getBase()}/api/attack/no_defense`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_prompt, context, judge_rule }),
  });
  return handle(res);
}

export async function attackWithShield(sample, { sensitivity = 'low', enableRag = false } = {}) {
  const { user_prompt, context = '', judge_rule = '' } = sample;
  const res = await fetch(`${getBase()}/api/attack/with_shield`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_prompt, context, judge_rule, sensitivity, enable_rag: enableRag }),
  });
  return handle(res);
}

// 防御：上传 ZIP 整合到 defend_group/<team>/
export async function uploadDefense(file, team) {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('team', team);
  const res = await fetch(`${getBase()}/api/upload/defense`, { method: 'POST', body: fd });
  return handle(res);
}

// 防御：调用某队伍 Detect
export async function detect(team, userPrompt) {
  const res = await fetch(`${getBase()}/detect/${encodeURIComponent(team)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_prompt: userPrompt }),
  });
  return handle(res); // 纯整数 0/1
}
