# 大模型攻防赛平台（ai_bachang）

大模型安全与 Agent 智能体安全攻防比赛的评测平台：**前端控制台（React）+ 后端评测服务（FastAPI）**。前端负责语料上传、批量并发评测、结果展示；后端封装赛题的攻击评测与防御检测接口。

```
ai_bachang/
├── backend/         FastAPI 服务（攻击评测 + 防御检测，端口 8000）
├── frontend/        React + Vite 控制台（端口 5173）
└── test_assets/     测试语料 + 防御示例包 + 自动化脚本
```

---

## 一、快速开始

### 1. 启动后端

```bash
cd backend
# 方式 A：用预配置好的 modelshield 环境（推荐，已含全部依赖）
conda activate modelshield

# 方式 B：自建环境
pip install -r requirements.txt

python server.py
# → http://127.0.0.1:8000
```

依赖清单见 [`backend/requirements.txt`](backend/requirements.txt)。

后端依赖外部 LLM 服务，地址在 `backend/.env` 配置：
- `LLM_SERVER_URL` — 被攻击的目标模型（Qwen3）
- `INPUT_DETECTOR_API_URL` — 模盾输入检测 LLM
- `OUTPUT_DETECTOR_API_URL` — 模盾输出检测 LLM
- `EMBEDDING_API_URL` — RAG 向量服务（仅 `enable_rag=true` 时用）

### 2. 启动前端

```bash
cd frontend
npm install        # 首次
npm run dev
# → http://localhost:5173
```

后端地址由 `frontend/.env` 的 `VITE_API_BASE` 配置（默认 `http://127.0.0.1:8000`）。改后端端口/换部署机器时改这一行即可，改完重启 `npm run dev`。模板见 `frontend/.env.example`。

### 3. 使用

浏览器打开 `http://localhost:5173`，左侧栏切赛道：

| 赛道 | 流程 |
|------|------|
| **攻击** | 上传样本 JSON（user_prompt/context/judge_rule，全量返回）→ 选端点 → 开始测试（4 路并发分批 + 进度条 + 可取消）→ 结果分页浏览 |
| **防御** | 上传 ZIP 防御包 + 队名 → 选队伍 → 上传样本 JSON（取 user_prompt）→ 批量检测得 0/1 |

前端通过 `frontend/.env` 的 `VITE_API_BASE` 连接后端（默认 `http://127.0.0.1:8000`）。左侧栏底部有连接状态指示灯（绿/红点），每 8 秒自动复探。

---

## 二、文档导航

| 文档 | 内容 |
|------|------|
| [`backend/server_API.md`](backend/server_API.md) | **后端 API 完整说明**（所有端点、字段、错误码、调用示例） |
| [`backend/summary.md`](backend/summary.md) | 考题及规则总结（四大风险类型、评分机制） |
| [`backend/defend_group/README.md`](backend/defend_group/README.md) | 防御队伍提交规范（Detect 接口 + 目录结构） |

---

## 三、后端端点速览

| 方法 | 端点 | 说明 |
|------|------|------|
| `POST` | `/api/upload/attack?limit=0` | 上传攻击 JSON，全量返回样本列表（每条含 user_prompt/context/judge_rule；`limit=0` 不截断） |
| `POST` | `/api/upload/defense` | 上传防御 ZIP，整合到 `defend_group/<队名>/` |
| `POST` | `/api/attack/no_defense` | 无防护评测：样本(三字段分角色) → 裸 LLM |
| `POST` | `/api/attack/with_shield` | 模盾防护：输入检测(仅 user_prompt) →（RAG）→ 生成(三字段) → 输出检测 |
| `POST` | `/detect/{group}` | 调队伍 `Detect`，返回 0/1 |
| `GET`  | `/groups` · `/api/groups` | 列出已上传队伍 |
| `GET`  | `/` | 服务自描述 |

详见 [`backend/server_API.md`](backend/server_API.md)。

---

## 四、攻击 JSON 格式（样本对象数组）

每条样本是一个对象，含三字段：

```json
[
  {
    "user_prompt": "攻击 user prompt（送 LLM 的 {role:user}）",
    "context": "历史上下文（送前置 {role:user}；可选，为空则不插入）",
    "judge_rule": "评审规则/系统提示词（送 {role:system}；可选）"
  },
  { "user_prompt": "...", "context": "...", "judge_rule": "..." }
]
```

- **`user_prompt`** 必填；`context` / `judge_rule` 可选（缺省为空）。
- 也兼容「按队分组」`{队名: [样本对象,...]}` 形态（递归收集样本对象）。
- 模盾的输入/输出检测**只检 `user_prompt` 与模型回复**，不检 `context` / `judge_rule`（避免评审规则被误判为攻击）。
- 防御检测（`/detect/{group}`）只取样本中的 `user_prompt` 送检。

上传参数 `limit`：`0` 或不传 = 全量；`>0` = 截断到前 N 条。

---

## 五、测试资源

| 文件 | 用途 |
|------|------|
| `test_assets/attack_corpus.json` | ⚠ 旧格式样本（`{prompt:...}` / 字符串数组），新解析器不识别，仅作历史参考 |
| `test_assets/attack_bulk.json` | ⚠ 旧格式大样本（120 条字符串数组），同上 |
| `test_assets/rule_guard.zip` | 防御示例 1：关键词 + 正则 + Base64 解码 |
| `test_assets/heuristic_shield.zip` | 防御示例 2：指令密度 + 角色重置 + 模板 token |

> 注：新格式样本需为对象数组，每条含 `user_prompt`（`context`/`judge_rule` 可选），见 [§四](#四攻击-json-格式样本对象数组)。
> 这两个 `attack_*.json` 是早期旧格式，上传会被解析为空；如需测试请准备新格式文件。

防御示例包可直接上传测试。攻击/防御集成测试用命令行脚本：

```bash
# 攻击：读样本文件，三字段发 LLM，输出检测精度
python backend/test_attack.py --file <样本.json> --out results.json

# 防御：读同一份样本，只取 user_prompt 发 /detect/{group}
python backend/test_defend.py --file <样本.json> --group <队伍名>
```

---

## 六、技术栈

- **后端**：Python 3.10+ / FastAPI / torch 2.6+ / transformers 4.51+ / openai SDK
- **前端**：React 19 / Vite 8 / lucide-react（纯前端，无 UI 框架）
- **测试**：Playwright（端到端）+ Python 脚本（离线验证）
