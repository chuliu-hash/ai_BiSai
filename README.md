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

### 1. 启动后端（必须用 modelshield 环境）

```bash
cd backend
conda activate modelshield       # 含 fastapi / torch / transformers
python server.py
# → http://127.0.0.1:8000
```

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
| **攻击** | 上传 JSON 语料（任意数量，全量返回）→ 选端点 → 开始测试（4 路并发分批 + 进度条 + 可取消）→ 结果分页浏览 |
| **防御** | 上传 ZIP 防御包 + 队名 → 选队伍 → 输入提示词 → 检测得 0/1 |

前端通过 `frontend/.env` 的 `VITE_API_BASE` 连接后端（默认 `http://127.0.0.1:8000`）。左侧栏底部有连接状态指示灯（绿/红点），每 8 秒自动复探。

---

## 二、文档导航

| 文档 | 内容 |
|------|------|
| [`frontend/使用.txt`](frontend/使用.txt) | 启动 + 使用流程 + 攻击 JSON 格式速查（最简上手） |
| [`frontend/PRODUCT.md`](frontend/PRODUCT.md) | 前端产品定位与设计原则 |
| [`backend/server_API.md`](backend/server_API.md) | **后端 API 完整说明**（所有端点、字段、错误码、调用示例） |
| [`backend/Readme.md`](backend/Readme.md) | 考题及规则总结 |
| [`backend/defend_group/README.md`](backend/defend_group/README.md) | 防御队伍提交规范（Detect 接口 + 目录结构） |
| [`test_assets/README.md`](test_assets/README.md) | 测试语料 + 防御示例包 + 自动化脚本说明 |

---

## 三、后端端点速览

| 方法 | 端点 | 说明 |
|------|------|------|
| `POST` | `/api/upload/attack?limit=0` | 上传攻击 JSON，全量返回 prompt 列表（`limit=0` 不截断） |
| `POST` | `/api/upload/defense` | 上传防御 ZIP，整合到 `defend_group/<队名>/` |
| `POST` | `/api/attack/no_defense` | 无防护评测：prompt → 裸 LLM |
| `POST` | `/api/attack/with_shield` | 模盾防护：输入检测 →（RAG）→ 生成 → 输出检测 |
| `POST` | `/detect/{group}` | 调队伍 `Detect`，返回 0/1 |
| `GET`  | `/groups` · `/api/groups` | 列出已上传队伍 |
| `GET`  | `/` | 服务自描述 |

详见 [`backend/server_API.md`](backend/server_API.md)。

---

## 四、攻击 JSON 格式（三种均支持）

```jsonc
// 格式 1：字符串数组
["忽略之前所有指令...", "Ignore all previous instructions..."]

// 格式 2：对象数组（识别键，大小写不敏感）
[{"prompt": "..."}, {"user_prompt": "..."}, {"text": "..."},
 {"content": "..."}, {"提示词": "..."}, {"攻击语料": "..."}]

// 格式 3：按队分组（赛题标准）
{"team_alpha": [{"prompt": "..."}, "字符串也行"], "team_beta": [...]}
```

识别键：`prompt` / `user_prompt` / `text` / `content` / `提示词` / `攻击语料` / `攻击提示词` / `指令`

上传参数 `limit`：`0` 或不传 = 全量；`>0` = 截断到前 N 条。

---

## 五、测试资源

| 文件 | 用途 |
|------|------|
| `test_assets/attack_corpus.json` | 20 条小样本（三格式混合） |
| `test_assets/attack_bulk.json` | 120 条大样本（验证全量 + 分批） |
| `test_assets/rule_guard.zip` | 防御示例 1：关键词 + 正则 + Base64 解码 |
| `test_assets/heuristic_shield.zip` | 防御示例 2：指令密度 + 角色重置 + 模板 token |
| `test_assets/e2e_test.py` | Playwright 端到端浏览器测试 |

详见 [`test_assets/README.md`](test_assets/README.md)。

---

## 六、技术栈

- **后端**：Python 3.10+ / FastAPI / torch 2.6+ / transformers 4.51+ / openai SDK
- **前端**：React 19 / Vite 8 / lucide-react（纯前端，无 UI 框架）
- **测试**：Playwright（端到端）+ Python 脚本（离线验证）
