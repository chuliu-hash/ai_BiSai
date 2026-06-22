"""FastAPI 应用：请求模型 + 路由 + 启动预热。

合并了攻击评测端点（/api/attack/*）与防御检测端点（/detect/{group}、/groups），
由统一的 server.py 入口启动。
"""
from _bootstrap import _HERE  # noqa: F401

import asyncio
import importlib
import io
import json
import os
import re
import shutil
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import defend_group
from config import (
    DEFAULT_LLM_BASE_URL, DEFAULT_LLM_MODEL, MAX_CONCURRENT_DETECT,
    _req_pool, _get_detector, _get_output_detector,
)
from core import _process_no_defense, _process_with_shield


# ───────────────────────── 请求模型 ─────────────────────────

class AttackRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="完整的攻击提示词（User Prompt），服务端不再做任何拼接")
    llm_base_url: Optional[str] = None
    llm_model: Optional[str] = None


class ShieldedAttackRequest(AttackRequest):
    sensitivity: str = Field("low", description="输入检测敏感度 low/medium/high")
    enable_rag: bool = Field(False, description="RAG 安全上下文增强开关（默认关闭，详见 server_API.md）")


class DetectRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1, description="待检测的用户提示词")


# ───────────────────────── 线程池 ─────────────────────────

# 防御检测专用线程池：阻塞的队伍 Detect 丢过来，不卡事件循环（与 attack 的 _req_pool 独立）
_defend_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="defend")


# ───────────────────────── 上传相关配置 / 工具 ─────────────────────────

# 单次攻击批量上传的最大条数（避免一请求炸 BERT；前端可分批）
MAX_ATTACK_BATCH = int(os.environ.get("MAX_ATTACK_BATCH", "50"))

# defend_group 根目录（队伍 zip 解压目的地）
_DEFEND_ROOT = Path(defend_group.__file__).parent

# 允许的队伍名：合法 Python 标识符 + 非保留名
_TEAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_TEAMS = {"__init__", "__pycache__"}

# 防御包上传的 zip bomb 防护上限
_MAX_ZIP_FILES = int(os.environ.get("MAX_ZIP_FILES", "500"))
_MAX_ZIP_TOTAL_SIZE = int(os.environ.get("MAX_ZIP_TOTAL_SIZE", str(200 * 1024 * 1024)))  # 200MB

# 允许的前端来源（CORS）。
# 默认放开为 ["*"]：适配本地 localhost / 远程内部平台（如 quchiai）等多种域名。
# 如需收紧，设置环境变量 CORS_ORIGINS（逗号分隔），例如：
#   CORS_ORIGINS=http://localhost:5173,https://workbench-xxx.quchiai.com
_env_cors = os.environ.get("CORS_ORIGINS", "").strip()
_CORS_ORIGINS = (
    [o.strip() for o in _env_cors.split(",") if o.strip()]
    if _env_cors else ["*"]
)


def _safe_team(name: str) -> str:
    """校验队伍名合法且非保留；非法抛 HTTPException(400)。"""
    name = (name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="队伍名不能为空")
    if not _TEAM_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail=f"队伍名必须是合法 Python 标识符：{name!r}")
    if name in _RESERVED_TEAMS:
        raise HTTPException(status_code=400, detail=f"队伍名 {name!r} 为保留名，禁止使用")
    return name


def _extract_prompts(obj) -> list:
    """从解析后的 JSON 对象抽取 prompt 列表。

    支持三种提交形态：
      · ["prompt1", "prompt2", ...]                         → 字符串数组
      · [{"prompt": "...", ...}, ...] / [{..., "攻击语料": "..."}]  → 对象数组
      · {"队名": [{"prompt": "..."}, ...], ...}              → 按队分组的对象
    统一返回 list[str]（非字符串元素转 str，空串丢弃）。
    """
    prompts = []

    def push(item):
        if isinstance(item, str):
            if item.strip():
                prompts.append(item)
        elif item is not None:
            s = str(item).strip()
            if s:
                prompts.append(s)

    if isinstance(obj, str):
        push(obj)
    elif isinstance(obj, list):
        for row in obj:
            if isinstance(row, str):
                push(row)
            elif isinstance(row, dict):
                _prompts_from_dict(row, push)
    elif isinstance(obj, dict):
        _prompts_from_dict(obj, push)
    return prompts


def _prompts_from_dict(d: dict, push):
    """从一个 dict 抽取 prompt：优先取 prompt/提示词/攻击语料 等键；否则把每个值递归处理。"""
    PROMPT_KEYS = ("prompt", "user_prompt", "text", "content",
                   "提示词", "攻击语料", "攻击提示词", "指令")
    found = False
    for k, v in d.items():
        hit = (isinstance(k, str) and (k.lower() in PROMPT_KEYS or k in PROMPT_KEYS))
        if hit:
            found = True
            if isinstance(v, list):
                for sub in v:
                    if isinstance(sub, str):
                        push(sub)
                    elif isinstance(sub, dict):
                        _prompts_from_dict(sub, push)
            else:
                push(v)
    if found:
        return
    # 没有命中已知键：把每个值当潜在容器递归（应对按队分组的 {队名: [...]} 形态）
    for v in d.values():
        if isinstance(v, list):
            for sub in v:
                if isinstance(sub, str):
                    push(sub)
                elif isinstance(sub, dict):
                    _prompts_from_dict(sub, push)
        elif isinstance(v, dict):
            _prompts_from_dict(v, push)
        else:
            push(v)



# ───────────────────────── FastAPI 应用 ─────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.environ.get("PRELOAD", "true").lower() != "false":
        # 预热最常用的 low 档检测器 + 输出规则，避免开赛瞬间首请求卡在加载
        try:
            _get_detector("low")
            _get_output_detector()
            print(f"[预热完成] low 档检测器已就绪 | 并发上限={MAX_CONCURRENT_DETECT}")
        except Exception as e:
            print(f"[预热失败] {e}（将退化为首次请求加载）")
    yield


app = FastAPI(title="攻防评测统一服务", version="1.0", lifespan=lifespan)

# CORS：允许前端开发服务器（Vite 5173）跨域调用
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ───────────────────────── 攻击评测端点 ─────────────────────────

@app.post("/api/attack/no_defense")
async def attack_no_defense(req: AttackRequest):
    """无防护模型：完整提示词 → 直接调裸 LLM → 返回生成结果。"""
    base_url = req.llm_base_url or DEFAULT_LLM_BASE_URL
    model = req.llm_model or DEFAULT_LLM_MODEL
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_req_pool, _process_no_defense, req.prompt, base_url, model)


@app.post("/api/attack/with_shield")
async def attack_with_shield(req: ShieldedAttackRequest):
    """模盾防护模型：完整提示词 → 输入检测 → (RAG增强)生成 → 输出检测。"""
    base_url = req.llm_base_url or DEFAULT_LLM_BASE_URL
    model = req.llm_model or DEFAULT_LLM_MODEL
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _req_pool, _process_with_shield,
        req.prompt, req.sensitivity, req.enable_rag, base_url, model,
    )


# ───────────────────────── 防御检测端点 ─────────────────────────

@app.post("/detect/{group}")
async def detect(group: str, req: DetectRequest) -> int:
    """调用指定队伍(group)的 Detect(user_prompt)，返回 0（安全）/ 1（不安全）。"""
    try:
        Detect = defend_group.get_detect(group)
    except (ModuleNotFoundError, AttributeError) as e:
        raise HTTPException(status_code=404, detail=str(e))
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_defend_pool, Detect, req.user_prompt)


@app.get("/groups")
async def groups():
    """列出所有已上传的防御队伍子包。"""
    return {"groups": defend_group.list_groups()}


# 别名：前端统一走 /api 前缀
@app.get("/api/groups")
async def api_groups():
    return await groups()


# ───────────────────────── 文件上传端点 ─────────────────────────

@app.post("/api/upload/attack")
async def upload_attack(file: UploadFile = File(...), limit: Optional[int] = None):
    """攻击赛道：上传 JSON 文件，解析出 prompt 列表。

    - limit > 0：截断到前 N 条（向后兼容默认行为）
    - limit = 0 或未传：返回全量（不截断），交由前端分批测试
    - 仍解析出总数 truncated 字段，便于前端提示
    """
    raw = await file.read()
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"JSON 解析失败: {e}")

    prompts = _extract_prompts(obj)
    if not prompts:
        raise HTTPException(status_code=400, detail="未从文件中解析出任何提示词")

    total_parsed = len(prompts)
    # limit=0 表示不截断；limit 为正整数才截断
    if limit is not None and limit > 0:
        truncated = total_parsed > limit
        prompts = prompts[:limit]
    else:
        truncated = False

    return {
        "team": os.path.splitext(file.filename or "")[0],
        "filename": file.filename,
        "total": len(prompts),            # 本次返回的条数
        "total_parsed": total_parsed,    # 文件中实际解析出的条数
        "truncated": truncated,
        "max_batch": MAX_ATTACK_BATCH,
        "prompts": prompts,
    }


@app.post("/api/upload/defense")
async def upload_defense(
    file: UploadFile = File(...),
    team: str = Form(...),
):
    """防御赛道：上传 ZIP 包，解压整合到 defend_group/<team>/，校验暴露 Detect。

    成功后即可通过 POST /detect/{team} 测试该队伍。覆盖式上传：同名队伍会被替换。
    """
    team = _safe_team(team)
    raw = await file.read()

    # 必须是 zip
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="文件不是合法的 ZIP 压缩包")

    # 安全校验：禁止 zip slip + 禁止绝对路径 + zip bomb 防护
    target_dir = _DEFEND_ROOT / team
    members = []
    total_uncompressed = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        # zip bomb 防护：文件数与解压总大小上限
        if len(members) >= _MAX_ZIP_FILES:
            raise HTTPException(status_code=400, detail=f"压缩包文件数超过上限 {_MAX_ZIP_FILES}")
        total_uncompressed += info.file_size
        if total_uncompressed > _MAX_ZIP_TOTAL_SIZE:
            raise HTTPException(status_code=400, detail=f"压缩包解压后总大小超过上限 {_MAX_ZIP_TOTAL_SIZE // (1024*1024)} MB")
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            raise HTTPException(status_code=400, detail=f"压缩包含不安全路径: {info.filename}")
        # 去掉常见的顶层同名目录前缀（如 myteam/myteam/detector.py → myteam/detector.py）
        top = name.split("/", 1)
        if len(top) == 2 and top[0] == team:
            rel = top[1]
        else:
            rel = name
        members.append((info, rel))

    # 覆盖式解压：先删旧目录再重建
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    file_names = []
    for info, rel in members:
        dest = target_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        file_names.append(rel)

    # 必须有 __init__.py（Python 子包），否则补一个空的
    if not (target_dir / "__init__.py").exists():
        (target_dir / "__init__.py").write_text("", encoding="utf-8")

    # 校验：能 import 且暴露 Detect
    importlib.invalidate_caches()
    try:
        mod = importlib.import_module(f"defend_group.{team}")
        if not hasattr(mod, "Detect"):
            raise AttributeError("子包未暴露 Detect(user_prompt) 函数")
    except Exception as e:
        # 回滚：删除刚解压的目录，避免污染队伍列表
        shutil.rmtree(target_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"队伍包校验失败（已回滚）: {e}")

    return {
        "team": team,
        "filename": file.filename,
        "files": file_names,
        "groups": defend_group.list_groups(),
        "message": f"已整合到 defend_group/{team}/，可用 POST /detect/{team} 测试",
    }


# ───────────────────────── 根端点（统一目录）─────────────────────────

@app.get("/")
async def root():
    return {
        "service": "ai-security-eval-server",
        "endpoints": ["/api/attack/no_defense", "/api/attack/with_shield",
                      "/api/upload/attack", "/api/upload/defense"],
        "detect": "POST /detect/{group} {user_prompt} -> 0(safe)/1(unsafe)",
        "list_groups": "/groups",
        "max_concurrent_detect": MAX_CONCURRENT_DETECT,
    }
