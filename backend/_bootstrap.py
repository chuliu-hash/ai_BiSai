"""引导模块：路径设置 + .env 加载。

必须在 import defend 之前被导入（每个模块首行 `from _bootstrap import _HERE`），
以便 defend 内部的 os.environ.get 也能读到 .env 配置（含 NO_PROXY 等代理绕过）。
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _load_env(path):
    """读取 .env 到 os.environ（不覆盖已存在的环境变量）。"""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if val and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]                       # 引号包围：原样保留
            elif " #" in val:
                val = val.split(" #", 1)[0].rstrip()  # 未引号：剥离行内注释
            os.environ.setdefault(key, val)


# 导入即加载 .env（在任何 defend import 之前）
_load_env(os.path.join(_HERE, ".env"))


def _ensure_local_no_proxy():
    """强制把本地服务 host 合并进 NO_PROXY/no_proxy。

    setdefault 无法覆盖系统已 export 的 NO_PROXY（若系统值不含 127.1.1.1，
    requests/openai 会对本地服务走系统代理 → 代理返回 503，且报错仍显示原始 URL，
    极易误判为「服务不可用」）。这里改为「合并」：扫描所有 *_URL 解析 host + 兜底本地网段，
    确保本地服务一定绕过代理。
    """
    from urllib.parse import urlparse
    hosts = {"127.0.0.1", "localhost", "127.1.1.1"}
    for k, v in os.environ.items():
        if k.upper().endswith("_URL") and isinstance(v, str) and v.startswith("http"):
            h = urlparse(v).hostname
            if h:
                hosts.add(h)
    for key in ("NO_PROXY", "no_proxy"):
        cur = [h.strip() for h in os.environ.get(key, "").split(",") if h.strip()]
        merged = cur + [h for h in sorted(hosts) if h not in cur]
        os.environ[key] = ",".join(merged)


_ensure_local_no_proxy()
