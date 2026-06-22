"""
攻防评测统一服务（FastAPI）—— 合并攻击评测与防御检测。

端点（详见 app.py）:
  攻击评测: POST /api/attack/no_defense
            POST /api/attack/with_shield
  防御检测: POST /detect/{group}  {"user_prompt": "..."}  -> 0(安全)/1(不安全)
            GET  /groups

启动:
    python server.py
环境变量:
    SERVER_PORT  端口（默认 8000）；其余见 .env
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _bootstrap  # noqa: F401  加载 .env + 代理绕过
from app import app  # noqa: F401  让 `uvicorn server:app` 可用


def main():
    import uvicorn
    port = int(os.environ.get("SERVER_PORT", "8000"))
    print(f"攻防评测统一服务: http://0.0.0.0:{port}  "
          f"(POST /api/attack/*, POST /detect/{{group}} -> 0/1, GET /groups)")
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
