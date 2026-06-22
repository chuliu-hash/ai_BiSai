# -*- coding: utf-8 -*-
"""
真实集成测试 —— 连接已部署的统一服务（server），对两个攻击端点发真实请求（非 mock）。

特点：
  · 连真实服务（HTTP requests）
  · 提示词由你提供：--prompt / --prompt-file / 交互输入，避免在代码里硬编码违规内容
  · 默认提示词为安全示例，开箱即跑；带响应结构断言

用法:
    # 1) 默认安全提示词 + 本地服务
    python test_real.py

    # 2) 指向部署服务器 + 自己的提示词（一条）
    python test_real.py --base-url http://<服务器IP>:8000 --prompt "你的完整提示词"

    # 3) 从文件读多条提示词（每行一条，# 开头注释）
    python test_real.py --prompt-file my_prompts.txt --base-url http://<IP>:8000

    # 4) 交互模式：逐条输入、逐条测（空行结束）
    python test_real.py --interactive --base-url http://<IP>:8000

    # 5) 只测模盾防护 + 开 RAG + medium 敏感度
    python test_real.py --only with_shield --sensitivity medium --enable-rag
"""
import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_env(path):
    """读取 .env 到 os.environ（不覆盖已存在变量）。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if v and v[0] in "\"'" and v[-1] == v[0]:
                v = v[1:-1]
            elif " #" in v:
                v = v.split(" #", 1)[0].rstrip()
            os.environ.setdefault(k, v)


def _bypass_proxy_for(base_url):
    """确保目标地址绕过系统代理：把 host 加入 NO_PROXY/no_proxy。"""
    host = urlparse(base_url).hostname or ""
    if not host:
        return
    for k in ("NO_PROXY", "no_proxy"):
        cur = os.environ.get(k, "")
        if host not in cur:
            os.environ[k] = f"{cur},{host}" if cur else host


# 默认提示词：明显安全的示例，避免硬编码任何违规内容
DEFAULT_PROMPT = "请用三句话介绍一下量子计算的基本原理。"


def call(base_url, path, payload, timeout):
    start = time.time()
    r = requests.post(f"{base_url}{path}", json=payload, timeout=timeout)
    return r.status_code, r.json(), time.time() - start


def show(title, code, data, elapsed):
    print(f"\n{'=' * 70}")
    print(f"{title}  |  HTTP {code}  |  {elapsed:.2f}s")
    print("=" * 70)
    print(json.dumps(data, ensure_ascii=False, indent=2))


def check_no_defense(code, data, prompt):
    assert code == 200, f"期望 HTTP 200，实际 {code}"
    assert data.get("prompt") == prompt, "prompt 未原样回显"
    assert "model_response" in data, "响应缺 model_response 字段"
    assert "shield" not in data, "no_defense 不应返回 shield"
    print("  [结构校验 PASS] no_defense 响应结构正确")


def check_with_shield(code, data, prompt):
    assert code == 200, f"期望 HTTP 200，实际 {code}"
    assert data.get("prompt") == prompt, "prompt 未原样回显"
    sh = data.get("shield")
    assert sh is not None, "响应缺 shield 字段"
    for k in ("is_safe", "stopped_at", "input_detection"):
        assert k in sh, f"shield 缺字段 {k}"
    print("  [结构校验 PASS] with_shield 响应结构正确")


def run_one(base_url, prompt, sensitivity, enable_rag, only, timeout):
    if only in ("no_defense", "both"):
        code, data, t = call(base_url, "/api/attack/no_defense", {"prompt": prompt}, timeout)
        check_no_defense(code, data, prompt)
        show("无防护  POST /api/attack/no_defense", code, data, t)
        print(f"  >> 模型回复: {(data.get('model_response') or '')[:200]}")

    if only in ("with_shield", "both"):
        payload = {"prompt": prompt, "sensitivity": sensitivity, "enable_rag": enable_rag}
        code, data, t = call(base_url, "/api/attack/with_shield", payload, timeout)
        check_with_shield(code, data, prompt)
        show("模盾防护  POST /api/attack/with_shield", code, data, t)
        sh = data["shield"]
        ind = sh.get("input_detection") or {}
        outd = sh.get("output_detection") or {}
        print(f"  >> 输入检测: is_safe={ind.get('is_safe')} risk={ind.get('risk_level')} "
              f"category={ind.get('category')} by={ind.get('decision_by')}")
        print(f"  >> 终止于: {sh.get('stopped_at') or '全流程完成（未拦截）'}")
        if outd:
            print(f"  >> 输出检测: is_safe={outd.get('is_safe')} failed_rules={outd.get('failed_rules')}")
        print(f"  >> 模型回复: {(data.get('model_response') or '')[:200]}")


def collect_prompts(args):
    if args.interactive:
        print("\n交互模式：输入提示词后回车即测，空行结束。")
        out = []
        while True:
            try:
                line = input("prompt> ").rstrip("\n")
            except (EOFError, KeyboardInterrupt):
                break
            if not line.strip():
                break
            out.append(line)
        return out
    if args.prompt_file:
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    return [args.prompt or DEFAULT_PROMPT]


def main():
    ap = argparse.ArgumentParser(description="统一服务攻击端点真实集成测试")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000", help="已部署服务地址")
    ap.add_argument("--prompt", default=None, help="完整提示词（不填用默认安全示例）")
    ap.add_argument("--prompt-file", default=None, help="从文件读提示词，每行一条（# 注释）")
    ap.add_argument("--sensitivity", default="low", choices=["low", "medium", "high"])
    ap.add_argument("--enable-rag", action="store_true")
    ap.add_argument("--only", choices=["no_defense", "with_shield", "both"], default="both")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--interactive", action="store_true", help="交互式逐条输入提示词")
    args = ap.parse_args()

    # 加载 .env，并确保目标地址绕过代理
    _load_env(os.path.join(_HERE, ".env"))
    _bypass_proxy_for(args.base_url)

    # 健康检查
    try:
        h = requests.get(f"{args.base_url}/", timeout=5).json()
        print(f"已连接 {args.base_url}  端点={h.get('endpoints')}  并发上限={h.get('max_concurrent_detect')}")
    except Exception as e:
        print(f"✗ 无法连接 {args.base_url}: {e}")
        sys.exit(1)

    prompts = collect_prompts(args)
    if not prompts:
        print("没有提示词可测"); sys.exit(0)

    print(f"\n共 {len(prompts)} 条提示词 | 模式={args.only} | sensitivity={args.sensitivity} | enable_rag={args.enable_rag}")

    for i, p in enumerate(prompts, 1):
        print(f"\n{'#' * 60}\n# 提示词 {i}/{len(prompts)}\n{'#' * 60}")
        print(f"内容: {p[:120]}{'...' if len(p) > 120 else ''}")
        try:
            run_one(args.base_url, p, args.sensitivity, args.enable_rag, args.only, args.timeout)
        except AssertionError as e:
            print(f"  [结构校验 FAIL] {e}")
        except requests.exceptions.RequestException as e:
            print(f"  [请求失败] {e}")


if __name__ == "__main__":
    main()
