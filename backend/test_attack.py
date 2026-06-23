# -*- coding: utf-8 -*-
"""
真实集成测试 —— 连接已部署的统一服务（server），对两个攻击端点发真实请求（非 mock）。

样本来源：JSON 文件（新格式，每条含 user_prompt / context / judge_rule）。
三条字段按角色送 LLM：judge_rule→{role:system}、context→前置 {role:user}、user_prompt→{role:user}。

用法:
    # 1) 本地服务 + 默认测试样本（需提供 --file）
    python test_attack.py --file test_samples.json

    # 2) 指向部署服务器
    python test_attack.py --file test_samples.json --base-url http://<服务器IP>:8000

    # 3) 只测模盾防护 + 开 RAG + medium 敏感度
    python test_attack.py --file test_samples.json --only with_shield --sensitivity medium --enable-rag

    # 4) 截断只测前 N 条（可选）
    python test_attack.py --file test_samples.json --limit 10

JSON 样本格式（与前端上传格式一致，由服务端 _extract_samples 解析）：
    [
      {"user_prompt": "...", "context": "...", "judge_rule": "..."},
      ...
    ]
    context / judge_rule 可选（缺省为空）；也兼容 {"队名": [样本,...]} 按队分组形态。
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


def extract_samples(obj):
    """从解析后的 JSON 抽取攻击样本（与后端 app._extract_samples 一致，本脚本自包含实现）。

    每条样本：{user_prompt, context, judge_rule}；context/judge_rule 缺省补 ""。
    兼容对象数组 与 {队名:[样本,...]} 按队分组形态。
    """
    samples = []

    def push(item):
        if isinstance(item, dict):
            up = item.get("user_prompt")
            if isinstance(up, str) and up.strip():
                ctx = item.get("context")
                jr = item.get("judge_rule")
                samples.append({
                    "user_prompt": up,
                    "context": ctx if isinstance(ctx, str) else "",
                    "judge_rule": jr if isinstance(jr, str) else "",
                })

    if isinstance(obj, list):
        for row in obj:
            push(row)
    elif isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, list):
                for sub in v:
                    push(sub)
            elif isinstance(v, dict):
                push(v)
    return samples


def load_samples(path):
    """读取样本 JSON 文件，返回样本列表。"""
    with open(path, encoding="utf-8") as f:
        obj = json.load(f)
    return extract_samples(obj)


def call(base_url, path, payload, timeout):
    start = time.time()
    r = requests.post(f"{base_url}{path}", json=payload, timeout=timeout)
    return r.status_code, r.json(), time.time() - start


def show(title, code, data, elapsed, sample):
    print(f"\n{'=' * 70}")
    print(f"{title}  |  HTTP {code}  |  {elapsed:.2f}s")
    print("=" * 70)
    up = sample["user_prompt"]
    print(f"  user_prompt: {up[:100]}{'...' if len(up) > 100 else ''}")
    print(json.dumps(data, ensure_ascii=False, indent=2))


def check_no_defense(code, data, sample):
    assert code == 200, f"期望 HTTP 200，实际 {code}"
    assert data.get("user_prompt") == sample["user_prompt"], "user_prompt 未原样回显"
    assert "model_response" in data, "响应缺 model_response 字段"
    assert "shield" not in data, "no_defense 不应返回 shield"
    print("  [结构校验 PASS] no_defense 响应结构正确")


def check_with_shield(code, data, sample):
    assert code == 200, f"期望 HTTP 200，实际 {code}"
    assert data.get("user_prompt") == sample["user_prompt"], "user_prompt 未原样回显"
    sh = data.get("shield")
    assert sh is not None, "响应缺 shield 字段"
    for k in ("is_safe", "stopped_at", "input_detection"):
        assert k in sh, f"shield 缺字段 {k}"
    print("  [结构校验 PASS] with_shield 响应结构正确")


def run_one(base_url, sample, sensitivity, enable_rag, only, timeout):
    payload = {
        "user_prompt": sample["user_prompt"],
        "context": sample["context"],
        "judge_rule": sample["judge_rule"],
    }
    if only in ("no_defense", "both"):
        code, data, t = call(base_url, "/api/attack/no_defense", payload, timeout)
        check_no_defense(code, data, sample)
        show("无防护  POST /api/attack/no_defense", code, data, t, sample)
        print(f"  >> 模型回复: {(data.get('model_response') or '')[:200]}")

    if only in ("with_shield", "both"):
        full = dict(payload, sensitivity=sensitivity, enable_rag=enable_rag)
        code, data, t = call(base_url, "/api/attack/with_shield", full, timeout)
        check_with_shield(code, data, sample)
        show("模盾防护  POST /api/attack/with_shield", code, data, t, sample)
        sh = data["shield"]
        ind = sh.get("input_detection") or {}
        outd = sh.get("output_detection") or {}
        print(f"  >> 输入检测: is_safe={ind.get('is_safe')} risk={ind.get('risk_level')} "
              f"category={ind.get('category')} by={ind.get('decision_by')}")
        print(f"  >> 终止于: {sh.get('stopped_at') or '全流程完成（未拦截）'}")
        if outd:
            print(f"  >> 输出检测: is_safe={outd.get('is_safe')} failed_rules={outd.get('failed_rules')}")
        print(f"  >> 模型回复: {(data.get('model_response') or '')[:200]}")


def main():
    ap = argparse.ArgumentParser(description="统一服务攻击端点真实集成测试（基于 JSON 样本文件）")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000", help="已部署服务地址")
    ap.add_argument("--file", required=True, help="样本 JSON 文件（每条含 user_prompt/context/judge_rule）")
    ap.add_argument("--limit", type=int, default=0,
                    help="只测前 N 条（0 或不传 = 全量）")
    ap.add_argument("--sensitivity", default="low", choices=["low", "medium", "high"])
    ap.add_argument("--enable-rag", action="store_true")
    ap.add_argument("--only", choices=["no_defense", "with_shield", "both"], default="both")
    ap.add_argument("--timeout", type=float, default=120.0)
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

    # 读取样本文件
    if not os.path.exists(args.file):
        print(f"✗ 样本文件不存在: {args.file}")
        sys.exit(1)
    try:
        samples = load_samples(args.file)
    except (json.JSONDecodeError, OSError) as e:
        print(f"✗ 读取样本文件失败: {e}")
        sys.exit(1)
    if not samples:
        print("✗ 未从样本文件解析出任何样本（需含 user_prompt 字段）")
        sys.exit(0)

    if args.limit > 0:
        samples = samples[:args.limit]

    print(f"\n共 {len(samples)} 条样本 | 模式={args.only} | sensitivity={args.sensitivity} | enable_rag={args.enable_rag}")

    for i, s in enumerate(samples, 1):
        print(f"\n{'#' * 60}\n# 样本 {i}/{len(samples)}\n{'#' * 60}")
        try:
            run_one(args.base_url, s, args.sensitivity, args.enable_rag, args.only, args.timeout)
        except AssertionError as e:
            print(f"  [结构校验 FAIL] {e}")
        except requests.exceptions.RequestException as e:
            print(f"  [请求失败] {e}")


if __name__ == "__main__":
    main()
