# -*- coding: utf-8 -*-
"""
真实集成测试 —— 连接已部署的统一服务（server），对防御检测端点发真实请求（非 mock）。

样本来源：JSON 文件（新格式，每条含 user_prompt / context / judge_rule）。
防御检测只把 user_prompt 送 POST /detect/{group}（赛题接口 Detect(user_prompt)，
context / judge_rule 与防御检测无关，仅用于人工对照，不参与判定）。

用法:
    # 1) 默认本地服务 + 测试样本（需提供 --file）
    python test_defend.py --file test_samples.json

    # 2) 指定队伍（默认 keyword_blacklist）+ 指向部署服务器
    python test_defend.py --file test_samples.json --group injection_rules --base-url http://<IP>:8000

    # 3) 截断只测前 N 条（可选）
    python test_defend.py --file test_samples.json --limit 10

    # 4) 跑完后顺带验证 404/422 错误路径
    python test_defend.py --file test_samples.json --group keyword_blacklist --check-errors

JSON 样本格式（与前端上传格式一致）：
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


def call_detect(base_url, group, user_prompt, timeout):
    """POST /detect/{group}，返回 (status_code, verdict, elapsed)。

    成功响应体是纯整数（0/1）；错误时是 {"detail": ...}。
    """
    start = time.time()
    r = requests.post(f"{base_url}/detect/{group}",
                      json={"user_prompt": user_prompt}, timeout=timeout)
    elapsed = time.time() - start
    if r.status_code == 200:
        # 防御接口返回纯整数，requests 仍能 .json() 解析
        try:
            verdict = r.json()
        except ValueError:
            verdict = None
        return r.status_code, verdict, elapsed
    # 非 200：detail 字段给出原因
    try:
        verdict = r.json()
    except ValueError:
        verdict = {"detail": r.text}
    return r.status_code, verdict, elapsed


def show(title, code, verdict, elapsed, sample):
    print(f"\n{'=' * 70}")
    print(f"{title}  |  HTTP {code}  |  {elapsed:.2f}s")
    print("=" * 70)
    up = sample["user_prompt"]
    print(f"  user_prompt: {up[:100]}{'...' if len(up) > 100 else ''}")
    print(f"  >> 判定: {verdict}")


def check_verdict(code, verdict):
    """校验 /detect 成功响应结构：HTTP 200 且 verdict ∈ {0, 1}（整数）。"""
    assert code == 200, f"期望 HTTP 200，实际 {code}"
    assert verdict in (0, 1), f"期望返回整数 0/1，实际 {verdict!r}（类型 {type(verdict).__name__}）"
    print(f"  [结构校验 PASS] 返回 {verdict}（{'安全' if verdict == 0 else '不安全'}）")


def run_one(base_url, group, sample, timeout):
    # 防御检测只检 user_prompt（context/judge_rule 不送检测）
    code, verdict, t = call_detect(base_url, group, sample["user_prompt"], timeout)
    check_verdict(code, verdict)
    show(f"POST /detect/{group}", code, verdict, t, sample)


def check_error_paths(base_url, group, timeout):
    """顺带验证防御端点的两个错误路径：不存在的队伍 → 404；空 user_prompt → 422。"""
    print(f"\n{'#' * 60}\n# 错误路径校验\n{'#' * 60}")

    # 404：不存在的队伍
    code, body, t = call_detect(base_url, "no_such_team", "hi", timeout)
    assert code == 404, f"期望 404，实际 {code}"
    assert isinstance(body, dict) and "detail" in body, f"404 响应应含 detail，实际 {body!r}"
    print(f"  [PASS] 不存在的队伍 → HTTP 404  detail={body['detail']}")

    # 422：空 user_prompt（Pydantic min_length=1 校验）
    start = time.time()
    r = requests.post(f"{base_url}/detect/{group}",
                      json={"user_prompt": ""}, timeout=timeout)
    assert r.status_code == 422, f"期望 422，实际 {r.status_code}"
    print(f"  [PASS] 空 user_prompt → HTTP 422  ({time.time() - start:.2f}s)")


def main():
    ap = argparse.ArgumentParser(description="统一服务防御端点真实集成测试（基于 JSON 样本文件）")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000", help="已部署服务地址")
    ap.add_argument("--group", default="keyword_blacklist",
                    help="目标队伍名（defend_group/ 下的子包；可用 GET /groups 查询全部）")
    ap.add_argument("--file", required=True,
                    help="样本 JSON 文件（每条含 user_prompt；context/judge_rule 可选，仅人工对照）")
    ap.add_argument("--limit", type=int, default=0,
                    help="只测前 N 条（0 或不传 = 全量）")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--check-errors", action="store_true",
                    help="跑完样本后顺带校验 404/422 错误路径")
    args = ap.parse_args()

    # 加载 .env，并确保目标地址绕过代理
    _load_env(os.path.join(_HERE, ".env"))
    _bypass_proxy_for(args.base_url)

    # 健康检查 + 队伍列表
    try:
        h = requests.get(f"{args.base_url}/", timeout=5).json()
        groups = requests.get(f"{args.base_url}/groups", timeout=5).json().get("groups", [])
        print(f"已连接 {args.base_url}  防御接口={h.get('detect')}  并发上限={h.get('max_concurrent_detect')}")
        print(f"可用队伍: {groups}")
    except Exception as e:
        print(f"✗ 无法连接 {args.base_url}: {e}")
        sys.exit(1)

    if args.group not in groups:
        print(f"✗ 队伍 '{args.group}' 不在可用列表 {groups} 中")
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

    print(f"\n共 {len(samples)} 条样本 | 队伍={args.group}")

    for i, s in enumerate(samples, 1):
        print(f"\n{'#' * 60}\n# 样本 {i}/{len(samples)}\n{'#' * 60}")
        try:
            run_one(args.base_url, args.group, s, args.timeout)
        except AssertionError as e:
            print(f"  [结构校验 FAIL] {e}")
        except requests.exceptions.RequestException as e:
            print(f"  [请求失败] {e}")

    if args.check_errors:
        try:
            check_error_paths(args.base_url, args.group, args.timeout)
            print("\n错误路径校验全部通过")
        except AssertionError as e:
            print(f"\n[错误路径校验 FAIL] {e}")
        except requests.exceptions.RequestException as e:
            print(f"\n[错误路径请求失败] {e}")


if __name__ == "__main__":
    main()
