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

    # 5) 把检测结果写入 JSON（便于留存/对比；不传则只打印）
    python test_attack.py --file test_samples.json --out results.json

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
    """POST 并解析 JSON。返回 (code, data, elapsed)。

    响应非 JSON 时 data 落到 {"_raw": 文本}，避免后续处理崩溃。
    """
    start = time.time()
    r = requests.post(f"{base_url}{path}", json=payload, timeout=timeout)
    elapsed = time.time() - start
    try:
        data = r.json()
    except ValueError:
        data = {"_raw": r.text}
    return r.status_code, data, elapsed


HEAD = 50  # 文本字段打印/保存时的截断长度（字符）


def head(s):
    """截断到 HEAD 个字符，超出加省略号。"""
    s = s or ""
    return s[:HEAD] + ("..." if len(s) > HEAD else "")


def slim(obj):
    """递归把响应里所有字符串截断到 HEAD 字符；dict/list 结构与数值保留原样。

    用于保存结果 JSON 时压缩冗长文本（user_prompt/context/judge_rule/
    model_response/error/detection_error 等），保持结构精简易读。
    """
    if isinstance(obj, str):
        return head(obj)
    if isinstance(obj, dict):
        return {k: slim(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [slim(v) for v in obj]
    return obj  # 数值 / bool / None 原样


def show(title, sample, http, elapsed, line):
    """打印一行精简结果：标题 + 三字段各取前20字 + 摘要行。"""
    print(f"{title}  [{http}] {elapsed:.2f}s")
    print(f"  user_prompt: {head(sample['user_prompt'])}")
    print(f"  context:     {head(sample['context'])}")
    print(f"  judge_rule:  {head(sample['judge_rule'])}")
    print(f"  >> {line}")


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


def _summary_no_defense(data):
    """no_defense 摘要行（用于打印）。"""
    resp = (data.get("model_response") or "").replace("\n", " ")
    err = data.get("error")
    return f"reply={resp[:HEAD]}{'...' if len(resp) > HEAD else ''}" + (f"  error={err}" if err else "")


def _summary_with_shield(data):
    """with_shield 摘要行（用于打印）。"""
    sh = data.get("shield") or {}
    resp = (data.get("model_response") or "").replace("\n", " ")
    err = data.get("error")
    parts = [
        f"detected={_is_attack_with_shield(data)}",
        f"is_safe={sh.get('is_safe')}",
        f"stopped_at={sh.get('stopped_at') or '完成'}",
        f"reply={resp[:HEAD]}{'...' if len(resp) > HEAD else ''}",
    ]
    if err:
        parts.append(f"error={err}")
    return "  ".join(parts)


def _is_attack_with_shield(data):
    """with_shield：是否被判定为攻击（即被拦截）。异常/未判定计为未检测，返回 None。"""
    sh = data.get("shield") or {}
    is_safe = sh.get("is_safe")
    if isinstance(is_safe, bool):
        return not is_safe  # is_safe=False → 拦截(攻击被检出)
    return None


def run_one(base_url, sample, sensitivity, enable_rag, only, timeout):
    """对一条样本跑选定端点，返回记录：三字段(前50字,便于阅读) + 各端点完整响应 + 是否检出。"""
    payload = {
        "user_prompt": sample["user_prompt"],
        "context": sample["context"],
        "judge_rule": sample["judge_rule"],
    }
    rec = {
        "user_prompt": head(sample["user_prompt"]),
        "context": head(sample["context"]),
        "judge_rule": head(sample["judge_rule"]),
        "no_defense": None,      # 完整响应（仅无防护）
        "with_shield": None,     # 完整响应（模盾防护）
        "detected": None,        # 是否被检出为攻击（仅 with_shield 有意义）
        "error": None,
    }

    if only in ("no_defense", "both"):
        code, data, t = call(base_url, "/api/attack/no_defense", payload, timeout)
        check_no_defense(code, data, sample)
        show("无防护", sample, code, t, _summary_no_defense(data))
        rec["no_defense"] = slim(data)

    if only in ("with_shield", "both"):
        full = dict(payload, sensitivity=sensitivity, enable_rag=enable_rag)
        code, data, t = call(base_url, "/api/attack/with_shield", full, timeout)
        check_with_shield(code, data, sample)
        show("模盾防护", sample, code, t, _summary_with_shield(data))
        rec["with_shield"] = slim(data)
        rec["detected"] = _is_attack_with_shield(data)
    return rec


def compute_accuracy(results, only):
    """计算攻击样本的检测精度：被检出为攻击(被拦截)的占比。

    only 决定用哪条路径判定：
      · with_shield / both → 用模盾检测结果（is_safe=False 即被检出）
      · no_defense         → 无防护模型无检测，不计精度（valid=0）
    异常/未判定(detected=None 或有 error)不计入分母，单独计入 skipped。
    返回 {"attack_detection": {"blocked","valid","skipped","rate"}}。
    """
    blocked = valid = skipped = 0
    use_shield = only in ("with_shield", "both")
    for r in results:
        if r.get("error"):
            skipped += 1
            continue
        if not use_shield:
            # no_defense 无检测能力
            skipped += 1
            continue
        det = r.get("detected")
        if det is None:
            skipped += 1
        elif det:
            blocked += 1
            valid += 1
        else:
            valid += 1
    rate = f"{(blocked / valid * 100):.1f}%" if valid else "N/A"
    return {"attack_detection": {"blocked": blocked, "valid": valid, "skipped": skipped, "rate": rate}}


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
    ap.add_argument("--out", default=None,
                    help="把完整检测结果写入该 JSON（含三字段前50字+完整响应+检测精度）；不传则只打印")
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

    results = []
    for i, s in enumerate(samples, 1):
        print(f"\n# 样本 {i}/{len(samples)}")
        rec = {
            "user_prompt": head(s["user_prompt"]),
            "context": head(s["context"]),
            "judge_rule": head(s["judge_rule"]),
            "no_defense": None,
            "with_shield": None,
            "detected": None,
            "error": None,
        }
        try:
            rec = run_one(args.base_url, s, args.sensitivity, args.enable_rag, args.only, args.timeout)
        except AssertionError as e:
            print(f"  [FAIL] {e}")
            rec["error"] = str(e)
        except requests.exceptions.RequestException as e:
            print(f"  [请求失败] {e}")
            rec["error"] = str(e)
        results.append(rec)

    # 检测精度：攻击样本中被检出为攻击的占比（仅 with_shield 有检测；异常/未判定不计入分母）
    summary = compute_accuracy(results, args.only)

    print(f"\n{'─' * 60}")
    print(f"检测精度（攻击被检出占比）: {summary['attack_detection']['rate']}  "
          f"({summary['attack_detection']['blocked']}/{summary['attack_detection']['valid']})")
    if summary['attack_detection']['skipped']:
        print(f"  (另有 {summary['attack_detection']['skipped']} 条异常/未判定，未计入)")

    # 写入结果 JSON（含完整响应 + 精度汇总）
    if args.out:
        out = {
            "total": len(results),
            "accuracy": summary,
            "results": results,
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\n结果已写入: {os.path.abspath(args.out)}（共 {len(results)} 条）")


if __name__ == "__main__":
    main()
