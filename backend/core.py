"""检测处理核心：LLM 调用 + 输入/RAG/输出检测 + 单条提示词处理。
"""
from _bootstrap import _HERE  # noqa: F401
from typing import Dict

from openai import OpenAI

from defend.prompt_detection import Detector
from defend.scr import SCR_RAG_System

from config import (
    LLM_TIMEOUT,
    _detect_slot, _get_detector, _get_scr, _get_output_detector,
)


def call_llm(prompt: str, base_url: str, model: str, temperature: float = 0.7) -> str:
    """调用后端大模型（带超时）。"""
    client = OpenAI(api_key="not-needed", base_url=base_url, timeout=LLM_TIMEOUT)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    return resp.choices[0].message.content or ""


def _run_input_detection(detector: Detector, text: str) -> Dict:
    """复用常驻 Detector 实例执行输入检测，返回结构化结果。"""
    results = detector.detect_with_bert_group(text)
    f = results[-1]
    is_safe = f.get("prediction") == 0

    # 捕获检测链路异常：defend 的 _invoke_llm_fallback 异常时会硬编码 prediction=0（安全兜底），
    # 但 confidence=0、p_attack=1 形成矛盾，会被误判为「安全」。这里识别 error 字段并暴露。
    detection_error = None
    for r in results:
        if isinstance(r, dict) and r.get("error"):
            detection_error = str(r["error"])
            break

    return {
        "is_safe": is_safe,
        "risk_level": f.get("mapped_risk_level", "无风险" if is_safe else "未知风险"),
        "category": f.get("mapped_category", "正常" if is_safe else "未知分类"),
        "confidence": f.get("confidence_score", 0.0),
        "p_safe": f.get("p_safe", 1.0 if is_safe else 0.0),
        "p_attack": f.get("p_attack", 0.0 if is_safe else 1.0),
        "decision_by": f.get("final_decision_by", "unknown"),
        "detection_error": detection_error,
    }


def _run_rag_prompt(scr: SCR_RAG_System, text: str, top_k: int = 2):
    """复用常驻 SCR 实例检索并拼接安全 prompt。"""
    ctx = scr.retrieve(text, top_k=top_k)
    prefix = scr.construct_safe_prompt(text, pre_retrieved_contexts=ctx)
    return prefix + text, len(ctx)


# ───────────────────────── 单条提示词处理（同步，在线程池跑）─────────────────────────

def _process_no_defense(prompt: str, base_url: str, model: str) -> Dict:
    record = {"prompt": prompt, "model_response": None, "error": None}
    try:
        record["model_response"] = call_llm(prompt, base_url, model)
    except Exception as e:
        record["error"] = f"LLM 调用失败: {e}"
    return record


def _process_with_shield(prompt: str, sensitivity: str, enable_rag: bool,
                         base_url: str, model: str) -> Dict:
    record = {"prompt": prompt, "model_response": None, "shield": None, "error": None}

    # ── 模盾层1：输入检测（占用全局槽位，限流 BERT 推理）──
    try:
        with _detect_slot():
            input_detection = _run_input_detection(_get_detector(sensitivity), prompt)
    except TimeoutError as e:
        record["error"] = str(e)
        return record
    except Exception as e:
        record["error"] = f"输入检测失败: {e}"
        return record

    # 输入检测异常（如 LLM fallback 服务不通）：不放行，暴露异常
    if input_detection.get("detection_error"):
        record["error"] = f"输入检测异常: {input_detection['detection_error']}"
        record["shield"] = {
            "is_safe": None,
            "stopped_at": "input_detection",
            "input_detection": input_detection,
            "rag": None,
            "output_detection": None,
        }
        return record

    # 输入不安全：拦截，不调 LLM
    if not input_detection["is_safe"]:
        record["shield"] = {
            "is_safe": False,
            "stopped_at": "input_detection",
            "input_detection": input_detection,
            "rag": None,
            "output_detection": None,
        }
        return record

    # ── 模盾层2：RAG 安全上下文增强（可选，详见 server_API.md「RAG 可选开关」；纯 IO 不占 BERT 额度）──
    gen_prompt = prompt
    rag_info = None
    if enable_rag:
        try:
            gen_prompt, n = _run_rag_prompt(_get_scr(), prompt)
            rag_info = {"retrieved": n}
        except Exception as e:
            rag_info = {"error": f"RAG 降级为直接生成: {e}"}

    # 调 LLM 生成
    try:
        resp = call_llm(gen_prompt, base_url, model)
    except Exception as e:
        record["error"] = f"LLM 生成失败: {e}"
        record["shield"] = {
            "is_safe": None,
            "stopped_at": "generation",
            "input_detection": input_detection,
            "rag": rag_info,
            "output_detection": None,
        }
        return record
    record["model_response"] = resp

    # ── 模盾层3：输出检测（复用常驻实例；内部 5 规则并发）──
    try:
        out = _get_output_detector().detect(prompt, resp)
        output_detection = {
            "is_safe": out.is_safe,
            "failed_rules": out.failed_rules,
            "total_rules": out.total_rules,
            "detection_error": "; ".join(out.error_rules) if out.error_rules else None,
        }
    except Exception as e:
        record["error"] = f"输出检测失败: {e}"
        record["shield"] = {
            "is_safe": None,
            "stopped_at": "output_detection",
            "input_detection": input_detection,
            "rag": rag_info,
            "output_detection": None,
        }
        return record

    # 输出检测异常（如输出检测 LLM 服务不通）：不放行，暴露异常
    if output_detection["detection_error"]:
        record["error"] = f"输出检测异常: {output_detection['detection_error']}"
        record["shield"] = {
            "is_safe": None,
            "stopped_at": "output_detection",
            "input_detection": input_detection,
            "rag": rag_info,
            "output_detection": output_detection,
        }
        return record

    record["shield"] = {
        "is_safe": output_detection["is_safe"],
        "stopped_at": None,
        "input_detection": input_detection,
        "rag": rag_info,
        "output_detection": output_detection,
    }
    return record
