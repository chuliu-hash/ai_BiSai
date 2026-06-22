# -*- coding: utf-8 -*-
"""Demo 防御 A：关键词黑名单（纯规则，无 BERT/LLM 依赖）。

命中攻击/注入关键词 → 1（不安全），否则 0（安全）。用于测试多队伍调度。
"""

# 攻击/注入常见关键词（中英文）
BLACKLIST = [
    # —— 注入指令 ——
    "忽略", "ignore", "disregard", "无视",
    "之前的指令", "previous instruction", "prior prompt", "above rules",
    # —— 越狱 ——
    "dan", "越狱", "jailbreak", "developer mode", "root mode",
    "没有任何限制", "no restrictions", "不受任何", "不受限制",
    "扮演", "roleplay", "role play", "假装你是", "act as",
    # —— 系统提示泄露 ——
    "系统提示", "system prompt", "system instruction", "system message",
    "developer message", "开发者指令",
    "输出你的提示词", "reveal your", "show your prompt", "repeat your system",
    # —— 注入术语 ——
    "prompt injection", "提示注入", "insert question",
]


def Detect(user_prompt: str) -> int:
    """赛题接口：命中黑名单关键词返回 1，否则 0。"""
    text = (user_prompt or "").lower()
    for kw in BLACKLIST:
        if kw.lower() in text:
            return 1
    return 0
