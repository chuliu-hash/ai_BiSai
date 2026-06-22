# -*- coding: utf-8 -*-
"""Demo 防御 B：注入特征正则（纯规则，无 BERT/LLM 依赖）。

用正则匹配常见提示注入/越狱模式，命中 → 1（不安全），否则 0。
与 keyword_blacklist 互补：捕捉变体、模板化注入。
"""
import re

PATTERNS = [
    # —— 英文注入模板 ——
    r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(the\s+)?(above|all|previous|prior)",
    r"you\s+are\s+(now|a)\s+(dan|jailbreak|root|developer)",
    r"(system|developer|hidden)\s+(prompt|instruction|message|context)",
    r"reveal\s+(your|the)\s+(system|hidden|original)\s+(prompt|instructions?)",
    r"repeat\s+(your|the)\s+(system|initial)\s+(prompt|message)",
    r"<\|im_start\|", r"<\|system\|>", r"<\|endoftext\|>",
    r"act\s+as.{0,20}(unrestricted|without rules|no restrictions)",
    r"do\s+anything\s+now",
    # —— 中文注入模板 ——
    r"忽略(之前|以上|前面|上文).{0,10}(指令|提示|规则|内容)",
    r"无视.{0,8}(指令|规则|限制)",
    r"你现在.{0,12}(是|扮演).{0,18}(没有|不受|无).{0,6}(限制|约束)",
    r"(输出|告诉我|展示|复述).{0,12}(你的|系统).{0,8}(提示词|指令|prompt|规则)",
    r"(dan|越狱).{0,8}(模式|激活|开启)",
    r"假装.{0,10}(没有|无).{0,6}(限制|道德|规则|约束)",
    r"角色扮演.{0,15}(黑客|不受|没有)",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]


def Detect(user_prompt: str) -> int:
    """赛题接口：命中任一注入模式返回 1，否则 0。"""
    text = user_prompt or ""
    for pat in _COMPILED:
        if pat.search(text):
            return 1
    return 0
