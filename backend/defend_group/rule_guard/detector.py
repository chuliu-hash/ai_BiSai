# -*- coding: utf-8 -*-
"""rule_guard detector：三层规则。

1. 关键词黑名单（中英文注入/越狱/泄露术语）
2. 注入句式正则（模板化攻击、token 标记、编码绕过）
3. Base64 解码探测：解码后若命中黑名单也算不安全
"""
import base64
import binascii
import re

BLACKLIST = [
    # 注入指令
    "忽略", "ignore", "disregard", "无视", "previous instruction",
    "之前的指令", "prior prompt", "above rules", "之前所有",
    # 越狱
    "dan", "越狱", "jailbreak", "developer mode", "root mode",
    "没有任何限制", "no restrictions", "不受任何", "不受限制",
    "扮演", "roleplay", "role play", "假装你是", "act as",
    "do anything now",
    # 系统提示泄露
    "系统提示", "system prompt", "system instruction", "system message",
    "developer message", "开发者指令",
    "输出你的提示词", "reveal your", "show your prompt",
    "repeat your system", "复述",
    # 注入术语
    "prompt injection", "提示注入", "insert question",
    # 敏感数据
    "api key", "access token", "webhook secret", "数据库连接",
    "身份证号", "手机号", "薪资", "hr 系统",
]

PATTERNS = [
    r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(the\s+)?(above|all|previous|prior)",
    r"you\s+are\s+(now|a)\s+(dan|jailbreak|root|developer)",
    r"(system|developer|hidden)\s+(prompt|instruction|message|context)",
    r"reveal\s+(your|the)\s+(system|hidden|original)\s+(prompt|instructions?)",
    r"repeat\s+(your|the)\s+(system|initial)\s+(prompt|message)",
    r"<\|im_start\|", r"<\|system\|>", r"<\|endoftext\|>",
    r"act\s+as.{0,20}(unrestricted|without rules|no restrictions)",
    r"do\s+anything\s+now",
    r"忽略(之前|以上|前面|上文).{0,10}(指令|提示|规则|内容)",
    r"无视.{0,8}(指令|规则|限制)",
    r"你现在.{0,12}(是|扮演).{0,18}(没有|不受|无).{0,6}(限制|约束)",
    r"(输出|告诉我|展示|复述).{0,12}(你的|系统).{0,8}(提示词|指令|prompt|规则)",
    r"(dan|越狱).{0,8}(模式|激活|开启)",
    r"假装.{0,10}(没有|无).{0,6}(限制|道德|规则|约束)",
    r"角色扮演.{0,15}(黑客|不受|没有)",
    # Base64 片段
    r"\[[A-Za-z0-9+/=]{16,}\]",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]


def _try_decode_b64(text: str) -> str:
    """尝试抽取形如 [xxxx] 或纯 base64 片段并解码，返回拼接结果。"""
    out = []
    # 形如 [base64]
    for m in re.findall(r"\[([A-Za-z0-9+/=]{12,})\]", text):
        try:
            dec = base64.b64decode(m, validate=True).decode("utf-8", "ignore")
            out.append(dec)
        except (binascii.Error, ValueError):
            pass
    return " ".join(out)


def Detect(user_prompt: str) -> int:
    """命中黑名单 / 正则 / 解码后命中 → 1（不安全），否则 0。"""
    text = (user_prompt or "").lower()
    candidates = [text]
    decoded = _try_decode_b64(user_prompt or "")
    if decoded:
        candidates.append(decoded.lower())

    for t in candidates:
        for kw in BLACKLIST:
            if kw in t:
                return 1
        for pat in _COMPILED:
            if pat.search(t):
                return 1
    return 0
