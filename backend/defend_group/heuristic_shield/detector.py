# -*- coding: utf-8 -*-
"""heuristic_shield detector：基于结构特征而非关键词。

策略（任一命中即判 1）：
1. 指令动词密度过高（单条提示中 >= 2 个祈使/操控动词）
2. 角色重置信号（"你是"/"act as"/"now you are"）
3. 多轮拼接痕迹（Q1/Q2/Qn、Scene1、[turn1]）
4. 特殊 token / 模板标记（<|...|>、[/INST]、<<SYS>>）
5. 编码/拆分绕过（base64、hex、形如 l1k3 th1s 的 leet）
6. 极短高风险指令（"reveal system prompt" 单句）
"""
import re

# 祈使/操控动词（中英）
IMPERATIVE_VERBS = [
    "忽略", "无视", "输出", "告诉我", "展示", "复述", "扮演", "假装",
    "请输出", "请告诉", "请扮演",
    "ignore", "disregard", "reveal", "repeat", "act", "show", "tell",
    "provide", "describe", "output", "explain",
]
# 角色重置触发词
ROLE_RESET = [
    r"你现在是", r"你现在.{0,6}是", r"你是.{0,10}(dan|root|developer|jailbreak)",
    r"假装你是", r"扮演",
    r"you are now", r"act as", r"pretend you", r"roleplay",
]
# 特殊 token / 模板
TEMPLATE_TOKENS = [
    r"<\|im_start\|", r"<\|system\|>", r"<\|endoftext\|>",
    r"<<sys>>", r"[/inst]", r"\[/?inst\]", r"<\s*system\s*>",
]
# 多轮 / 场景标记
MULTI_TURN = [
    r"q\s*1\b", r"q\s*2\b", r"q\s*n\b",
    r"turn\s*1", r"scene\s*1", r"\[turn\d", r"第.{1,3}轮",
]
# 编码绕过
ENCODING_HINTS = [
    r"\[[A-Za-z0-9+/=]{16,}\]",          # [base64]
    r"0x[0-9a-fA-F]{8,}",                   # hex
    r"\b[a-z0-9]*1[a-z0-9]*3[a-z0-9]*\b", # leet 痕迹如 l1k3
]
# 极短高风险短语
SHORT_RISK = [
    r"^\s*(reveal|repeat|show)\s+(your|the)\s+(system|initial|hidden)\s+(prompt|message|instructions?)\s*[.??]*\s*$",
    r"^\s*do anything now\s*$",
]

_IMP_COMPILED = [re.compile(re.escape(v), re.IGNORECASE) for v in IMPERATIVE_VERBS]
_ROLE_COMPILED = [re.compile(p, re.IGNORECASE) for p in ROLE_RESET]
_TPL_COMPILED = [re.compile(p, re.IGNORECASE) for p in TEMPLATE_TOKENS]
_MULTI_COMPILED = [re.compile(p, re.IGNORECASE) for p in MULTI_TURN]
_ENC_COMPILED = [re.compile(p, re.IGNORECASE) for p in ENCODING_HINTS]
_SHORT_COMPILED = [re.compile(p, re.IGNORECASE) for p in SHORT_RISK]


def Detect(user_prompt: str) -> int:
    """启发式判定：不依赖关键词黑名单，而看攻击的结构特征。"""
    text = user_prompt or ""

    # 1. 指令动词密度
    imp_hits = sum(1 for r in _IMP_COMPILED if r.search(text))
    if imp_hits >= 2:
        return 1

    # 2. 角色重置
    for r in _ROLE_COMPILED:
        if r.search(text):
            return 1

    # 3. 多轮拼接
    hits = sum(1 for r in _MULTI_COMPILED if r.search(text))
    if hits >= 2:
        return 1

    # 4. 模板 token
    for r in _TPL_COMPILED:
        if r.search(text):
            return 1

    # 5. 编码绕过
    for r in _ENC_COMPILED:
        if r.search(text):
            return 1

    # 6. 极短高风险
    for r in _SHORT_COMPILED:
        if r.search(text):
            return 1

    return 0
