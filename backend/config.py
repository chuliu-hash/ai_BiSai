"""配置：环境常量 + 并发原语 + 检测器单例（线程安全懒加载）。"""
from _bootstrap import _HERE  # noqa: F401  确保 .env 已加载（须早于 defend）

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Dict

from defend.prompt_detection import Detector
from defend.scr import SCR_RAG_System
from defend.safety_detector import SafetyDetector

# ── 环境常量 ──
DEFAULT_LLM_BASE_URL = os.environ.get("LLM_SERVER_URL", "http://127.0.0.1:8000/v1")
DEFAULT_LLM_MODEL = os.environ.get("LLM_SERVER_MODEL", "Qwen3")
MAX_CONCURRENT_DETECT = int(os.environ.get("MAX_CONCURRENT_DETECT", "12"))
DETECT_QUEUE_TIMEOUT = float(os.environ.get("DETECT_QUEUE_TIMEOUT", "120"))
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "60"))

# ── 并发原语 ──
# 全局并发闸门：限制同时在跑 BERT 输入检测的请求数
_detect_sem = threading.BoundedSemaphore(MAX_CONCURRENT_DETECT)
# 通用线程池：把阻塞的检测/生成丢过来，不卡事件循环
_req_pool = ThreadPoolExecutor(max_workers=max(MAX_CONCURRENT_DETECT * 2, 16), thread_name_prefix="attack")

# ── 单例缓存 ──
_singletons: Dict = {}
_singleton_lock = threading.Lock()


def _get_detector(sensitivity: str) -> Detector:
    """按 sensitivity 取常驻 Detector（三档独立实例，避免阈值竞态）。"""
    sensitivity = sensitivity if sensitivity in ("low", "medium", "high") else "low"
    key = ("detector", sensitivity)
    if key not in _singletons:
        with _singleton_lock:
            if key not in _singletons:
                d = Detector()
                d.set_bert()
                d.set_sensitivity(sensitivity)
                _singletons[key] = d
    return _singletons[key]


def _get_scr() -> SCR_RAG_System:
    key = ("scr",)
    if key not in _singletons:
        with _singleton_lock:
            if key not in _singletons:
                _singletons[key] = SCR_RAG_System()
    return _singletons[key]


def _get_output_detector() -> SafetyDetector:
    key = ("output",)
    if key not in _singletons:
        with _singleton_lock:
            if key not in _singletons:
                _singletons[key] = SafetyDetector()
    return _singletons[key]


@contextmanager
def _detect_slot(timeout: float = DETECT_QUEUE_TIMEOUT):
    """占用一个全局 BERT 检测槽位；排队超时抛 TimeoutError。"""
    got = _detect_sem.acquire(timeout=timeout)
    if not got:
        raise TimeoutError(f"检测并发达上限({MAX_CONCURRENT_DETECT})，排队超时")
    try:
        yield
    finally:
        _detect_sem.release()
