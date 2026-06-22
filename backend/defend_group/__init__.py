# -*- coding: utf-8 -*-
"""防御代码集合容器。

每个子包是一支队伍上传的防御实现，必须暴露 `Detect(user_prompt) -> 0/1`。
统一服务（server）通过 group 名动态加载对应子包（懒加载，不在容器 import 时载入所有队伍）。

新增队伍：在 defend_group/ 下新建 <队名>/ 子包，内含暴露 Detect 的 __init__.py。
"""
import importlib
import pkgutil


def list_groups():
    """列出 defend_group 下所有队伍子包名（仅扫描，不 import）。"""
    return sorted(name for _, name, ispkg in pkgutil.iter_modules(__path__) if ispkg)


def get_detect(group: str):
    """动态加载某队伍子包的 Detect 函数。队伍子包必须暴露 Detect。"""
    try:
        mod = importlib.import_module(f"{__name__}.{group}")
    except ModuleNotFoundError:
        raise ModuleNotFoundError(f"队伍防御包 '{group}' 不存在；可用: {list_groups()}")
    if not hasattr(mod, "Detect"):
        raise AttributeError(f"队伍包 '{group}' 未暴露 Detect(user_prompt)")
    return mod.Detect
