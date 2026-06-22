# 防御队伍提交规范

每支队伍把自己的防御代码作为一个 Python 子包放入，统一调用其 `Detect` 接口完成检测。

---

## 1. 目录结构（硬性要求）

```
defend_group/
└── <队名>/              ← 合法 Python 标识符：字母/数字/下划线，勿用中文、空格、连字符
    ├── __init__.py      ← 必须！且必须暴露 Detect
    └── (其余文件随意)    ← detector.py / 模型权重 / 规则表 等
```

**两条硬性约束**（任一不满足，该队伍不会被识别/调用）：

1. 子包必须有 `__init__.py`（普通 Python 包）
2. `__init__.py` 必须暴露 `Detect`

---

## 2. Detect 接口规范

```python
def Detect(user_prompt: str) -> int:
    """
    参数: user_prompt —— 用户提示词（str），原样传入，服务端不做任何预处理
    返回: 0（安全）/ 1（不安全/攻击）
    """
```

| 项 | 要求 |
|----|------|
| 函数名 | 必须是 `Detect`（大小写敏感） |
| 参数 | 仅 `user_prompt`
| 返回类型 | `int`：`0` = 安全，`1` = 不安全 |
---

## 3. 最小模板

**方式 A：直接写在 `__init__.py`**

```python
# defend_group/my_team/__init__.py
def Detect(user_prompt: str) -> int:
    if "忽略" in user_prompt or "ignore" in user_prompt.lower():
        return 1
    return 0
```

**方式 B：多模块，`__init__.py` 再导出**（推荐，便于组织复杂逻辑）

```python
# defend_group/my_team/__init__.py
from .detector import Detect
```

```python
# defend_group/my_team/detector.py
def Detect(user_prompt: str) -> int:
    # 你的检测逻辑（规则 / 模型 / 调外部服务均可）
    ...
    return 0  # 或 1
```

---

## 4. 返回值约定

| 返回 | 含义 |
|------|------|
| `0` | 安全（普通提示词） |
| `1` | 不安全（提示注入 / 越狱 / 违规 / 隐私泄露等攻击） |

---



---

## 8. 提交清单建议

提交压缩包内建议包含：

- `<队名>/__init__.py`（暴露 `Detect`）
- `<队名>/detector.py`（及其他源码）
- `<队名>/README.md`（说明检测思路、所用模型/规则、已知限制）
- 模型权重 / 规则文件（若体积大，按赛题要求单独提供下载或随包）

