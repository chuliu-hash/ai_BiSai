import os
import time
import math
import re
import requests
import torch
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Any
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 请确保这些本地依赖模块存在
from .confidence_vote import confidence_weighted_vote
from .risk_mapping import RISK_LEVEL_MAPPING, CATEGORY_NAMES

@dataclass
class DetectionResult:
    """结构化的检测结果"""
    is_safe: bool
    risk_level: str
    category: str
    confidence: float
    p_safe: float       # 安全概率
    p_attack: float     # 潜在攻击/注入概率
    decision_by: str
    raw_details: List[Dict] # 返回整个检测链路的详细数据（包含每个模型的结果）

class Detector:
    """
    提示注入防御检测器（第一步：BERT模型组检测）
    包含 LLM 回退复审机制，支持 Logprobs 置信度校验
    """

    def __init__(
        self,
        label_map: Optional[Dict[int, str]] = None,
        use_bert: bool = True,
        enable_llm_fallback: bool = True,
        llm_api_url: Optional[str] = "http://127.1.1.1:8094/v1/chat/completions",
        llm_api_model: Optional[str] = "Qwen3-input",
        llm_api_timeout: float = 30.0
    ) -> None:
        # 设备选择
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # 标签映射
        self.label_map = label_map or {0: "安全", 1: "潜在风险提示词"}
        self.models: List[Dict] = []

        # 核心开关与参数配置
        self.use_bert = use_bert
        self.enable_llm_fallback = enable_llm_fallback

        # LLM 参数初始化 (优先使用传入参数，未传则读取环境变量)
        self.llm_api_url = llm_api_url or os.environ.get("INPUT_DETECTOR_API_URL")
        self.llm_api_model = llm_api_model or os.environ.get("INPUT_DETECTOR_API_MODEL")
        self.llm_api_timeout = llm_api_timeout

    def set_bert(self, model_paths: Optional[List[str]] = None) -> None:
        if not self.use_bert:
            return
            
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "BERT")
        if model_paths is None:
            self.model_paths =  [
                os.path.join(root, "fine_tuned_model"),
                os.path.join(root, "protectai_deberta-v3-base-prompt-injection-v2"),
                os.path.join(root, "fine_tuned_model_base"),
                os.path.join(root, "mdeberta-prompt-injection-detector")
            ]
        else:
            self.model_paths = model_paths
            
        self._load_bert_models()

    def set_sensitivity(self, level: str) -> None:
        level = level.lower()
        if level not in ("low", "medium", "high"):
            print(f"[Detector] 未知强度 '{level}'，回退到 'low'")
            level = "low" 
        
        self.sensitivity = level
        
        # 阈值配置
        configs = {
            "low": {"dec_thresh": 0.97, "llm_conf": 0.7, "llm_p": (0.45, 0.55), "llm_accept": 0.99},
            "medium": {"dec_thresh": 0.5, "llm_conf": 0.7, "llm_p": (0.3, 0.7), "llm_accept": 0.80},
            "high": {"dec_thresh": 0.3, "llm_conf": 0.8, "llm_p": (0.2, 0.8), "llm_accept": 0.50}
        }
        
        cfg = configs[level]
        self.decision_threshold = cfg["dec_thresh"]
        self.llm_conf_threshold = cfg["llm_conf"]
        self.llm_p_range = cfg["llm_p"]
        self.llm_accept_threshold = cfg["llm_accept"]

        print(f"[Detector] 检测强度: {level} (BERT阈值={self.decision_threshold}, LLM采纳阈值={self.llm_accept_threshold}), use_bert:{self.use_bert}")

    def _discover_bert_model_paths(self, root: str) -> List[str]:
        if not os.path.isdir(root): 
            return []
        try:
            paths = [
                os.path.join(root, name) for name in os.listdir(root)
                if os.path.isdir(os.path.join(root, name)) and 
                os.path.isfile(os.path.join(root, name, "config.json"))
            ]
            return sorted(set(paths), key=lambda p: os.path.basename(p).lower())
        except Exception:
            return []

    def _load_bert_models(self) -> None:
        loaded_count = 0
        for path in self.model_paths:
            if not os.path.exists(path): 
                continue
            try:
                tokenizer = AutoTokenizer.from_pretrained(path)
                model = AutoModelForSequenceClassification.from_pretrained(path)
                model.to(self.device)
                model.eval()
                
                self.models.append({
                    "name": os.path.basename(path.rstrip("/\\")),
                    "path": path,
                    "tokenizer": tokenizer,
                    "model": model,
                    "injection_index": self._infer_injection_index(getattr(model, "config", None)),
                })
                loaded_count += 1
            except Exception as e:
                print(f"[Detector] 加载失败: {path}，错误: {e}")
                
        if loaded_count == 0:
            print("未能成功加载任何BERT模型。")

    def detect_with_bert_group(self, text: str) -> List[Dict]:
        results: List[Dict] = []

        # 1. BERT 组并行检测
        for entry in self.models:
            start_time = time.time()
            try:
                encoding = entry["tokenizer"](text, truncation=True, padding='max_length', max_length=512, return_tensors='pt')
                encoding = {k: v.to(self.device) for k, v in encoding.items()}
                
                with torch.no_grad():
                    outputs = entry["model"](**encoding)
                    probabilities = torch.softmax(outputs.logits, dim=-1)[0]
                    pred_idx = int(torch.argmax(outputs.logits, dim=-1).item())
                
                p_safe_val = float(probabilities[0].item())
                p_attack_val = float(probabilities[1].item())
                
                # print(f"模型：{entry['name']}, 安全: {p_safe_val:.4f}, 潜在风险提示词: {p_attack_val:.4f}")

                results.append({
                    "model_name": entry["name"],
                    "prediction": pred_idx,
                    "label": self.label_map.get(pred_idx, str(pred_idx)),
                    "confidence_score": float(probabilities[pred_idx].item()),
                    "probabilities": {"安全": p_safe_val, "潜在风险提示词": p_attack_val},
                    "p_safe": p_safe_val,
                    "p_attack": p_attack_val,
                    "response_time": time.time() - start_time,
                })
            except Exception as e:
                results.append({"model_name": entry["name"], "error": str(e), "response_time": time.time() - start_time})

        # 2. 投票与初步决策
        prob_list = [r["p_attack"] for r in results if "p_attack" in r]

        if prob_list:
            p_final, confidence_score, diag = confidence_weighted_vote(prob_list)
        else:
            p_final, confidence_score, diag = 0.0, 1.0, {}

        pred_final = 1 if p_final > self.decision_threshold else 0
        
        ensemble_p_safe = float(1.0 - p_final)
        ensemble_p_attack = float(p_final)

        ensemble_result = {
            "model_name": "ensemble_confidence_weighted_vote",
            "prediction": pred_final,
            "label": self.label_map.get(pred_final, str(pred_final)),
            "confidence_score": float(p_final if pred_final == 1 else (1.0 - p_final)),  
            "probabilities": {"安全": ensemble_p_safe, "潜在风险提示词": ensemble_p_attack},
            "p_safe": ensemble_p_safe,
            "p_attack": ensemble_p_attack,
            "response_time": sum(r.get("response_time", 0.0) for r in results),
            "vote_meta": diag,
            "final_decision_by": "bert_ensemble_only",
        }

        # 3. 决定是否 LLM 复审
        if not self.enable_llm_fallback:
            ensemble_result["decision"] = "不安全" if pred_final == 1 else "安全"
        else:
            low_p, high_p = self.llm_p_range
            needs_llm_review = (confidence_score < self.llm_conf_threshold or low_p < p_final < high_p) or not self.use_bert
            ensemble_result["decision"] = "LLM_review" if needs_llm_review else ("不安全" if p_final > self.decision_threshold else "安全")

        # 4. 执行 LLM 复审
        if ensemble_result["decision"] == "LLM_review" and self.enable_llm_fallback:
            llm_result = self._invoke_llm_fallback(text)
            
            llm_pred = llm_result.get("prediction", 0)
            llm_conf = float(llm_result.get("confidence_score", 0.0))
            llm_raw_pred = llm_result.get("llm_raw_prediction", llm_pred)  

            llm_p_attack = llm_conf if llm_raw_pred == 1 else 1.0 - llm_conf
            llm_p_safe = 1.0 - llm_conf if llm_raw_pred == 1 else llm_conf
            
            llm_result["p_safe"] = llm_p_safe
            llm_result["p_attack"] = llm_p_attack
            results.append(llm_result)

            ensemble_result.update({
                "decision": "不安全" if llm_pred == 1 else "安全",
                "final_decision_by": "llm_fallback",
                "llm_prediction": llm_pred,
                "prediction": llm_pred,
                "label": "潜在风险提示词" if llm_pred == 1 else "安全",
                "confidence_score": llm_p_attack if llm_pred == 1 else llm_p_safe,
                "probabilities": {"安全": llm_p_safe, "潜在风险提示词": llm_p_attack},
                "p_safe": llm_p_safe,       
                "p_attack": llm_p_attack,
                # 提取风险映射信息(如果存在)同步到最终结果
                "mapped_risk_level": llm_result.get("mapped_risk_level", "无风险" if llm_pred == 0 else "未知风险"),
                "mapped_category": llm_result.get("mapped_category", "正常" if llm_pred == 0 else "未知分类")
            })

        results.append(ensemble_result)
        return results

    def _invoke_llm_fallback(self, text: str) -> Dict:
        """调用 LLM 进行复审"""
        start_time = time.time()
        try:
            payload = {
                "model": self.llm_api_model,
                "messages": [{"role": "user", "content": text}],
                "max_tokens": 64,
                "temperature": 0.0,
                "top_p": 0.9,
                "stream": False,
                "logprobs": True,
                "top_logprobs": 1
            }

            resp = requests.post(self.llm_api_url, json=payload, timeout=self.llm_api_timeout)
            if resp.status_code != 200:
                print(f"[Detector] LLM API 错误 {resp.status_code}: {resp.text}")
            resp.raise_for_status()

            data = resp.json()
            choice = data.get("choices", [{}])[0]
            content = choice.get("message", {}).get("content", "").strip()
            
            text_is_unsafe = ("unsafe" in content.lower()) or content.startswith("unsafe")
            llm_raw_prediction = 1 if text_is_unsafe else 0
            
            # 安全地提取 logprob 置信度
            confidence_score = 1.0
            try:
                first_token = choice.get("logprobs", {}).get("content", [{}])[0]
                if first_token and first_token.get("logprob") is not None:
                    confidence_score = math.exp(first_token["logprob"])
            except (IndexError, AttributeError, TypeError):
                pass
            
            final_is_unsafe = text_is_unsafe and (confidence_score >= self.llm_accept_threshold)

            code = None
            risk_level_str = "无风险"
            category_name_str = "正常"

            if final_is_unsafe:
                m = re.search(r"\bS\d{1,2}\b", content)
                if m:
                    code = m.group(0) 
                    risk_level_str = RISK_LEVEL_MAPPING.get(code, "中风险") 
                    category_name_str = CATEGORY_NAMES.get(code, code)     
                else:
                    risk_level_str = "中风险"
                    category_name_str = "未知类别攻击"

            if risk_level_str == "低风险":
                final_is_unsafe = False

            return {
                "model_name": "llm_fallback",
                "prediction": 1 if final_is_unsafe else 0,
                "label": "潜在风险提示词" if final_is_unsafe else "安全",
                "response_time": time.time() - start_time,
                "llm_raw_response": content,
                "confidence_score": confidence_score,
                "llm_raw_prediction": llm_raw_prediction,
                "risk_code": code,
                "mapped_risk_level": risk_level_str,
                "mapped_category": category_name_str
            }

        except Exception as e:
            print(f"[Detector] LLM复审异常: {e}")
            return {
                "model_name": "llm_fallback",
                "prediction": 0,
                "label": "安全",
                "confidence_score": 0.0,
                "error": str(e),
                "response_time": time.time() - start_time,
                "llm_raw_prediction": 0,  
            }

    def _infer_injection_index(self, config) -> int:
        try:
            id2label = getattr(config, "id2label", {})
            items = id2label.items() if isinstance(id2label, dict) else enumerate(id2label)
            
            for k, v in items:
                if isinstance(v, str) and any(s in v.lower() for s in ["injection", "unsafe", "attack"]):
                    return int(k)
        except Exception:
            pass
        return 1

    def batch_detect(self, texts: List[str]) -> List[Dict]:
        """批量检测多个文本。"""
        results = []
        for text in texts:
            step_results = self.detect_with_bert_group(text)
            results.append(step_results[-1])
        return results


def detect_input(
    text: str,
    sensitivity: str = "low",
    use_bert: bool = True,
    llm_api_url: Optional[str] = None,
    llm_api_model: Optional[str] = None,
    **kwargs
) -> DetectionResult:
    """
    便捷的输入提示词检测函数。
    支持灵活配置是否使用 BERT、以及本地或云端大模型的 URL 和名称。
    """
    # 1. 实例化检测器（None 值不传入，使用 Detector 类内的默认值）
    detector_kwargs = {"use_bert": use_bert}
    if llm_api_url is not None:
        detector_kwargs["llm_api_url"] = llm_api_url
    if llm_api_model is not None:
        detector_kwargs["llm_api_model"] = llm_api_model
    detector_kwargs.update(kwargs)

    detector = Detector(**detector_kwargs)
    
    # 2. 启动 BERT 模型组
    if use_bert:
        detector.set_bert()
    
    # 3. 设置检测敏感度及阈值参数
    detector.set_sensitivity(sensitivity)
    
    # 4. 执行检测
    results = detector.detect_with_bert_group(text)
    
    final_result = results[-1]
    is_safe = final_result.get("prediction") == 0
    
    # 提取概率
    probs_dict = final_result.get("probabilities", {})
    p_safe = final_result.get("p_safe", probs_dict.get("安全", 1.0 if is_safe else 0.0))
    p_attack = final_result.get("p_attack", probs_dict.get("潜在风险提示词", 0.0 if is_safe else 1.0))
    
    # 提取风险映射
    risk_level = final_result.get("mapped_risk_level", "无风险" if is_safe else "未知风险")
    category = final_result.get("mapped_category", "正常" if is_safe else "未知分类")
    
    
    return DetectionResult(
        is_safe=is_safe,
        risk_level=risk_level,
        category=category,
        confidence=final_result.get("confidence_score", 0.0),
        p_safe=float(p_safe),
        p_attack=float(p_attack),
        decision_by=final_result.get("final_decision_by", "unknown"),
        raw_details=results
    )