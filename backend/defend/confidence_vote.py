import numpy as np


def confidence_weighted_vote(prob_list, alpha=1.5, beta=0.4, gamma=0.5):
    """
    对一组模型的恶意概率进行置信度加权投票，输出：
    - 综合恶意概率 p_final
    - 综合置信度分数 confidence_score（关注整体可靠性）
    - 诊断信息
    """
    p = np.array(prob_list, dtype=np.float64)
    if p.size == 0:
        # 无有效概率时，返回中性概率与中性置信度
        return 0.5, 0.5, {"confidences": [], "U_inter": 0.0, "ratio_pos": 0.0}

    # 模型内部置信度：靠近0或1则置信高
    conf = np.abs(p - 0.5) * 2
    conf = np.clip(conf, 1e-4, 1.0)

    # 加权平均
    weights = conf ** alpha
    p_final = float(np.sum(weights * p) / np.sum(weights))

    # 跨模型不确定性
    U_inter = float(np.var(p))
    p_final = (1 - beta * U_inter) * p_final + 0.5 * beta * U_inter

    # 检查预测方向分歧
    ratio_pos = float(np.mean(p > 0.5))
    if 0.4 < ratio_pos < 0.6:
        p_final = 0.5 + (p_final - 0.5) * (1 - gamma)

    # ---- 综合置信度分数 ----
    avg_conf = float(np.mean(conf))
    output_certainty = abs(p_final - 0.5) * 2  # 越偏离0.5越确定
    confidence_score = (
        (1 - U_inter) ** beta *
        avg_conf ** alpha *
        output_certainty ** gamma
    )

    confidence_score = float(np.clip(confidence_score, 0.0, 1.0))

    return float(p_final), float(confidence_score), {
        "confidences": conf.tolist(),
        "U_inter": float(U_inter),
        "ratio_pos": float(ratio_pos),
    }