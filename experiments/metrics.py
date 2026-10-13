import numpy as np

def ndcg_at_k(predicted_ranking, relevance_dict, k=10):
    """Computes Normalized Discounted Cumulative Gain at K using standard exponential DCG."""
    if len(predicted_ranking) == 0 or k <= 0:
        return 0.0
    
    dcg = 0.0
    for i, p in enumerate(predicted_ranking[:k]):
        rel = relevance_dict.get(p, 0)
        dcg += (2 ** rel - 1) / np.log2(i + 2)
        
    idcg = 0.0
    ideal_sorted_cves = sorted(relevance_dict.keys(), key=lambda x: relevance_dict[x], reverse=True)
    for i, p in enumerate(ideal_sorted_cves[:k]):
        rel = relevance_dict.get(p, 0)
        idcg += (2 ** rel - 1) / np.log2(i + 2)
        
    return float(round(dcg / idcg, 4)) if idcg > 0 else 0.0

def precision_at_k(predicted_ranking, relevance_dict, k=10, threshold=3):
    """Computes Precision at K for items with relevance >= threshold."""
    if not predicted_ranking or k <= 0:
        return 0.0
    top_k = predicted_ranking[:k]
    hits = sum(1 for cve in top_k if relevance_dict.get(cve, 0) >= threshold)
    return float(round(hits / k, 4))

def recall_at_k(predicted_ranking, relevance_dict, k=10, threshold=3):
    """Computes Recall at K for items with relevance >= threshold."""
    if not predicted_ranking or k <= 0:
        return 0.0
    total_relevant = sum(1 for rel in relevance_dict.values() if rel >= threshold)
    if total_relevant == 0:
        return 0.0
    top_k = predicted_ranking[:k]
    hits = sum(1 for cve in top_k if relevance_dict.get(cve, 0) >= threshold)
    return float(round(hits / total_relevant, 4))

def spearman_correlation(predicted, reference):
    """Computes Spearman Rank Correlation Coefficient."""
    if not predicted or not reference:
        return 0.0
    
    n = len(predicted)
    ref_dict = {cve: i for i, cve in enumerate(reference)}
    pred_dict = {cve: i for i, cve in enumerate(predicted)}
    
    d_sq = 0
    for cve in predicted:
        if cve in ref_dict:
            d_sq += (pred_dict[cve] - ref_dict[cve]) ** 2
            
    val = 1 - (6 * d_sq) / (n * (n**2 - 1))
    return float(round(val, 4))
