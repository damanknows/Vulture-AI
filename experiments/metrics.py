import numpy as np

def ndcg_at_k(predicted_ranking, relevance_dict, k):
    """Computes Normalized Discounted Cumulative Gain at K using provided relevance labels."""
    if len(predicted_ranking) == 0:
        return 0.0
    
    dcg = 0.0
    for i, p in enumerate(predicted_ranking[:k]):
        rel = relevance_dict.get(p, 0)
        dcg += (2 ** rel - 1) / np.log2(i + 2)
        
    idcg = 0.0
    # Ideal ranking sorts ALL items by relevance descending
    ideal_ranking = sorted(relevance_dict.keys(), key=lambda x: relevance_dict[x], reverse=True)
    for i, p in enumerate(ideal_ranking[:k]):
        rel = relevance_dict.get(p, 0)
        idcg += (2 ** rel - 1) / np.log2(i + 2)
        
    return dcg / idcg if idcg > 0 else 0.0

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
            
    return 1 - (6 * d_sq) / (n * (n**2 - 1))
