import numpy as np

def ndcg_at_k(predicted_ranking, reference_ranking, k):
    """Computes Normalized Discounted Cumulative Gain at K."""
    if len(predicted_ranking) == 0:
        return 0.0
    
    # relevance is defined as inverse of reference priority (higher priority = smaller rank number)
    # e.g., max_rank - rank
    max_rank = len(reference_ranking)
    rel = {cve: max_rank - rank + 1 for cve, rank in zip(reference_ranking, range(1, len(reference_ranking) + 1))}
    
    dcg = 0.0
    for i, p in enumerate(predicted_ranking[:k]):
        dcg += (2 ** rel.get(p, 0) - 1) / np.log2(i + 2)
        
    idcg = 0.0
    ideal_ranking = sorted(reference_ranking, key=lambda x: rel.get(x, 0), reverse=True)
    for i, p in enumerate(ideal_ranking[:k]):
        idcg += (2 ** rel.get(p, 0) - 1) / np.log2(i + 2)
        
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

def precision_at_k(predicted, reference, k):
    pred_set = set(predicted[:k])
    ref_set = set(reference[:k])
    if not pred_set:
        return 0.0
    return len(pred_set.intersection(ref_set)) / k

def recall_at_k(predicted, reference, k):
    pred_set = set(predicted[:k])
    ref_set = set(reference[:k])
    if not ref_set:
        return 0.0
    return len(pred_set.intersection(ref_set)) / len(ref_set)

def f1_at_k(predicted, reference, k):
    p = precision_at_k(predicted, reference, k)
    r = recall_at_k(predicted, reference, k)
    if p + r == 0:
        return 0.0
    return 2 * p * r / (p + r)

def bootstrap_ci(metric_fn, predicted, reference, k=None, n=1000, alpha=0.05):
    """Calculates bootstrap confidence intervals for a given metric."""
    scores = []
    pairs = list(zip(predicted, reference))
    size = len(pairs)
    
    for _ in range(n):
        idx = np.random.randint(0, size, size)
        boot_pred = [predicted[i] for i in idx]
        boot_ref = [reference[i] for i in idx]
        
        if k is not None:
            score = metric_fn(boot_pred, boot_ref, k)
        else:
            score = metric_fn(boot_pred, boot_ref)
        scores.append(score)
        
    scores.sort()
    lower = scores[int((alpha/2) * n)]
    upper = scores[int((1 - alpha/2) * n)]
    return lower, upper
