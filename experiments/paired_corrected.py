"""Run from the project root: python -m experiments.paired_corrected."""

import csv
from pathlib import Path

import numpy as np

from experiments import revision_statistics as stats
from risk_engine import compute_vrs
from weight_sensitivity import get_weight_config, list_weight_configs


DATA = Path('data/benchmark/versions/cves_v2_kev_corrected_2026-11-26.csv')
SHA = '2b78d7c280ad29a1f25f06359b73453cb493974fc3a503281bad23a3d472780e'
OUT = Path('experiments/revision/statistics/paired_corrected_v2.csv')


def main():
    if stats.sha256_of(DATA) != SHA:
        raise ValueError('Corrected dataset checksum mismatch')
    findings, reference, labels = stats.load_benchmark(DATA)
    ids, checked_labels, _, _ = stats.load_labels(DATA)
    if labels != checked_labels:
        raise ValueError('Reference label mismatch')
    index = {cid: i for i, cid in enumerate(ids)}
    grades = np.array([labels[cid] for cid in ids])
    ref = stats._Ranking('reference', reference, index).pos
    rankings = stats.build_rankings(findings)
    pairs = [(stats.VRS, name) for name in rankings if name != stats.VRS]
    for config in list_weight_configs():
        weights = get_weight_config(config)
        rankings[config] = stats._rank_by_score(findings, lambda f: compute_vrs(f, weights=weights)['vrs'])
        if config != 'original':
            pairs.append(('original', config))
    models = {name: stats._Ranking(name, order, index) for name, order in rankings.items()}
    rows = []
    for strategy in stats.STRATEGIES:
        draws = stats.make_indices(len(ids), stats.DEFAULT_ITERATIONS, stats.DEFAULT_SEED, strategy, grades)
        samples = np.vstack([np.arange(len(ids)), draws])  # row zero is the observed benchmark
        values = {}
        for name, model in models.items():
            values[name] = np.array([[m[key] for key in stats.METRICS] for m in
                                     (stats.metrics_for_sample(i, model, ref, grades) for i in samples)])
        for a, b in pairs:
            for j, metric in enumerate(stats.METRICS):
                diff = values[a][:, j] - values[b][:, j]
                valid = diff[1:][np.isfinite(diff[1:])]
                lo, hi = np.percentile(valid, [2.5, 97.5])
                rows.append(dict(dataset_sha256=SHA, n=len(ids), strategy=strategy,
                                 seed=stats.DEFAULT_SEED, iterations=len(draws), n_valid=len(valid),
                                 reference_method=a, comparator=b, metric=metric,
                                 reference_observed=values[a][0,j], comparator_observed=values[b][0,j],
                                 difference=diff[0], ci_low=lo, ci_high=hi))
    with OUT.open('x', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0], lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


if __name__ == '__main__':
    main()
