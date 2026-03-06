#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
analyze.py — Statistical analysis of benchmark results.

Computes:
- Descriptive statistics (median, p25/p75, min/max)
- Mann-Whitney U test between two configurations
- Restore latency linear fit (R² for dirty page sweep)

Usage:
  python3 analyze.py --input results/bench_30run.json
  python3 analyze.py --compare results/1core.json results/2core.json
  python3 analyze.py --restore-sweep results/restore_sweep.json
"""

import argparse
import json
import math
import sys


def log(msg):
    print(msg, flush=True)


def mann_whitney_u(x, y):
    """Mann-Whitney U test (two-sided). No scipy dependency."""
    nx, ny = len(x), len(y)
    if nx == 0 or ny == 0:
        return None, None

    # Rank all values
    combined = [(v, 'x') for v in x] + [(v, 'y') for v in y]
    combined.sort(key=lambda t: t[0])

    # Assign ranks (handle ties by averaging)
    ranks = {}
    i = 0
    while i < len(combined):
        j = i
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + j + 1) / 2.0  # 1-based average rank
        for k in range(i, j):
            ranks.setdefault(combined[k][1], []).append(avg_rank)
        i = j

    r_x = sum(ranks.get('x', []))
    u_x = r_x - nx * (nx + 1) / 2.0
    u_y = nx * ny - u_x
    u = min(u_x, u_y)

    # Normal approximation for p-value (valid for n >= 20)
    mu = nx * ny / 2.0
    sigma = math.sqrt(nx * ny * (nx + ny + 1) / 12.0)
    if sigma == 0:
        return u, 1.0
    z = (u - mu) / sigma
    # Two-sided p-value via normal CDF approximation
    p = 2.0 * (1.0 - normal_cdf(abs(z)))
    return u, p


def normal_cdf(x):
    """Approximation of the standard normal CDF (Abramowitz & Stegun)."""
    a1 = 0.254829592
    a2 = -0.284496736
    a3 = 1.421413741
    a4 = -1.453152027
    a5 = 1.061405429
    p = 0.3275911
    sign = 1 if x >= 0 else -1
    x = abs(x)
    t = 1.0 / (1.0 + p * x)
    y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-x * x / 2.0)
    return 0.5 * (1.0 + sign * y)


def linear_fit(xs, ys):
    """Least-squares linear fit. Returns (slope, intercept, r_squared)."""
    n = len(xs)
    if n < 2:
        return 0, 0, 0
    sx = sum(xs)
    sy = sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    syy = sum(y * y for y in ys)

    denom = n * sxx - sx * sx
    if denom == 0:
        return 0, 0, 0

    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n

    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = syy - sy * sy / n
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0

    return slope, intercept, r_squared


def analyze_single(path):
    """Analyze a single 30-run result file."""
    with open(path) as f:
        data = json.load(f)

    values = data.get('exec_per_sec_values', [])
    summary = data.get('summary', {})

    log('=== Benchmark Analysis: %s ===' % path)
    log('Hardware: %s' % json.dumps(data.get('hardware', {})))
    log('Config: %s' % json.dumps(data.get('config', {})))
    log('')

    if summary:
        log('Exec/sec statistics (n=%d):' % summary.get('n', 0))
        log('  Median : %.0f' % summary.get('median', 0))
        log('  p25    : %.0f' % summary.get('p25', 0))
        log('  p75    : %.0f' % summary.get('p75', 0))
        log('  Min    : %.0f' % summary.get('min', 0))
        log('  Max    : %.0f' % summary.get('max', 0))
        log('  Mean   : %.0f' % summary.get('mean', 0))

    # Print all values for reference
    if values:
        log('')
        log('All values: %s' % ', '.join('%.0f' % v for v in values))

    return values


def analyze_compare(path_a, path_b):
    """Compare two result files with Mann-Whitney U test."""
    with open(path_a) as f:
        data_a = json.load(f)
    with open(path_b) as f:
        data_b = json.load(f)

    values_a = data_a.get('exec_per_sec_values', [])
    values_b = data_b.get('exec_per_sec_values', [])

    log('=== Mann-Whitney U Comparison ===')
    log('A: %s (n=%d)' % (path_a, len(values_a)))
    log('B: %s (n=%d)' % (path_b, len(values_b)))
    log('')

    if not values_a or not values_b:
        log('ERROR: need non-empty value arrays')
        return

    median_a = sorted(values_a)[len(values_a) // 2]
    median_b = sorted(values_b)[len(values_b) // 2]

    log('A median: %.0f exec/sec' % median_a)
    log('B median: %.0f exec/sec' % median_b)

    if median_a > 0:
        log('Ratio B/A: %.2fx' % (median_b / median_a))

    u_stat, p_value = mann_whitney_u(values_a, values_b)
    log('')
    log('Mann-Whitney U test (two-sided):')
    log('  U = %.0f' % u_stat)
    log('  p = %.6f' % p_value)
    if p_value < 0.05:
        log('  Result: SIGNIFICANT (p < 0.05)')
    else:
        log('  Result: NOT SIGNIFICANT (p >= 0.05)')

    return {
        'u_statistic': u_stat,
        'p_value': p_value,
        'median_a': median_a,
        'median_b': median_b,
        'ratio': median_b / median_a if median_a > 0 else None,
    }


def analyze_restore_sweep(path):
    """Analyze restore latency sweep for linear fit."""
    with open(path) as f:
        data = json.load(f)

    samples = data.get('samples', [])
    if not samples:
        log('ERROR: no samples in %s' % path)
        return

    log('=== Restore Latency Sweep Analysis ===')
    log('')

    xs = [s['dirty_pages'] for s in samples]
    ys = [s['total_cycles_median'] for s in samples]

    slope, intercept, r_sq = linear_fit(xs, ys)

    log('Linear fit: cycles = %.2f × dirty_pages + %.0f' % (slope, intercept))
    log('R² = %.4f' % r_sq)
    log('')

    if r_sq >= 0.95:
        log('PASS: R² >= 0.95 (linear relationship confirmed)')
    else:
        log('FAIL: R² < 0.95 (non-linear — check for outliers)')

    # Print per-component breakdown at key points
    log('')
    log('%-12s %-12s %-12s %-12s %-12s %-12s' % (
        'DirtyPages', 'Total', 'DirtyWalk', 'INVEPT', 'VMCS', 'XRSTOR'))
    log('-' * 72)
    for s in samples:
        log('%-12d %-12d %-12d %-12d %-12d %-12d' % (
            s['dirty_pages'],
            s.get('total_cycles_median', 0),
            s.get('dirty_walk_cycles_median', 0),
            s.get('invept_cycles_median', 0),
            s.get('vmcs_cycles_median', 0),
            s.get('xrstor_cycles_median', 0),
        ))

    return {'slope': slope, 'intercept': intercept, 'r_squared': r_sq}


def main():
    parser = argparse.ArgumentParser(description='Benchmark analysis')
    parser.add_argument('--input', help='Single result file to analyze')
    parser.add_argument('--compare', nargs=2, metavar=('A', 'B'),
                        help='Compare two result files (Mann-Whitney U)')
    parser.add_argument('--restore-sweep', help='Analyze restore latency sweep')
    parser.add_argument('--output', help='Write analysis to JSON file')
    args = parser.parse_args()

    result = {}

    if args.input:
        analyze_single(args.input)
    elif args.compare:
        result = analyze_compare(args.compare[0], args.compare[1])
    elif args.restore_sweep:
        result = analyze_restore_sweep(args.restore_sweep)
    else:
        parser.print_help()
        return 1

    if args.output and result:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        log('\nAnalysis written to %s' % args.output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
