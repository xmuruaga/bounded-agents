# Enforcement latency

## Reproduce

```
python scripts/benchmark_latency.py --protocol appendix-d \
    --output evals/latency/results/latency_appendix_d.json
```

Implements the protocol documented in Appendix D of the paper: 20,000 timed
iterations after 500 warmup iterations, nearest-rank percentiles, five
independent repetitions reporting the median and the range across repetitions,
the admit path enforced (the run aborts if any timed call fails to reach an
admit decision through all six conditions), and the session rebuilt every 20
actions outside the timed region because budget consumption accumulates.

Measures the in-process authorization path only. Excludes model inference,
network round-trips, remote PDP retrieval and evidence-sink I/O. Absolute values
are hardware-dependent; `results/latency_appendix_d.json` records CPU, core and
thread counts, base clock, OS build, RAM, CPython version, the exact command,
the commit SHA, whether the tree was dirty, and a UTC timestamp.

The legacy `--protocol legacy` mode is retained for backwards compatibility but
**does not** reproduce the reported figures: its fixture sets
`max_blast_radius=0.5` while each timed action consumes `blast_radius=0.1`, so
the budget exhausts after five admits and every later `pdp.evaluate()` returns
on the "budget exhausted" fast path. It measures the deny path.

## Measured vs reported

Measured on the host documented in Appendix D (Intel Core i5-1245U, 10 cores /
12 threads, 1.6 GHz base, 16 GB, Windows 11 build 26200, CPython 3.11.9),
commit `edd5fae`, clean tree.

| Component | p50 measured | p50 pre-reconciliation [range] | p99 measured | p99 pre-reconciliation [range] |
|---|---|---|---|---|
| Full admissibility, C4 below threshold | 0.0493 | 0.060 [0.058–0.069] | 0.2403 | 0.310 [0.226–0.342] |
| Full admissibility, C4 token verified | 0.0567 | 0.069 [0.067–0.074] | 0.2363 | 0.323 [0.277–0.347] |
| Composition closure (isolated) | 0.0016 | 0.0013 [0.0013–0.0024] | 0.0031 | 0.0032 [0.0019–0.0054] |
| Envelope narrowing (meet + re-sign) | 0.0153 | 0.016 [0.016–0.027] | 0.0589 | 0.062 [0.040–0.101] |

All milliseconds. The table above records the state **before** the paper was
reconciled with this artifact: the pre-reconciliation figures in Appendix D were
0.060/0.310 and 0.069/0.323 for the two admissibility rows, which this artifact
does not reproduce as medians. Appendix D now reports the values measured here,
so Table 12 of the paper is a direct transcription of
`results/latency_appendix_d.json` and the validator asserts the two agree.

## Load sensitivity

The protocol requires an otherwise idle host. That precondition is a requirement,
not a formality. Two further executions on the same machine while other workloads
were running:

| Execution | Full admissibility p50 | Full admissibility p99 |
|---|---|---|
| `latency_appendix_d.json` (in protocol, idle) | 0.049 | 0.240 |
| `latency_appendix_d_rerun.json` (loaded) | 0.091 | 0.427 |
| `latency_appendix_d_rerun2.json` (loaded) | 0.083 | 0.345 |

Roughly a factor of two in both statistics. The loaded runs are committed as
evidence of the spread; they are **not** the basis for any figure in the paper.

Every execution, in protocol or not, stays below the **0.5 ms p99** bound quoted
in the abstract. That bound is the claim to prefer in summary text: it holds
across all measured conditions, whereas a specific median does not survive a
loaded host.
