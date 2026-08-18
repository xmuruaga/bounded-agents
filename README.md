# Bounded Agents: Delegation Security for Multi-Agent AI Systems

**Agentic Principal Chain (APC) — Reference Implementation**

[![arXiv](https://img.shields.io/badge/arXiv-2608.15888-b31b1b.svg)](https://arxiv.org/abs/2608.15888)
[![CI](https://github.com/xmuruaga/bounded-agents/actions/workflows/ci.yml/badge.svg)](https://github.com/xmuruaga/bounded-agents/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-215%20passed-brightgreen.svg)](#testing)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg)](#testing)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

This repository contains the reference implementation and evaluation artifact for the paper *Bounded Agents: Delegation Security for Multi-Agent AI Systems* ([arXiv:2608.15888](https://arxiv.org/abs/2608.15888)).

📄 **[Paper on arXiv](https://arxiv.org/abs/2608.15888)** · **[PDF in this repo](paper/bounded-agents.pdf)** · **[LaTeX source](paper/main.tex)**

`paper/bounded-agents.pdf` is the official arXiv-stamped PDF of v1, byte-for-byte as served by arXiv. `paper/main.tex` and `paper/references.bib` are the LaTeX source submitted for that version.

## The Problem

Today's agent authorization asks one question per action: *is this actor allowed to do this thing?* That is not enough when authority is delegated across hops and exercised over a stateful session. Two failures follow. Authority does not attenuate as it passes from user to orchestrator to sub-agent to tool, so a compromised sub-agent inherits the full grant. And individually authorized actions compose into prohibited outcomes: reading a confidential document and sending an external email are each permitted, but together they are exfiltration.

**Agentic Principal Chain (APC)** makes delegated authority a first-class, enforced object. Scope narrows monotonically at every hop, and every proposed action must satisfy six conjunctive conditions — identity, scope and composition, context, approval, evidence, and intent — with no scoring and no overrides. Composition restrictions are evaluated over session history, not per action in isolation. The result: exfiltration attack success rate drops to 0% across the deterministic benchmarks and all four AgentDojo compromised-model suites, at roughly −8.6 pp task utility.

## Requirements

- Python 3.11 or newer
- **Zero runtime dependencies** for the core library and all deterministic evaluations
- AWS Bedrock credentials only for the two live-LLM AgentDojo evaluations (optional)

## Quick Start

```bash
git clone https://github.com/xmuruaga/bounded-agents.git
cd bounded-agents
uv pip install -e ".[dev]"          # or: pip install -e ".[dev]"
pytest                              # 215 tests — validates all formal properties
python scripts/demo.py              # executable walkthrough of the six conditions
python scripts/verify_numbers.py    # cross-checks every number in the paper against result files
python scripts/benchmark_latency.py # rerun local authorization-path latency benchmark
```

All formal properties, delegation chain scenarios, adaptive attacks, and deterministic benchmarks run locally with zero external dependencies. `verify_numbers.py` also re-checks the headline figures directly against `paper/main.tex`, the LaTeX source submitted to arXiv.

## Paper-to-Code Mapping

| Paper Section | Code | Tests | What it validates |
|---|---|---|---|
| §4.2 Authorization Scope (Def. 4.1) | `apc/core.py` | `test_core.py` | Meet-semilattice, narrowing, blast radius monotonicity (Thm. 4.6) |
| §5 Six Conditions (PDP) | `apc/pdp.py` | `test_pdp.py` | Conjunctive admissibility predicate, fail-closed behavior |
| §4.7 Composition Closure (Thm. 4.7) | `apc/compose.py` | `test_compose.py` | Pairwise restrictions, incremental checking |
| §4.7 k-tuple Extensions (Prop. 4.2) | `apc/compose.py` | `test_k_tuple.py` | Ordered subsequence matching |
| §5 C4 Approval Binding | `apc/approval.py` | `test_approval.py` | Hash-bound tokens, single-use, expiry |
| §5 C5 Evidence Commitment | `apc/pdp.py` | `test_evidence_chain.py` | SHA-256 hash chain, tamper detection, fail-closed |
| §5 C6 Intent Binding | `apc/intent.py` | `test_intent.py` | Pre-declared intent, action-resource map, graduated enforcement |
| §4.3 Delegation Budget | `apc/budget.py` | `test_budget.py` | Six budget dimensions, cumulative tracking |
| §5 Impact Calibration | `apc/calibrate.py` | `test_calibrate.py` | Expert elicitation, Bayesian estimation, sensitivity analysis |
| §6 Evaluation (all) | `evals/` | `test_adversarial.py` | 3,154 evaluation instances across 6 components |

## Reproducing Paper Claims

| Claim | How to verify | API key needed? |
|---|---|---|
| Formal properties (Thm. 4.6, Thm. 4.7, Prop. 4.2) | `pytest tests/` | No |
| 99 delegation chain scenarios (§6.1) | `python evals/delegation/run_delegation.py` | No |
| Adaptive attacks — 43 variants (§6.5) | `python evals/adaptive/run_adaptive.py` | No |
| InjecAgent — 1,054 cases (§6.2) | `python evals/injecagent/run_injecagent.py` | No |
| ASB — 400 cases (§6.3) | `python evals/asb/run_asb.py` | No |
| Latency (§6.1) | `python scripts/benchmark_latency.py` | No |
| Paper numbers vs. result files | `python scripts/verify_numbers.py` | No |
| AgentDojo utility — 4 suites (§6.4) | `python evals/agentdojo/run_multirun2.py` | Yes (Bedrock) |
| AgentDojo compromised-model (§6.4) | `python evals/agentdojo/run_compromised.py` | Yes (Bedrock) |

For AgentDojo evaluations, copy `evals/agentdojo/.env.example` to `evals/agentdojo/.env` and add your AWS Bedrock credentials (Claude Sonnet 4.6 for utility, Claude Haiku 4.5 for compromised-model).

## Repository Structure

```
apc/                  Core library (zero dependencies, ~2,500 LOC)
tests/                Test suite (215 tests, 90% statement coverage of apc/)
evals/                Evaluation harnesses (6 components, 3,154 evaluation instances)
  adaptive/           23 named attacks, 43 variants (§6.5)
  delegation/         99 multi-hop scenarios, depths 2–8 (§6.1)
  injecagent/         1,054 deterministic cases (§6.2)
  asb/                400 deterministic cases (§6.3)
  agentdojo/          4 suites, utility + compromised-model (§6.4)
  head_to_head/       Mechanism-class comparison (Appendix C)
scripts/              Demo, latency benchmark, number verification, charts
docs/                 Interactive demo and evaluation dashboard
paper/                Compiled PDF plus the LaTeX source submitted to arXiv
```

### Data included vs. fetched separately

All result files needed to reproduce every number in the paper are committed under `evals/*/results/`. The deterministic benchmark inputs (InjecAgent and ASB test cases, under `evals/injecagent/data/` and `evals/asb/data/`) are adapted from the upstream benchmarks and included directly — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution. The AgentDojo suites are installed from the upstream package via `evals/requirements-evals.txt`; nothing else needs downloading.

## Evaluation Summary

3,154 evaluation instances across two deterministic benchmarks, four AgentDojo domains, 99 delegation-chain scenarios, and 43 adaptive-attack variants. The AgentDojo utility and compromised-model cohorts are drawn from the same task–injection space and are not disjoint.

| Component | Cases | Type | Key Result |
|-----------|-------|------|------------|
| Delegation chains | 99 | Multi-hop (2–8 hops) | 99/99, all 6 conditions validated |
| InjecAgent | 1,054 | Deterministic | Data stealing ASR 100% → **0%** |
| ASB | 400 | Deterministic | Disruptive ASR 100% → **0%** |
| AgentDojo (utility) | 949 | Live LLM, 4 suites | Weighted Δ interactive ≈ −8.6 pp |
| AgentDojo (compromised) | 609 | Live LLM, 4 suites | Exfil **0%** all suites; manip. 12.1% aggregated |
| Adaptive | 43 | APC-aware adversary | 23/24 prohibited-outcome variants blocked; session splitting admitted by design |

See [docs/evaluation.html](docs/evaluation.html) for interactive drill-down into every case.

## The Six Conditions

Every proposed action must pass all six (conjunctive — no scoring, no overrides):

| # | Condition | Question |
|---|-----------|----------|
| C1 | Identity Binding | Is the actor bound to a verifiable identity in the principal chain? |
| C2 | Scope + Composition | Is the action within scope, composition restrictions, and budget? |
| C3 | Context Binding | Is the action bound to the correct session and policy version? |
| C4 | Approval Binding | Does a high-impact action have a valid, hash-bound approval token? |
| C5 | Evidence Commitment | Is the evidence sink reachable (fail-closed)? |
| C6 | Intent Binding | Is the action relevant to the declared task? |

## Testing

```bash
pytest                            # all 215 tests
pytest --cov=apc                  # with coverage report
python scripts/demo.py            # executable specification
python scripts/verify_numbers.py  # cross-check paper numbers against result files
```

Expected output: `215 passed`, 90% statement coverage of `apc/`, and `ALL CHECKS PASSED` from `verify_numbers.py`. The deterministic evaluation harnesses reproduce the exact numbers in the committed `results/` files; the two live-LLM AgentDojo evaluations will vary run to run, which is why the paper reports multi-run means (see `evals/agentdojo/results/MANIFEST.md`).

## Limitations

- **Composition restrictions are authored, not inferred.** The restriction set is written per security domain by a human using an action-class taxonomy. Coverage is measured relative to an enumerated set of prohibited outcomes, not to all possible harmful action sequences (paper §5, §7).
- **Session splitting is admitted by design.** Of the 43 adaptive-attack variants, one prohibited-outcome variant is not blocked: an adversary that splits a prohibited composition across separate sessions. Composition closure is defined over a single session's history.
- **Utility cost is real.** Interactive task utility drops roughly 8.6 pp (weighted) under APC on the AgentDojo suites. APC trades some capability for bounded authority.
- **Impact calibration relies on expert judgment.** The impact scores driving approval thresholds come from expert elicitation; different security teams may derive different values. Sensitivity analysis is in `apc/calibrate.py`.
- **Reference implementation, not production infrastructure.** `apc/` is written for clarity and verifiability against the paper's formal claims. It has no persistence layer, no distributed policy store, and no production hardening.
- **AgentDojo cohorts are not disjoint.** The utility and compromised-model cohorts are drawn from the same task–injection space.

## Citation

```bibtex
@misc{muruaga2026bounded,
  title         = {Bounded Agents: Delegation Security for Multi-Agent AI Systems},
  author        = {Muruaga, Xabier},
  year          = {2026},
  eprint        = {2608.15888},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2608.15888}
}
```

The version of this repository that reproduces the arXiv results is tagged [`v1.0.0`](https://github.com/xmuruaga/bounded-agents/releases/tag/v1.0.0).

## License

Apache 2.0 — see [LICENSE](LICENSE).

Third-party benchmark data redistributed here (InjecAgent, ASB) remains under its upstream MIT licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
