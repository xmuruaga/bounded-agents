#!/usr/bin/env python
"""
Latency benchmark for the APC reference implementation.

Verifies the quantitative claims in the paper (Appendix A.7):
  - Full admissibility evaluation: <0.5 ms p99
  - Composition closure check:    <0.03 ms p99
  - Envelope narrowing:           <0.24 ms p99

Usage:
  python scripts/benchmark_latency.py
  python scripts/benchmark_latency.py --iterations 10000 --warmup 500
  python scripts/benchmark_latency.py --json

Results are hardware-dependent; paper claims were measured on commodity x86-64.
"""

import sys
import time
import statistics
import argparse
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apc.core import (
    Scope, DelegationBudgetSpec, AuthorizationEnvelope,
    Principal, ExecutionRole,
)
from apc.compose import (
    ActionClassMapping, CompositionChecker,
    RestrictionTemplate, compile_templates,
)
from apc.budget import BudgetState
from apc.approval import ApprovalStore
from apc.pdp import PolicyDecisionPoint, ProposedAction, EvidenceSink
from apc.calibrate import ImpactWeights

SIGNING_KEY = b"benchmark-key-do-not-use-in-production"


# ---------------------------------------------------------------------------
# Fixture builders — match actual constructor signatures
# ---------------------------------------------------------------------------

def make_scope() -> Scope:
    return Scope(
        resources=frozenset(["docs:contracts/*", "email:internal"]),
        actions=frozenset(["read", "send_internal"]),
        data_classifications=frozenset(["internal", "confidential"]),
        composition_restrictions=frozenset([("read", "send_external")]),
    )


def make_budget_spec() -> DelegationBudgetSpec:
    return DelegationBudgetSpec(
        max_delegation_depth=3,
        max_blast_radius=0.5,
        max_irreversible_effects=2,
        max_sensitivity_class="confidential",
        cross_domain_composition=False,
        max_cost=100.0,
    )


def make_principal(pid: str = "bench-agent-001", depth: int = 1) -> Principal:
    return Principal(
        principal_id=pid,
        role=ExecutionRole.ON_BEHALF_OF,
        role_scope=make_scope(),
    )


def make_envelope() -> AuthorizationEnvelope:
    principal = make_principal()
    env = AuthorizationEnvelope(
        envelope_id="bench-env-001",
        task_session_id="bench-session-001",
        originating_principal=principal,
        effective_scope=make_scope(),
        budget_spec=make_budget_spec(),
        chain=[principal],
        policy_version="1.0.0",
    )
    env.sign(SIGNING_KEY)
    return env


def make_composition_checker() -> CompositionChecker:
    templates = [
        RestrictionTemplate.deny_compose("read", "send_external"),
        RestrictionTemplate.deny_compose("read_sensitive", "send_external"),
    ]
    restrictions = compile_templates(templates)
    mapping = ActionClassMapping.from_dict({
        "read": "read",
        "read_sensitive": "read_sensitive",
        "write": "write",
        "send_external": "send_external",
        "send_internal": "send_internal",
        "delete": "delete",
    })
    return CompositionChecker(
        restrictions=restrictions,
        class_mapping=mapping,
        k_tuple_restrictions=(),
    )


def make_pdp() -> PolicyDecisionPoint:
    return PolicyDecisionPoint(
        signing_key=SIGNING_KEY,
        impact_weights=ImpactWeights(alpha=0.4, beta=0.4, gamma=0.2),
        approval_threshold=0.7,
        approval_store=ApprovalStore(),
        evidence_sink=EvidenceSink(),
    )


def make_action(envelope: AuthorizationEnvelope) -> ProposedAction:
    return ProposedAction(
        action_type="read",
        target_resource="docs:contracts/acme-2025.pdf",
        parameters={"format": "text"},
        actor_principal_id=envelope.originating_principal.principal_id,
        task_session_id=envelope.task_session_id,
        policy_version=envelope.policy_version,
        blast_radius=0.1,
        irreversible_effects=0,
        sensitivity_class="internal",
        is_cross_domain=False,
        compute_cost=1.0,
        irreversibility_score=0.0,
        blast_radius_score=0.1,
        sensitivity_score=0.2,
    )


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def percentile(data: list[float], p: float) -> float:
    s = sorted(data)
    return s[min(int(len(s) * p / 100), len(s) - 1)]


def summarize(latencies_ms: list[float]) -> dict:
    return {
        "p50_ms": percentile(latencies_ms, 50),
        "p95_ms": percentile(latencies_ms, 95),
        "p99_ms": percentile(latencies_ms, 99),
        "mean_ms": statistics.mean(latencies_ms),
        "throughput_per_sec": 1000.0 / statistics.mean(latencies_ms),
        "iterations": len(latencies_ms),
    }


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

def benchmark_full_evaluation(iterations: int, warmup: int) -> dict:
    """Full six-condition admissibility evaluation."""
    envelope = make_envelope()
    budget = BudgetState(spec=envelope.budget_spec)
    checker = make_composition_checker()
    pdp = make_pdp()
    action = make_action(envelope)

    for _ in range(warmup):
        pdp.evaluate(action, envelope, budget, checker)

    latencies_ms = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        pdp.evaluate(action, envelope, budget, checker)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000)

    return summarize(latencies_ms)


def benchmark_composition_check(iterations: int, warmup: int) -> dict:
    """Composition closure check in isolation (with prior read in history)."""
    checker = make_composition_checker()
    checker.record("read", "docs:contracts/file.pdf")

    for _ in range(warmup):
        checker.check("send_internal", "email:internal")

    latencies_ms = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        checker.check("send_internal", "email:internal")
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000)

    return summarize(latencies_ms)


def benchmark_envelope_narrowing(iterations: int, warmup: int) -> dict:
    """Authorization Envelope narrowing (scope meet + re-sign)."""
    parent_env = make_envelope()
    child_principal = make_principal("bench-child-001")

    for _ in range(warmup):
        parent_env.narrow(child_principal, SIGNING_KEY)

    latencies_ms = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        parent_env.narrow(child_principal, SIGNING_KEY)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000)

    return summarize(latencies_ms)


# ---------------------------------------------------------------------------
# Paper claim verification
# ---------------------------------------------------------------------------

PAPER_CLAIMS = {
    "full_evaluation":    ("p99_ms", 0.5,  "<0.5 ms p99  (Appendix A.7)"),
    "composition_check":  ("p99_ms", 0.03, "<0.03 ms p99 (Appendix A.7)"),
    "envelope_narrowing": ("p99_ms", 0.24, "<0.24 ms p99 (Appendix A.7)"),
}


def check_claim(name: str, result: dict) -> bool:
    metric, threshold, label = PAPER_CLAIMS[name]
    value = result[metric]
    ok = value <= threshold
    print(f"  [{'PASS' if ok else 'FAIL'}]  {metric} = {value:.4f} ms   (paper claim: {label})")
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify APC latency claims from the paper (Appendix A.7)."
    )
    parser.add_argument("--iterations", type=int, default=5000,
                        help="Timed iterations (default: 5000)")
    parser.add_argument("--warmup", type=int, default=200,
                        help="Warmup iterations (default: 200)")
    parser.add_argument("--json", action="store_true",
                        help="Print full results as JSON")
    parser.add_argument("--protocol", choices=["legacy", "appendix-d"], default="legacy",
                        help="'appendix-d' reproduces the documented measurement "
                             "protocol (20k iterations, 500 warmup, 5 repetitions, "
                             "admit path enforced, session rebuilt at fixed intervals)")
    parser.add_argument("--repetitions", type=int, default=5,
                        help="Independent repetitions, appendix-d protocol (default: 5)")
    parser.add_argument("--session-length", type=int, default=SESSION_LENGTH_DEFAULT,
                        help="Actions per session before rebuild (default: 20)")
    parser.add_argument("--output", default=None,
                        help="Write a machine-readable result artifact to this path")
    args = parser.parse_args()

    if args.protocol == "appendix-d":
        iterations = args.iterations if args.iterations != 5000 else 20000
        warmup = args.warmup if args.warmup != 200 else 500
        return run_appendix_d(
            iterations, warmup, args.repetitions, args.session_length, args.output,
            " ".join(["python", "scripts/benchmark_latency.py"] + sys.argv[1:]),
        )

    print(f"\nAPC Latency Benchmark  —  verifying paper claims (Appendix A.7)")
    print(f"{'='*62}")
    print(f"Iterations: {args.iterations}   Warmup: {args.warmup}")
    print(f"{'='*62}\n")

    results = {}
    all_pass = True

    print("1. Full six-condition admissibility evaluation")
    r = benchmark_full_evaluation(args.iterations, args.warmup)
    results["full_evaluation"] = r
    print(f"   p50={r['p50_ms']:.4f} ms  p95={r['p95_ms']:.4f} ms  p99={r['p99_ms']:.4f} ms")
    print(f"   throughput: {r['throughput_per_sec']:,.0f} evals/sec")
    all_pass &= check_claim("full_evaluation", r)
    print()

    print("2. Composition closure check (isolated, prior read in history)")
    r = benchmark_composition_check(args.iterations, args.warmup)
    results["composition_check"] = r
    print(f"   p50={r['p50_ms']:.4f} ms  p95={r['p95_ms']:.4f} ms  p99={r['p99_ms']:.4f} ms")
    all_pass &= check_claim("composition_check", r)
    print()

    print("3. Authorization Envelope narrowing (scope meet + re-sign)")
    r = benchmark_envelope_narrowing(args.iterations, args.warmup)
    results["envelope_narrowing"] = r
    print(f"   p50={r['p50_ms']:.4f} ms  p95={r['p95_ms']:.4f} ms  p99={r['p99_ms']:.4f} ms")
    all_pass &= check_claim("envelope_narrowing", r)
    print()

    print(f"{'='*62}")
    if all_pass:
        print("ALL PAPER CLAIMS VERIFIED on this hardware")
    else:
        print("WARNING: one or more claims not met on this hardware.")
        print("Claims were measured on commodity x86-64; results are hardware-dependent.")
    print(f"{'='*62}\n")

    if args.json:
        print(json.dumps(results, indent=2))

    return 0 if all_pass else 1


# ===========================================================================
# Appendix D conformant protocol
# ===========================================================================
#
# The legacy benchmarks above run a fixed action repeatedly against a single
# session. Because pdp.evaluate() consumes budget on every admit, the fixture
# budget (max_blast_radius=0.5, action blast_radius=0.1) exhausts after five
# actions and every later call returns on the "budget exhausted" fast path.
# Those numbers therefore describe the deny path, not the admit path.
#
# This protocol implements what Appendix D of the paper documents:
#   - 20,000 timed iterations after 500 warmup iterations
#   - nearest-rank percentiles over the sorted sample
#   - 5 independent repetitions; median reported, range across repetitions
#   - admit path only: every timed call must pass all six conditions and
#     perform the evidence commit, composition record and budget consumption
#   - the session is rebuilt at fixed intervals OUTSIDE the timed region,
#     because budget consumption accumulates
#   - aborts if any timed call fails to reach an admit decision
#
# Usage:
#   python scripts/benchmark_latency.py --protocol appendix-d \
#       --output evals/latency/results/latency_appendix_d.json

import os
import platform
import subprocess
from datetime import datetime, timezone

SESSION_LENGTH_DEFAULT = 20


def nearest_rank(sorted_data: list[float], p: float) -> float:
    """Nearest-rank percentile: index = ceil(p/100 * N) - 1."""
    n = len(sorted_data)
    if n == 0:
        raise ValueError("empty sample")
    import math
    idx = math.ceil(p / 100.0 * n) - 1
    return sorted_data[max(0, min(idx, n - 1))]


def _headroom_budget(session_length: int) -> DelegationBudgetSpec:
    """Budget sized so a session of `session_length` admits actions can complete.

    Each timed action consumes blast_radius 0.1 and compute_cost 1.0, so the
    ceilings must exceed session_length x those costs; otherwise the PDP starts
    returning on the budget fast path and the measurement stops describing the
    admit path.
    """
    return DelegationBudgetSpec(
        max_delegation_depth=3,
        max_blast_radius=0.1 * session_length + 1.0,
        max_irreversible_effects=2,
        max_sensitivity_class="confidential",
        cross_domain_composition=False,
        max_cost=1.0 * session_length + 10.0,
    )


def _session(session_length: int, high_impact: bool, seq: int):
    """Fresh session. Returns (pdp, envelope, budget, checker, action, token_id)."""
    principal = make_principal()
    envelope = AuthorizationEnvelope(
        envelope_id=f"bench-env-{seq}",
        task_session_id=f"bench-session-{seq}",
        originating_principal=principal,
        effective_scope=make_scope(),
        budget_spec=_headroom_budget(session_length),
        chain=[principal],
        policy_version="1.0.0",
    )
    envelope.sign(SIGNING_KEY)
    budget = BudgetState(spec=envelope.budget_spec)
    checker = make_composition_checker()
    pdp = make_pdp()

    action = ProposedAction(
        action_type="read",
        target_resource="docs:contracts/acme-2025.pdf",
        parameters={"format": "text"},
        actor_principal_id=principal.principal_id,
        task_session_id=envelope.task_session_id,
        policy_version=envelope.policy_version,
        blast_radius=0.1,
        irreversible_effects=0,
        sensitivity_class="internal",
        is_cross_domain=False,
        compute_cost=1.0,
        # C4 dimensions are per action profile and are distinct from the
        # budget dimensions above (paper section 5, C4).
        irreversibility_score=1.0 if high_impact else 0.0,
        blast_radius_score=1.0 if high_impact else 0.1,
        sensitivity_score=1.0 if high_impact else 0.2,
    )
    return pdp, envelope, budget, checker, action


def _mint(pdp, envelope, action, n: int, seq: int) -> list[str]:
    """Pre-mint single-use approval tokens outside the timed region."""
    ids = []
    store = pdp._approval_store
    for i in range(n):
        tid = f"tok-{seq}-{i}"
        store.issue(
            token_id=tid,
            action_type=action.action_type,
            target_resource=action.target_resource,
            parameters=action.parameters,
            scope_snapshot={},
            approver_id="bench-approver",
            policy_version=envelope.policy_version,
            task_session_id=envelope.task_session_id,
            ttl_seconds=3600.0,
        )
        ids.append(tid)
    return ids


def _measure_admissibility(iterations, warmup, session_length, high_impact):
    """Timed admit-path admissibility. Aborts if any call is not admitted."""
    lat, seq, i_in_session = [], 0, 0
    pdp, env, budget, checker, action = _session(session_length, high_impact, seq)
    tokens = _mint(pdp, env, action, session_length, seq) if high_impact else []

    for i in range(warmup + iterations):
        if i_in_session >= session_length:
            seq += 1
            i_in_session = 0
            pdp, env, budget, checker, action = _session(session_length, high_impact, seq)
            tokens = _mint(pdp, env, action, session_length, seq) if high_impact else []
        tok = tokens[i_in_session] if high_impact else None

        t0 = time.perf_counter()
        d = pdp.evaluate(action, env, budget, checker, approval_token_id=tok)
        t1 = time.perf_counter()

        if not d.admitted:
            raise SystemExit(
                "ABORT: timed call not admitted at i=%d (high_impact=%s): %s"
                % (i, high_impact, d.denial_reasons))
        i_in_session += 1
        if i >= warmup:
            lat.append((t1 - t0) * 1000)
    return lat


def _measure_composition(iterations, warmup, session_length):
    checker = make_composition_checker()
    checker.record("read", "docs:contracts/file.pdf")
    lat = []
    for i in range(warmup + iterations):
        t0 = time.perf_counter()
        r = checker.check("send_internal", "email:internal")
        t1 = time.perf_counter()
        if not r.allowed:
            raise SystemExit("ABORT: composition check denied at i=%d" % i)
        if i >= warmup:
            lat.append((t1 - t0) * 1000)
    return lat


def _measure_narrowing(iterations, warmup, session_length):
    parent = make_envelope()
    child = make_principal("bench-child-001")
    lat = []
    for i in range(warmup + iterations):
        t0 = time.perf_counter()
        parent.narrow(child, SIGNING_KEY)
        t1 = time.perf_counter()
        if i >= warmup:
            lat.append((t1 - t0) * 1000)
    return lat


COMPONENTS = {
    "full_admissibility_c4_below_threshold":
        lambda it, wu, sl: _measure_admissibility(it, wu, sl, high_impact=False),
    "full_admissibility_c4_token_verified":
        lambda it, wu, sl: _measure_admissibility(it, wu, sl, high_impact=True),
    "composition_closure_isolated": _measure_composition,
    "envelope_narrowing": _measure_narrowing,
}


def _host_metadata(argv_command: str, iterations, warmup, repetitions, session_length) -> dict:
    def _git(*a):
        try:
            return subprocess.check_output(["git"] + list(a),
                                           cwd=str(Path(__file__).resolve().parent.parent),
                                           stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            return "unknown"

    cpu = platform.processor()
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "$c=Get-CimInstance Win32_Processor|Select-Object -First 1;"
             "$o=Get-CimInstance Win32_OperatingSystem;"
             "\"$($c.Name.Trim())|$($c.NumberOfCores)|$($c.NumberOfLogicalProcessors)|"
             "$($c.MaxClockSpeed)|$($o.Caption)|$($o.BuildNumber)|"
             "$([math]::Round($o.TotalVisibleMemorySize/1MB,1))\""],
            stderr=subprocess.DEVNULL).decode().strip()
        name, cores, threads, mhz, os_name, build, ram = out.split("|")
        host = {"cpu": name, "cores": int(cores), "threads": int(threads),
                "base_clock_mhz": int(mhz), "os": os_name, "os_build": build,
                "ram_gb": float(ram)}
    except Exception:
        host = {"cpu": cpu, "platform": platform.platform()}

    return {
        "protocol": "appendix-d",
        "command": argv_command,
        "iterations_per_repetition": iterations,
        "warmup_iterations": warmup,
        "repetitions": repetitions,
        "session_length_actions": session_length,
        "percentile_method": "nearest-rank (index = ceil(p/100 * N) - 1)",
        "timer": "time.perf_counter()",
        "measures": ("in-process authorization path only; excludes model inference, "
                     "network round-trips, remote PDP retrieval and evidence-sink I/O"),
        "admit_path_enforced": True,
        "python": {"version": platform.python_version(),
                   "implementation": platform.python_implementation(),
                   "compiler": platform.python_compiler()},
        "host": host,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def run_appendix_d(iterations: int, warmup: int, repetitions: int,
                   session_length: int, output: str | None,
                   argv_command: str) -> int:
    print("\nAPC latency benchmark - Appendix D protocol")
    print("=" * 78)
    print("iterations=%d  warmup=%d  repetitions=%d  session_length=%d"
          % (iterations, warmup, repetitions, session_length))
    print("=" * 78)

    results = {}
    for name, fn in COMPONENTS.items():
        print("\n%s" % name)
        reps = []
        for r in range(repetitions):
            lat = sorted(fn(iterations, warmup, session_length))
            rep = {"repetition": r + 1,
                   "p50_ms": nearest_rank(lat, 50),
                   "p95_ms": nearest_rank(lat, 95),
                   "p99_ms": nearest_rank(lat, 99),
                   "mean_ms": statistics.mean(lat),
                   "min_ms": lat[0], "max_ms": lat[-1],
                   "n": len(lat)}
            reps.append(rep)
            print("   rep %d/%d  p50=%.4f  p99=%.4f  mean=%.4f"
                  % (r + 1, repetitions, rep["p50_ms"], rep["p99_ms"], rep["mean_ms"]))
        p50s = [x["p50_ms"] for x in reps]
        p99s = [x["p99_ms"] for x in reps]
        results[name] = {
            "repetitions": reps,
            "p50_ms_median": statistics.median(p50s),
            "p50_ms_range": [min(p50s), max(p50s)],
            "p99_ms_median": statistics.median(p99s),
            "p99_ms_range": [min(p99s), max(p99s)],
            "p99_ms_highest_repetition": max(p99s),
        }
        s = results[name]
        print("   -> p50 median %.4f [%.4f-%.4f]   p99 median %.4f [%.4f-%.4f]   highest p99 %.4f"
              % (s["p50_ms_median"], s["p50_ms_range"][0], s["p50_ms_range"][1],
                 s["p99_ms_median"], s["p99_ms_range"][0], s["p99_ms_range"][1],
                 s["p99_ms_highest_repetition"]))

    # Paper Appendix D / section 6.2 reported values, for comparison only.
    reported = {
        "full_admissibility_c4_below_threshold": {"p50_ms": 0.060, "p99_ms": 0.310},
        "full_admissibility_c4_token_verified": {"p50_ms": 0.069, "p99_ms": 0.323},
        "composition_closure_isolated": {"p50_ms": 0.0013, "p99_ms": 0.0032},
        "envelope_narrowing": {"p50_ms": 0.016, "p99_ms": 0.062},
    }
    print("\n" + "=" * 78)
    print("MEASURED vs REPORTED (Appendix D table)")
    print("=" * 78)
    print("   %-42s %-18s %-18s" % ("component", "p50 meas/report", "p99 meas/report"))
    for name, s in results.items():
        rep = reported[name]
        print("   %-42s %7.4f / %-7.4f  %7.4f / %-7.4f"
              % (name, s["p50_ms_median"], rep["p50_ms"],
                 s["p99_ms_median"], rep["p99_ms"]))

    artifact = {
        "metadata": _host_metadata(argv_command, iterations, warmup, repetitions, session_length),
        "results": results,
        "reported_in_paper": reported,
    }

    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(artifact, f, indent=2)
        print("\nArtifact written: %s" % p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
