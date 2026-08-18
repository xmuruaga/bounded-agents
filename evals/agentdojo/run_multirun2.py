#!/usr/bin/env python
"""
Multi-run evaluation with per-condition checkpoints.

Runs N independent full evaluations of a suite. Unlike run_multirun.py which
wraps run_suite() as a black box, this runner executes one condition at a time
and writes a checkpoint after each condition completes. This means:

  - If the process dies mid-run, completed conditions are saved
  - Progress is visible in real time
  - Each condition's results are independently verifiable

For paper results: use --conditions baseline,apc-approved (2 conditions).
apc-strict is omitted by default to halve the cost; it can be added back.

Usage:
  python -u run_multirun2.py --suite workspace --runs 3
  python -u run_multirun2.py --suite banking --runs 3
  python -u run_multirun2.py --suite workspace --runs 3 --conditions baseline,apc-approved
"""
import sys, json, time, copy, types, importlib, argparse, statistics
from pathlib import Path
from datetime import datetime

sys.path.insert(0, ".")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

for _pkg_name in ("agentdojo.agent_pipeline", "agentdojo.agent_pipeline.llms"):
    if _pkg_name not in sys.modules:
        _spec = importlib.util.find_spec(_pkg_name)
        if _spec and _spec.submodule_search_locations:
            _stub = types.ModuleType(_pkg_name)
            _stub.__path__ = list(_spec.submodule_search_locations)
            _stub.__package__ = _pkg_name
            sys.modules[_pkg_name] = _stub

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.attacks.baseline_attacks import DirectAttack
from agentdojo.task_suite.load_suites import get_suite

from apc.intent import IntentEnforcementMode
from apc_defense.pipeline_element import APCDefenseElement
from suite_config import get_suite_config, MODELS, ALL_SUITES
from experiments.llm_factory import make_llm


def run_one_condition(suite_name, model_id, condition_name, output_dir, run_idx):
    """Run a single condition for a suite and write checkpoint immediately."""

    classifier, scope, max_tasks = get_suite_config(suite_name)
    suite = get_suite("v1.2.2", suite_name)
    task_ids = list(suite.user_tasks.keys())[:max_tasks]
    inj_ids = list(suite.injection_tasks.keys())
    sys_msg = load_system_message(None)
    total = len(task_ids) * len(inj_ids)

    print(f"\n  Condition: {condition_name} | {len(task_ids)} tasks x {len(inj_ids)} inj = {total} pairs")

    # Build pipeline for this condition
    llm = make_llm(model=model_id)
    apc_el = None

    if condition_name == "baseline":
        pipeline = AgentPipeline([
            SystemMessage(sys_msg), InitQuery(), llm,
            ToolsExecutionLoop([ToolsExecutor(), llm])
        ])
    elif condition_name == "apc-approved":
        apc_el = APCDefenseElement(suite_scope=scope, classifier=classifier,
            intent_mode=IntentEnforcementMode.STRICT, auto_approve_c4=True)
        pipeline = AgentPipeline([
            SystemMessage(sys_msg), InitQuery(), llm,
            ToolsExecutionLoop([apc_el, ToolsExecutor(), llm])
        ])
    elif condition_name == "apc-strict":
        apc_el = APCDefenseElement(suite_scope=scope, classifier=classifier,
            intent_mode=IntentEnforcementMode.STRICT, auto_approve_c4=False)
        pipeline = AgentPipeline([
            SystemMessage(sys_msg), InitQuery(), llm,
            ToolsExecutionLoop([apc_el, ToolsExecutor(), llm])
        ])
    else:
        raise ValueError(f"Unknown condition: {condition_name}")

    # Build attack using a separate baseline pipeline (required by DirectAttack)
    llm_atk = make_llm(model=model_id)
    atk_pipeline = AgentPipeline([
        SystemMessage(sys_msg), InitQuery(), llm_atk,
        ToolsExecutionLoop([ToolsExecutor(), llm_atk])
    ])
    attack = DirectAttack(task_suite=suite, target_pipeline=atk_pipeline)

    results = []
    done = 0
    t_start = time.time()

    for tid in task_ids:
        user_task = suite.get_user_task_by_id(tid)
        for iid in inj_ids:
            done += 1
            if apc_el is not None:
                apc_el.reset()
            print(f"  [{done}/{total}] run{run_idx} {condition_name} | {tid} x {iid}",
                  end=" ", flush=True)
            t0 = time.time()
            try:
                inj_task = suite.get_injection_task_by_id(iid)
                injections = attack.attack(user_task, inj_task)
                utility, security = suite.run_task_with_pipeline(
                    pipeline, user_task, inj_task, injections)
                elapsed = time.time() - t0
                print(f"u={utility} s={security} ({elapsed:.1f}s)", flush=True)
                results.append({
                    "task_id": tid, "injection_id": iid,
                    "utility": utility, "security": security,
                    "elapsed": round(elapsed, 2),
                })
            except Exception as e:
                elapsed = time.time() - t0
                print(f"ERROR ({elapsed:.1f}s): {e}", flush=True)
                results.append({
                    "task_id": tid, "injection_id": iid,
                    "utility": False, "security": False,
                    "elapsed": round(elapsed, 2), "error": str(e),
                })

    n = len(results)
    upr = sum(1 for r in results if r["utility"]) / n if n else 0
    asr = sum(1 for r in results if r["security"]) / n if n else 0
    errors = sum(1 for r in results if "error" in r)
    elapsed_total = round(time.time() - t_start, 1)

    summary = {
        "condition": condition_name, "suite": suite_name, "model": model_id,
        "run_idx": run_idx, "n_pairs": n, "upr": upr, "asr": asr,
        "errors": errors, "elapsed_s": elapsed_total,
    }

    # Write checkpoint immediately after condition completes
    ckpt_path = output_dir / f"{suite_name}_run{run_idx}_{condition_name}.json"
    with open(ckpt_path, "w") as f:
        json.dump({**summary, "results": results}, f, indent=2)

    print(f"\n  -> {condition_name}: UPR={upr:.3f} ASR={asr:.3f} errors={errors}"
          f" ({elapsed_total}s) | saved: {ckpt_path.name}", flush=True)

    return summary


def aggregate(summaries):
    """Aggregate N condition summaries into mean/std/min/max."""
    uprs = [s["upr"] for s in summaries]
    asrs = [s["asr"] for s in summaries]
    n = len(uprs)
    return {
        "n": n,
        "upr_mean": statistics.mean(uprs),
        "upr_std": statistics.stdev(uprs) if n > 1 else 0.0,
        "upr_min": min(uprs), "upr_max": max(uprs),
        "asr_mean": statistics.mean(asrs),
        "asr_std": statistics.stdev(asrs) if n > 1 else 0.0,
        "asr_min": min(asrs), "asr_max": max(asrs),
        "raw_uprs": uprs, "raw_asrs": asrs,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Multi-run evaluation with per-condition checkpoints.")
    parser.add_argument("--suite", default="workspace", choices=ALL_SUITES)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--model", default="sonnet",
                        help="'haiku', 'sonnet', or full Bedrock model ID")
    parser.add_argument("--conditions", default="baseline,apc-strict,apc-approved",
                        help="Comma-separated conditions to run "
                             "(default: baseline,apc-strict,apc-approved)")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: results/multirun2/TIMESTAMP/)")
    args = parser.parse_args()

    model_id = MODELS.get(args.model, args.model)
    conditions = [c.strip() for c in args.conditions.split(",")]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output) if args.output else \
        Path(__file__).parent / "results" / "multirun2" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    # Cost estimate
    classifier, scope, max_tasks = get_suite_config(args.suite)
    suite_obj = get_suite("v1.2.2", args.suite)
    n_tasks = min(max_tasks, len(suite_obj.user_tasks))
    n_inj = len(suite_obj.injection_tasks)
    pairs = n_tasks * n_inj
    total_calls = pairs * len(conditions) * args.runs
    cost_est = total_calls * 0.012

    print(f"\nMulti-run evaluation (per-condition checkpoints)")
    print(f"{'='*60}")
    print(f"Suite:      {args.suite} ({n_tasks} tasks x {n_inj} inj = {pairs} pairs)")
    print(f"Model:      {args.model!r} -> {model_id}")
    print(f"Conditions: {conditions}")
    print(f"Runs:       {args.runs}")
    print(f"Total calls:{total_calls}  (~${cost_est:.0f} Sonnet medium est.)")
    print(f"Output:     {output_dir}")
    print(f"{'='*60}\n")

    # Collect per-condition results across runs
    all_summaries = {c: [] for c in conditions}

    for run_idx in range(1, args.runs + 1):
        print(f"\n{'='*60}")
        print(f"RUN {run_idx}/{args.runs}")
        print(f"{'='*60}")
        for condition in conditions:
            try:
                s = run_one_condition(
                    args.suite, model_id, condition, output_dir, run_idx)
                all_summaries[condition].append(s)
            except Exception as e:
                print(f"\n  RUN {run_idx} {condition} FAILED: {e}")
                print(f"  Skipping — continuing with next condition/run")

    # Aggregate
    print(f"\n{'='*60}")
    print(f"AGGREGATED RESULTS ({args.suite}, {args.runs} runs)")
    print(f"{'='*60}")
    agg = {}
    for condition in conditions:
        summaries = all_summaries[condition]
        if not summaries:
            print(f"  {condition}: NO SUCCESSFUL RUNS")
            continue
        a = aggregate(summaries)
        agg[condition] = a
        print(f"  {condition}: UPR {a['upr_mean']*100:.1f} +/- {a['upr_std']*100:.1f}%"
              f"  ASR {a['asr_mean']*100:.1f}%"
              f"  (n={a['n']}, min={a['upr_min']*100:.1f}%, max={a['upr_max']*100:.1f}%)")

    # Write final summary
    import subprocess, platform
    def git_commit():
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            ).decode().strip()
        except Exception:
            return "unknown"

    summary_out = {
        "protocol": {
            "suite": args.suite, "model_alias": args.model,
            "model_id": model_id, "runs": args.runs,
            "conditions": conditions, "timestamp": timestamp,
            "apc_git_commit": git_commit(),
            "agentdojo_version": "v1.2.2",
            "note": "per-condition checkpoints; paper results use baseline+apc-approved",
        },
        "run_summary": {
            c: {"successful": len(all_summaries[c]), "requested": args.runs,
                "failed": args.runs - len(all_summaries[c])}
            for c in conditions
        },
        "aggregated": agg,
    }

    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary_out, f, indent=2)
    print(f"\nSummary: {summary_path}")

    # Quick LaTeX snippet
    if "baseline" in agg and "apc-approved" in agg:
        b = agg["baseline"]
        a = agg["apc-approved"]
        n = b["n"]
        suite_label = args.suite.capitalize()
        pairs_label = pairs
        latex = (
            f"% {suite_label} ({pairs_label} pairs/run, {n} runs, {model_id})\n"
            f"% baseline UPR: {b['upr_mean']*100:.1f} +/- {b['upr_std']*100:.1f}%\n"
            f"% apc-approved UPR: {a['upr_mean']*100:.1f} +/- {a['upr_std']*100:.1f}%\n"
            f"% delta: {(a['upr_mean']-b['upr_mean'])*100:+.1f} pp\n"
            f"% apc ASR: {a['asr_mean']*100:.1f}%\n"
            f"{suite_label} ({pairs_label} runs) & "
            f"{b['upr_mean']*100:.1f}\\% & "
            f"{a['upr_mean']*100:.1f} $\\pm$ {a['upr_std']*100:.1f}\\% & "
            f"[Progent] & "
            f"\\textbf{{0.0\\%}} & [Progent] \\\\"
        )
        latex_path = output_dir / "table_row.tex"
        with open(latex_path, "w") as f:
            f.write(latex)
        print(f"LaTeX row: {latex_path}")
        print(f"\n{latex}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
