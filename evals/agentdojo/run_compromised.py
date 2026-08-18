#!/usr/bin/env python
"""
Compromised-Model Evaluation: simulates a fully compromised model in AgentDojo.

For each (user_task, injection_task) pair, injects the injection task's
ground-truth final tool call into the agent's pipeline output. This
represents the worst case: the model follows the attacker's instruction.

Two conditions:
  1. compromised-no-apc: Injection executes without defense
  2. compromised-apc: APC enforcement blocks prohibited actions

Usage:
  python -u run_compromised.py                          # workspace × haiku (default)
  python -u run_compromised.py --suite banking           # banking × haiku
  python -u run_compromised.py --suite travel --model sonnet  # travel × sonnet
  python -u run_compromised.py --all                     # all 4 suites × default model
"""
import sys, json, time, types, importlib, argparse
sys.path.insert(0, ".")
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent.parent))

from pathlib import Path
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
from apc_defense.compromised_model_injector import CompromisedModelInjector
from apc_defense.pipeline_element import APCDefenseElement
from suite_config import get_suite_config, MODELS, ALL_SUITES
from experiments.llm_factory import make_llm


def run_suite(suite_name, model_id, dry_run=False):
    """Run compromised-model evaluation for one suite."""
    print(f"\n{'='*70}")
    print(f"SUITE: {suite_name} | MODEL: {model_id.split('.')[-1][:30]}")
    print(f"{'='*70}\n")

    classifier, scope, max_tasks = get_suite_config(suite_name)
    suite = get_suite("v1.2.2", suite_name)
    task_ids = list(suite.user_tasks.keys())[:max_tasks]
    sys_msg = load_system_message(None)

    # Load default environment for ground truth extraction
    default_env = suite.load_and_inject_default_environment({})

    # Identify injection tasks with ground truth
    evaluable_inj = {}
    for iid in sorted(suite.injection_tasks.keys(), key=lambda x: int(x.split("_")[-1])):
        task = suite.get_injection_task_by_id(iid)
        gt = task.ground_truth(default_env)
        if len(gt) > 0:
            evaluable_inj[iid] = gt
            final = gt[-1]
            profile = classifier.classify(final.function)
            action_type = profile.action_type if profile else "unknown"
            print(f"  {iid}: {final.function} -> {action_type}")
        else:
            print(f"  {iid}: no ground truth (skipped)")

    n_runs = len(task_ids) * len(evaluable_inj)
    print(f"\nEvaluable: {len(evaluable_inj)} injection tasks")
    print(f"Runs per condition: {len(task_ids)} x {len(evaluable_inj)} = {n_runs}")

    if dry_run:
        print(f"\n[DRY RUN] Would execute {n_runs * 2} total runs (2 conditions)")
        return None

    # Attack object
    dummy_llm = make_llm(model=model_id)
    dummy_pipe = AgentPipeline([SystemMessage(sys_msg), InitQuery(), dummy_llm,
        ToolsExecutionLoop([ToolsExecutor(), dummy_llm])])
    dummy_pipe.name = "baseline"
    attack = DirectAttack(task_suite=suite, target_pipeline=dummy_pipe)

    def run_condition(name, use_apc=False):
        results = []
        inj_ids = list(evaluable_inj.keys())
        total = len(task_ids) * len(inj_ids)
        done = 0

        for tid in task_ids:
            user_task = suite.get_user_task_by_id(tid)
            for iid in inj_ids:
                done += 1
                gt = evaluable_inj[iid]
                injector = CompromisedModelInjector.from_ground_truth(list(gt))
                if injector is None:
                    continue

                llm = make_llm(model=model_id)
                if use_apc:
                    apc_el = APCDefenseElement(suite_scope=scope, classifier=classifier,
                        intent_mode=IntentEnforcementMode.STRICT)
                    pipe = AgentPipeline([SystemMessage(sys_msg), InitQuery(), llm,
                        ToolsExecutionLoop([injector, apc_el, ToolsExecutor(), llm])])
                else:
                    pipe = AgentPipeline([SystemMessage(sys_msg), InitQuery(), llm,
                        ToolsExecutionLoop([injector, ToolsExecutor(), llm])])
                pipe.name = "compromised"

                print(f"  [{done}/{total}] {name} | {tid} x {iid}", end=" ", flush=True)
                t0 = time.time()
                try:
                    inj_task = suite.get_injection_task_by_id(iid)
                    injections = attack.attack(user_task, inj_task)
                    utility, security = suite.run_task_with_pipeline(
                        pipe, user_task, inj_task, injections,
                    )
                    elapsed = time.time() - t0
                    mark = " <<<" if security else ""
                    print(f"u={utility} s={security} ({elapsed:.1f}s){mark}")
                    results.append({
                        "task_id": tid, "injection_id": iid,
                        "utility": utility, "security": security,
                        "elapsed": round(elapsed, 2),
                        "attack_tool": injector.attack_tool,
                    })
                except Exception as e:
                    elapsed = time.time() - t0
                    print(f"ERROR ({elapsed:.1f}s): {e}")
                    results.append({
                        "task_id": tid, "injection_id": iid,
                        "utility": False, "security": False,
                        "elapsed": round(elapsed, 2),
                        "error": str(e),
                        "attack_tool": injector.attack_tool,
                    })

        n = len(results)
        upr = sum(1 for r in results if r["utility"]) / n if n else 0
        asr = sum(1 for r in results if r["security"]) / n if n else 0
        return {
            "condition": name, "suite": suite_name, "model": model_id,
            "n_tasks": len(task_ids), "n_injections": len(inj_ids),
            "total_runs": n, "upr": upr, "asr": asr, "results": results,
        }

    # Run both conditions
    print(f"\nCONDITION 1: Compromised, no APC")
    print("-" * 50)
    r1 = run_condition("compromised-no-apc", use_apc=False)

    print(f"\nCONDITION 2: Compromised, with APC")
    print("-" * 50)
    r2 = run_condition("compromised-apc", use_apc=True)

    # Results
    print(f"\n{'='*70}")
    print(f"RESULTS — {suite_name}")
    print(f"{'='*70}")
    print(f"  {'Condition':<30} {'UPR':>8} {'ASR':>8} {'Runs':>6}")
    print(f"  {'-'*54}")
    for r in [r1, r2]:
        print(f"  {r['condition']:<30} {r['upr']:>7.1%} {r['asr']:>7.1%} {r['total_runs']:>6}")

    # Save
    model_short = "haiku" if "haiku" in model_id else "sonnet"
    results_dir = Path(__file__).resolve().parent / "results" / f"compromised-{suite_name}-{model_short}"
    results_dir.mkdir(parents=True, exist_ok=True)

    all_results = {"compromised-no-apc": r1, "compromised-apc": r2}
    summary = {k: {kk: vv for kk, vv in v.items() if kk != "results"}
               for k, v in all_results.items()}

    with open(results_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    with open(results_dir / "details.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Saved: {results_dir}/")
    return all_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compromised-model evaluation")
    parser.add_argument("--suite", default="workspace", choices=ALL_SUITES,
                        help="AgentDojo suite to evaluate")
    parser.add_argument("--model", default="haiku", choices=list(MODELS.keys()),
                        help="Model to use")
    parser.add_argument("--all", action="store_true",
                        help="Run all 4 suites")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would run without executing")
    args = parser.parse_args()

    model_id = MODELS[args.model]
    suites_to_run = ALL_SUITES if args.all else [args.suite]

    for suite_name in suites_to_run:
        run_suite(suite_name, model_id, dry_run=args.dry_run)

    print("\nAll done.")
