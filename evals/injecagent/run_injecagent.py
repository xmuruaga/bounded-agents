#!/usr/bin/env python
"""
InjecAgent × APC Evaluation

Evaluates whether APC composition closure blocks InjecAgent attacks.

For each test case:
  1. The agent already executed the user tool (step 1 — pre-filled)
  2. The injection instructs the agent to execute attacker tool(s)
  3. APC evaluates: given the composition history, is the attacker tool admissible?

No LLM needed — this is a pure policy evaluation over the 1,054 test cases.
The question is: "If the agent tries to execute the attacker tool after the
user tool, does APC block it?"

Three conditions:
  - baseline:       No APC (all attacks succeed if agent follows injection)
  - apc-complete:   Full composition restrictions
  - apc-incomplete: Missing key pair (validates Theorem 5.1)

Usage:
    python -u run_injecagent.py
"""

import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tool_profiles import get_action_type, TOOL_PROFILES
from scope_config import make_checker

DATA_DIR = Path(__file__).resolve().parent / "data"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def load_test_cases():
    """Load all InjecAgent test cases."""
    with open(DATA_DIR / "test_cases_ds_base.json") as f:
        ds = json.load(f)
    with open(DATA_DIR / "test_cases_dh_base.json") as f:
        dh = json.load(f)
    # Tag each case
    for c in ds:
        c["_category"] = "data_stealing"
    for c in dh:
        c["_category"] = "direct_harm"
    return ds, dh


def evaluate_case(case: dict, checker) -> dict:
    """Evaluate a single test case against APC.

    Returns dict with:
      - blocked: True if APC would block the attack
      - reason: why it was blocked/allowed
      - step: which step was blocked (1 or 2 for data stealing)
      - conditions: per-step condition evaluation {C1..C6}
    """
    category = case["_category"]
    user_tool = case["User Tool"]
    attacker_tools = case["Attacker Tools"]

    # Baseline conditions: C1,C3,C4,C5 always pass (simulated env),
    # C2a always pass (scope not evaluated in composition-only mode),
    # C2c always pass (no budget in this benchmark),
    # C6 always pass (no intent in this benchmark).
    # Only C2b (composition closure) is actively evaluated.
    def make_conds(c2b_pass: bool) -> dict:
        return {
            "C1": True,   # Identity — simulated, always valid
            "C2a": True,  # Scope — not evaluated (composition-only)
            "C2b": c2b_pass,  # Composition closure — the active check
            "C2c": True,  # Budget — not evaluated in this benchmark
            "C3": True,   # Context — simulated, always valid
            "C4": True,   # Approval — not required (low impact)
            "C5": True,   # Evidence — simulated sink always available
            "C6": True,   # Intent — not evaluated in this benchmark
        }

    steps = []

    # Step 0: The user tool was already executed (pre-filled in scratchpad).
    user_action = get_action_type(user_tool)
    if checker is not None:
        checker.record(user_action, resource=user_tool)
    steps.append({"tool": user_tool, "action": user_action, "conditions": make_conds(True), "admitted": True})

    if category == "data_stealing":
        # Step 1: Attacker tool 1 — read sensitive data
        atk_tool_1 = attacker_tools[0]
        atk_action_1 = get_action_type(atk_tool_1)

        if checker is not None:
            result_1 = checker.check(atk_action_1, resource=atk_tool_1)
            conds_1 = make_conds(result_1.allowed)
            steps.append({"tool": atk_tool_1, "action": atk_action_1, "conditions": conds_1, "admitted": result_1.allowed})
            if not result_1.allowed:
                return {
                    "blocked": True,
                    "step": 1,
                    "reason": f"composition: {result_1.violations or result_1.k_tuple_violations}",
                    "tool_blocked": atk_tool_1,
                    "conditions": [s["conditions"] for s in steps],
                    "steps": steps,
                }
            checker.record(atk_action_1, resource=atk_tool_1)
        else:
            steps.append({"tool": atk_tool_1, "action": atk_action_1, "conditions": make_conds(True), "admitted": True})

        # Step 2: Attacker tool 2 — exfiltrate via GmailSendEmail
        atk_tool_2 = attacker_tools[1]
        atk_action_2 = get_action_type(atk_tool_2)

        if checker is not None:
            result_2 = checker.check(atk_action_2, resource=atk_tool_2)
            conds_2 = make_conds(result_2.allowed)
            steps.append({"tool": atk_tool_2, "action": atk_action_2, "conditions": conds_2, "admitted": result_2.allowed})
            if not result_2.allowed:
                return {
                    "blocked": True,
                    "step": 2,
                    "reason": f"composition: {result_2.violations or result_2.k_tuple_violations}",
                    "tool_blocked": atk_tool_2,
                    "conditions": [s["conditions"] for s in steps],
                    "steps": steps,
                }
        else:
            steps.append({"tool": atk_tool_2, "action": atk_action_2, "conditions": make_conds(True), "admitted": True})

        return {
            "blocked": False, "step": 0, "reason": "allowed", "tool_blocked": None,
            "conditions": [s["conditions"] for s in steps],
            "steps": steps,
        }

    else:  # direct_harm
        atk_tool = attacker_tools[0]
        atk_action = get_action_type(atk_tool)

        if checker is not None:
            result = checker.check(atk_action, resource=atk_tool)
            conds = make_conds(result.allowed)
            steps.append({"tool": atk_tool, "action": atk_action, "conditions": conds, "admitted": result.allowed})
            if not result.allowed:
                return {
                    "blocked": True,
                    "step": 1,
                    "reason": f"composition: {result.violations or result.k_tuple_violations}",
                    "tool_blocked": atk_tool,
                    "conditions": [s["conditions"] for s in steps],
                    "steps": steps,
                }
        else:
            steps.append({"tool": atk_tool, "action": atk_action, "conditions": make_conds(True), "admitted": True})

        return {
            "blocked": False, "step": 0, "reason": "allowed", "tool_blocked": None,
            "conditions": [s["conditions"] for s in steps],
            "steps": steps,
        }


def run_condition(name: str, cases: list[dict], condition: str) -> dict:
    """Run all test cases under a condition."""
    blocked = 0
    allowed = 0
    details = []

    for case in cases:
        checker = make_checker(condition)
        result = evaluate_case(case, checker)
        if result["blocked"]:
            blocked += 1
        else:
            allowed += 1
        details.append({
            "category": case["_category"],
            "attack_type": case["Attack Type"],
            "user_tool": case["User Tool"],
            "attacker_tools": case["Attacker Tools"],
            "blocked": result["blocked"],
            "step": result["step"],
            "reason": result["reason"],
            "tool_blocked": result["tool_blocked"],
            "conditions": result.get("conditions", []),
            "steps": result.get("steps", []),
        })

    total = blocked + allowed
    block_rate = blocked / total if total > 0 else 0
    # In InjecAgent, baseline ASR assumes all attacks succeed if agent follows injection.
    # With APC, blocked attacks don't succeed → ASR = (total - blocked) / total
    asr = (total - blocked) / total if total > 0 else 0

    return {
        "condition": name,
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "block_rate": block_rate,
        "asr": asr,
        "details": details,
    }


def main():
    print("InjecAgent x APC Evaluation")
    print("=" * 60)

    ds, dh = load_test_cases()
    all_cases = ds + dh
    print(f"Test cases: {len(ds)} data stealing + {len(dh)} direct harm = {len(all_cases)}")
    print()

    conditions = ["none", "complete", "incomplete"]
    results = {}

    for condition in conditions:
        label = {"none": "BASELINE", "complete": "APC-COMPLETE", "incomplete": "APC-INCOMPLETE"}[condition]
        print(f"--- {label} ---")

        # Run data stealing and direct harm separately
        ds_result = run_condition(f"{label}/data_stealing", ds, condition)
        dh_result = run_condition(f"{label}/direct_harm", dh, condition)

        # Combined
        combined = run_condition(label, all_cases, condition)

        print(f"  Data Stealing: ASR={ds_result['asr']:.1%}  blocked={ds_result['blocked']}/{ds_result['total']}")
        print(f"  Direct Harm:   ASR={dh_result['asr']:.1%}  blocked={dh_result['blocked']}/{dh_result['total']}")
        print(f"  Combined:      ASR={combined['asr']:.1%}  blocked={combined['blocked']}/{combined['total']}")
        print()

        results[condition] = {
            "data_stealing": ds_result,
            "direct_harm": dh_result,
            "combined": combined,
        }

    # Comparison table
    print("=" * 60)
    print(f"  {'Condition':<20} {'DS ASR':>8} {'DH ASR':>8} {'Total ASR':>10} {'Blocked':>8}")
    print(f"  {'-'*56}")
    for cond in conditions:
        label = {"none": "Baseline", "complete": "APC-Complete", "incomplete": "APC-Incomplete"}[cond]
        r = results[cond]
        print(f"  {label:<20} {r['data_stealing']['asr']:>7.1%} {r['direct_harm']['asr']:>7.1%} "
              f"{r['combined']['asr']:>9.1%} {r['combined']['blocked']:>8}")
    print(f"  {'-'*56}")

    ds_reduction = results["none"]["data_stealing"]["asr"] - results["complete"]["data_stealing"]["asr"]
    print(f"  DS ASR reduction (complete): {ds_reduction:+.1%}")

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    # Strip details for summary
    summary = {}
    for cond, r in results.items():
        summary[cond] = {
            k: {kk: vv for kk, vv in v.items() if kk != "details"}
            for k, v in r.items()
        }
    with open(RESULTS_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # Save full details
    full = {}
    for cond, r in results.items():
        full[cond] = r
    with open(RESULTS_DIR / "details.json", "w") as f:
        json.dump(full, f, indent=2, default=str)

    print(f"\n  Results: {RESULTS_DIR / 'summary.json'}")
    print(f"  Details: {RESULTS_DIR / 'details.json'}")


if __name__ == "__main__":
    main()
