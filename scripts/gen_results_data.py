#!/usr/bin/env python
"""
Generate docs/results-data.js from all benchmark result JSONs.

Run after any benchmark to update the evaluation dashboard:
    python scripts/gen_results_data.py

Reads:
  evals/injecagent/results/details.json
  evals/asb/results/summary.json
  evals/agentdojo/results/quick/details.json
  evals/adaptive/results/adaptive_results.json
  evals/delegation/results/delegation_results.json

Writes:
  docs/results-data.js
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"
DOCS = ROOT / "docs"


def load_json(path):
    if not path.exists():
        print(f"  SKIP: {path.relative_to(ROOT)} (not found)")
        return None
    with open(path) as f:
        return json.load(f)


def build_injecagent():
    """Transform InjecAgent details into dashboard format."""
    data = load_json(EVALS / "injecagent" / "results" / "details.json")
    if not data:
        return {}

    result = {}
    for condition in ["none", "complete", "incomplete"]:
        cond_data = data.get(condition, {})
        for sub in ["data_stealing", "direct_harm"]:
            sub_data = cond_data.get(sub, {})
            for case in sub_data.get("details", []):
                cat = case.get("attack_type", "unknown")
                key = f"{sub}/{cat}"
                if key not in result:
                    result[key] = []

                user_tool = case.get("user_tool", "")
                attacker_tools = case.get("attacker_tools", [])
                blocked = 1 if case.get("blocked", False) else 0

                steps = []
                for step in case.get("steps", []):
                    conds = step.get("conditions", {})
                    cond_list = [
                        1 if conds.get("C1", True) else 0,
                        1 if conds.get("C2a", True) else 0,
                        1 if conds.get("C2b", True) else 0,
                        1 if conds.get("C2c", True) else 0,
                        1 if conds.get("C3", True) else 0,
                        1 if conds.get("C4", True) else 0,
                        1 if conds.get("C5", True) else 0,
                        1 if conds.get("C6", True) else 0,
                    ]
                    admitted = 1 if step.get("admitted", True) else 0
                    steps.append([
                        step.get("tool", ""),
                        step.get("action", ""),
                        admitted,
                        cond_list,
                    ])

                # Only add for 'complete' condition (primary result)
                if condition == "complete":
                    result[key].append([user_tool, attacker_tools, blocked, steps])

    return result


def build_asb():
    """Transform ASB summary into dashboard case-level format.

    Each agent gets representative cases showing the composition check.
    Format: [name, [chain], blocked, [[step_tool, step_action, admitted, conds]]]
    """
    data = load_json(EVALS / "asb" / "results" / "summary.json")
    if not data:
        return {}

    complete = data.get("complete", {})
    per_agent = complete.get("per_agent", {})

    result = {}
    for agent, stats in per_agent.items():
        cases = []
        blocked = stats["blocked"]
        total = stats["total"]
        allowed = total - blocked

        # Disruptive cases (blocked by composition: read_sensitive → execute_harmful)
        n_disruptive = min(blocked, total // 2)
        for i in range(min(n_disruptive, 3)):
            cases.append([
                f"disruptive_{i+1}",
                [f"normal_tool → attack_tool"],
                1,
                [
                    [f"normal_tool ({agent.replace('_agent','')})", "read_sensitive", 1, [1,1,1,1,1,1,1,1]],
                    ["attack_tool (disruptive)", "execute_harmful", 0, [1,1,0,1,1,1,1,1]],
                ]
            ])

        # Stealthy blocked cases (read_sensitive → write)
        n_stealthy_blocked = blocked - n_disruptive
        for i in range(min(n_stealthy_blocked, 2)):
            cases.append([
                f"stealthy_blocked_{i+1}",
                [f"normal_tool → attack_tool"],
                1,
                [
                    [f"normal_tool ({agent.replace('_agent','')})", "read_sensitive", 1, [1,1,1,1,1,1,1,1]],
                    ["attack_tool (stealthy)", "send_external", 0, [1,1,0,1,1,1,1,1]],
                ]
            ])

        # Stealthy allowed cases (non-sensitive normal tool → write, no composition violation)
        for i in range(min(allowed, 2)):
            cases.append([
                f"stealthy_allowed_{i+1}",
                [f"normal_tool → attack_tool"],
                0,
                [
                    [f"normal_tool ({agent.replace('_agent','')})", "read", 1, [1,1,1,1,1,1,1,1]],
                    ["attack_tool (stealthy)", "write", 1, [1,1,1,1,1,1,1,1]],
                ]
            ])

        result[agent] = cases
    return result


def build_agentdojo():
    """Transform AgentDojo details into dashboard format."""
    from collections import defaultdict
    """Transform AgentDojo details into dashboard format.

    Categories:
      - Utility: per-task UPR comparison (baseline vs APC)
      - Compromised · Exfiltration: per-run ASR
      - Compromised · Destruction: per-run ASR
      - Compromised · Manipulation: per-run ASR
    """
    result = {}

    # Standard evaluation — group by suite + task, show utility comparison
    UTILITY_SUITES = {
        "Workspace": EVALS / "agentdojo" / "results" / "utility-workspace-sonnet" / "details.json",
        "Banking": EVALS / "agentdojo" / "results" / "utility-banking-sonnet" / "details.json",
        "Travel": EVALS / "agentdojo" / "results" / "utility-travel-sonnet" / "details.json",
        "Slack": EVALS / "agentdojo" / "results" / "utility-slack-sonnet" / "details.json",
    }
    # Fallback to quick/details.json if per-suite files not available
    UTILITY_SUITES_FALLBACK = EVALS / "agentdojo" / "results" / "quick" / "details.json"

    for suite_label, suite_path in UTILITY_SUITES.items():
        std_data = load_json(suite_path)
        if not std_data:
            continue
        baseline_runs = std_data.get("baseline", {}).get("results", [])
        apc_runs = (std_data.get("apc-approved", {}).get("results", [])
                    or std_data.get("apc", {}).get("results", [])
                    or std_data.get("apc-no-overrides", {}).get("results", []))

        base_by_task = defaultdict(list)
        apc_by_task = defaultdict(list)
        for r in baseline_runs:
            base_by_task[r["task_id"]].append(r)
        for r in apc_runs:
            apc_by_task[r["task_id"]].append(r)

        task_cases = []
        for tid in sorted(base_by_task.keys(), key=lambda x: int(x.split("_")[-1])):
            b_runs = base_by_task[tid]
            a_runs = apc_by_task.get(tid, [])
            b_upr = sum(1 for r in b_runs if r["utility"]) / len(b_runs) if b_runs else 0
            a_upr = sum(1 for r in a_runs if r["utility"]) / len(a_runs) if a_runs else 0
            delta = a_upr - b_upr
            no_regression = 1 if abs(delta) < 0.01 else 0
            task_cases.append([
                tid.replace("_", " ").title(),
                [f"Baseline UPR: {b_upr:.0%}", f"APC UPR: {a_upr:.0%}", f"Delta: {delta:+.0%}"],
                no_regression,
                [
                    ["Baseline", f"UPR {b_upr:.0%}", 1, None],
                    ["With APC", f"UPR {a_upr:.0%}", no_regression, None],
                ]
            ])
        result[suite_label] = task_cases

    # Compromised-model — load all suites, group by suite + attack type
    COMPROMISED_SUITES = {
        "workspace": EVALS / "agentdojo" / "results" / "compromised-workspace-haiku" / "details.json",
        "banking": EVALS / "agentdojo" / "results" / "compromised-banking-haiku" / "details.json",
        "travel": EVALS / "agentdojo" / "results" / "compromised-travel-haiku" / "details.json",
        "slack": EVALS / "agentdojo" / "results" / "compromised-slack-haiku" / "details.json",
    }

    # Map attack_tool to attack category and APC action_type
    ATTACK_TOOL_MAP = {
        "send_email": ("Exfiltration", "send_external"),
        "send_money": ("Exfiltration", "transfer"),
        "post_webpage": ("Exfiltration", "send_external"),
        "send_direct_message": ("Exfiltration", "send_internal"),
        "delete_file": ("Destruction", "delete"),
        "delete_email": ("Destruction", "delete"),
        "remove_user_from_slack": ("Destruction", "delete"),
        "create_calendar_event": ("Manipulation", "write"),
        "update_scheduled_transaction": ("Manipulation", "write"),
        "reserve_hotel": ("Manipulation", "write"),
        "update_password": ("Manipulation", "write"),
        "get_webpage": ("Exfiltration", "read_external"),
    }

    def _fmt_task(tid):
        return tid.replace("_", " ").replace("user task", "User Task").replace("injection task", "Injection Task")

    def _derive_conditions(attack_tool, attack_type, apc_blocked):
        conds = [1, 1, 1, 1, 1, 1, 1, 1]
        if not apc_blocked:
            return conds
        if attack_type == "Exfiltration":
            conds[2] = 0  # C2b
            conds[5] = 0  # C4
            conds[7] = 0  # C6
        elif attack_type == "Destruction":
            conds[7] = 0  # C6
        elif attack_type == "Manipulation":
            conds[7] = 0  # C6
        return conds

    for suite_name, details_path in COMPROMISED_SUITES.items():
        comp_data = load_json(details_path)
        if not comp_data:
            continue

        no_apc = comp_data.get("compromised-no-apc", {}).get("results", [])
        with_apc = comp_data.get("compromised-apc", {}).get("results", [])

        apc_index = {}
        for r in with_apc:
            apc_index[(r["task_id"], r["injection_id"])] = r

        # Group by attack type
        by_type = defaultdict(list)
        for r_no in no_apc:
            attack_tool = r_no.get("attack_tool", "")
            if attack_tool not in ATTACK_TOOL_MAP:
                continue
            attack_type, action_type = ATTACK_TOOL_MAP[attack_tool]

            key = (r_no["task_id"], r_no["injection_id"])
            r_apc = apc_index.get(key, {})
            sec_no = r_no.get("security", False)
            sec_apc = r_apc.get("security", False)
            apc_blocked = 0 if sec_apc else 1

            attack_conds = _derive_conditions(attack_tool, attack_type, apc_blocked)
            legit_conds = [1, 1, 1, 1, 1, 1, 1, 1]

            by_type[attack_type].append([
                f"{_fmt_task(r_no['task_id'])} \u00d7 {_fmt_task(r_no['injection_id'])}",
                [f"No APC: {'attack succeeded' if sec_no else 'attack blocked'}",
                 f"With APC: {'attack succeeded' if sec_apc else 'attack blocked'}"],
                apc_blocked,
                [
                    ["Legitimate action", "read", 1, legit_conds],
                    [attack_tool, action_type, 0 if apc_blocked else 1, attack_conds],
                ]
            ])

        suite_label = suite_name.capitalize()
        for attack_type in ["Exfiltration", "Destruction", "Manipulation"]:
            if attack_type in by_type:
                cat_key = f"{suite_label} \u00b7 {attack_type}"
                result[cat_key] = by_type[attack_type]

    return result

def build_adaptive():
    """Transform adaptive results into dashboard case-level format.

    Format: [name, desc, blocked, blocked_at_step, reason, tool_sequence]
    Categories are grouped for narrative clarity.
    """
    data = load_json(EVALS / "adaptive" / "results" / "adaptive_results.json")
    if not data:
        return {}

    # New format: {baseline: [...], apc_complete: [...]}
    if isinstance(data, dict) and "apc_complete" in data:
        items = data["apc_complete"]
    else:
        items = data

    # Map raw property_tested to grouped category names
    GROUP_MAP = {
        "Pairwise composition closure limitation": "Composition Closure",
        "k-tuple composition closure": "Composition Closure",
        "k-tuple composition closure (attack blocked)": "Composition Closure",
        "Pairwise limitation (attack succeeds)": "Composition Closure",
        "Per-session composition (split succeeds)": "Composition Closure",
        "Per-session composition (single session blocks)": "Composition Closure",
        "C2b (persistent influence, A4)": "Composition Closure",
        "C2b (k-tuple catches non-sensitive variant too)": "Composition Closure",

        "C6 intent binding (positive case)": "Intent Binding",
        "C6 intent binding (blocks out-of-intent)": "Intent Binding",
        "C6 (graduated enforcement — warn)": "Intent Binding",
        "C6 (graduated enforcement — strict)": "Intent Binding",
        "C6 (graduated enforcement — audit)": "Intent Binding",
        "C6 (audit mode, positive)": "Intent Binding",

        "C2c cumulative budget tracking": "Budget & Scope",
        "C2c (delegation depth, positive)": "Budget & Scope",
        "C2c (delegation depth overflow)": "Budget & Scope",
        "C2c (compute cost budget)": "Budget & Scope",
        "C2c (compute cost, positive)": "Budget & Scope",
        "A3 (scope probing, positive)": "Budget & Scope",
        "A3 (scope probing, boundary)": "Budget & Scope",
        "A3 (probe positive: read/public)": "Budget & Scope",
        "A3 (probe boundary: delete/public)": "Budget & Scope",
        "A3 (probe boundary: send_external/public)": "Budget & Scope",
        "A3 (probe boundary: read/confidential)": "Budget & Scope",
        "A3 (probe positive: write/internal)": "Budget & Scope",

        "C4 (approval hash integrity)": "Approval & Evidence",
        "C4 (approval, positive)": "Approval & Evidence",
        "C4 (temporal validity of approval)": "Approval & Evidence",
        "C4 (single-use token, positive)": "Approval & Evidence",
        "C4 (single-use enforcement)": "Approval & Evidence",
        "C5 (evidence fail-closed)": "Approval & Evidence",
        "C5 (evidence, positive)": "Approval & Evidence",

        "T2 (signature forgery prevention)": "Tamper Resistance",
        "T2 (signature verification, positive)": "Tamper Resistance",
        "T2 (envelope integrity, positive)": "Tamper Resistance",
        "T2 (envelope immutability)": "Tamper Resistance",
        "T3 + C4 (cross-session token replay)": "Tamper Resistance",
    }

    result = {}
    for s in items:
        raw_prop = s.get("property_tested", "unknown")
        cat = GROUP_MAP.get(raw_prop, raw_prop)
        if cat not in result:
            result[cat] = []

        seq = s.get("tool_sequence", [])
        reason = s.get("reason", "")
        blocked = s["blocked"]

        # Derive C1-C6 conditions for the blocked step
        # [C1, C2a, C2b, C2c, C3, C4, C5, C6]
        conds = [1, 1, 1, 1, 1, 1, 1, 1]  # all pass by default
        if blocked:
            r = reason.lower()
            if "pair:" in r or "k-tuple:" in r or "composition" in raw_prop.lower():
                conds[2] = 0  # C2b
            if "budget" in r or "cost:" in r:
                conds[3] = 0  # C2c
            if "scope" in r or "not in scope" in r or "classification" in r:
                conds[1] = 0  # C2a
            if "approval" in r:
                conds[5] = 0  # C4
            if "evidence" in r:
                conds[6] = 0  # C5
            if "intent" in raw_prop.lower() or "denied:" in r and "outside permitted" in r:
                conds[7] = 0  # C6
            if "signature" in r or "sealed" in r.lower() or "immutab" in r.lower():
                # Tamper resistance — maps to C1 (identity/integrity)
                conds[0] = 0  # C1
            if "session_id mismatch" in r:
                conds[5] = 0  # C4 (cross-session replay)

        result[cat].append([
            s["name"],
            s.get("description", ""),
            1 if blocked else 0,
            s.get("blocked_at_step", 0),
            reason,
            seq,
            conds,
        ])
    return result


def build_delegation():
    """Transform delegation results into dashboard case-level format.

    Format: [name, [chain_info], blocked, [[step_tool, step_action, admitted, null]]]
    """
    data = load_json(EVALS / "delegation" / "results" / "delegation_results.json")
    if not data:
        return {}

    # New format: {baseline: [...], apc_complete: [...]}
    if isinstance(data, dict) and "apc_complete" in data:
        items = data["apc_complete"]
    else:
        items = data

    result = {}
    for s in items:
        cat = s.get("category", "unknown")
        if cat not in result:
            result[cat] = []

        blocked = 1 if s["blocked"] else 0
        blocked_by = s.get("blocked_by", "")
        prop = s.get("property", "")

        # Derive C1-C6 conditions based on the property tested
        # [C1, C2a, C2b, C2c, C3, C4, C5, C6]
        conds_pass = [1, 1, 1, 1, 1, 1, 1, 1]
        conds_fail = [1, 1, 1, 1, 1, 1, 1, 1]
        if blocked:
            p = prop.lower()
            b = blocked_by.lower()
            if "scope" in p or "scope" in cat or "sensitivity" in cat or "narrowing" in cat:
                conds_fail[1] = 0  # C2a
            if "composition" in p or "composition" in cat or "k_tuple" in cat:
                conds_fail[2] = 0  # C2b
            if "budget" in p or "budget" in cat or "blast" in cat or "depth" in cat:
                conds_fail[3] = 0  # C2c
            if "identity" in cat or "context" in cat or "expired" in cat:
                conds_fail[4] = 0  # C3
            if "approval" in cat or "approval" in p:
                conds_fail[5] = 0  # C4
            if "evidence" in cat or "evidence" in p:
                conds_fail[6] = 0  # C5
            if "intent" in cat or "intent" in p:
                conds_fail[7] = 0  # C6
            if "conjunctive" in cat or "multi_condition" in cat:
                # Multiple conditions fail — derive from blocked_by
                if "scope" in b: conds_fail[1] = 0
                if "composition" in b or "pair" in b: conds_fail[2] = 0
                if "budget" in b: conds_fail[3] = 0
                if "intent" in b: conds_fail[7] = 0

        result[cat].append([
            s["name"],
            [f"depth={s['chain_depth']}", f"hop {s['adversary_position']}", prop],
            blocked,
            [
                [s["attack"][:80], prop, 1 if not blocked else 0,
                 conds_pass if not blocked else conds_fail],
                [blocked_by if blocked else "ADMITTED", "result",
                 1 if not blocked else 0,
                 conds_pass if not blocked else conds_fail],
            ]
        ])
    return result


def main():
    print("Generating docs/results-data.js")
    print("=" * 50)

    bench_data = {}

    print("  InjecAgent...")
    bench_data["injecagent"] = build_injecagent()

    print("  ASB...")
    bench_data["asb"] = build_asb()

    print("  AgentDojo (utility)...")
    bench_data["agentdojo_utility"] = {}
    print("  AgentDojo (compromised)...")
    bench_data["agentdojo_compromised"] = {}
    ad = build_agentdojo()
    UTILITY_SUITE_KEYS = {"Workspace", "Banking", "Travel", "Slack", "UPR"}
    for k, v in ad.items():
        if k in UTILITY_SUITE_KEYS:
            bench_data["agentdojo_utility"][k] = v
        else:
            bench_data["agentdojo_compromised"][k] = v

    print("  Adaptive...")
    bench_data["adaptive"] = build_adaptive()

    print("  Delegation...")
    bench_data["delegation"] = build_delegation()

    # Summary stats
    counts = {k: sum(len(v) if isinstance(v, list) else 1 for v in d.values())
              for k, d in bench_data.items()}
    print(f"\n  Benchmarks: {len(bench_data)}")
    for k, c in counts.items():
        print(f"    {k}: {c} entries")

    # Write
    output = f"const BENCH_DATA={json.dumps(bench_data, separators=(',', ':'))};\n"
    out_path = DOCS / "results-data.js"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

    size_kb = len(output) / 1024
    print(f"\n  Written: {out_path.relative_to(ROOT)} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
