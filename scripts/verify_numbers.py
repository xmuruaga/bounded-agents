"""Cross-check all numbers between raw data, evaluation.html, and paper.

Authoritative manuscript validation lives in scripts/verify_paper_numbers.py,
which derives every reported metric from the artifacts. This script covers
benchmark-level totals and the dashboard badges.
"""
import json, re, sys
from pathlib import Path

# The console on Windows defaults to cp1252, which cannot encode the check marks
# used below. Force UTF-8 so the script is runnable without PYTHONIOENCODING.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:  # pragma: no cover - Python < 3.7
    pass

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"
DOCS = ROOT / "docs"

def load(p):
    with open(p) as f:
        return json.load(f)

errors = []
def check(label, expected, actual):
    if abs(expected - actual) > 0.05:
        errors.append(f"MISMATCH {label}: expected {expected}, got {actual}")
        print(f"  ✗ {label}: expected {expected}, got {actual}")
    else:
        print(f"  ✓ {label}: {actual}")

print("=" * 60)
print("RAW DATA VERIFICATION")
print("=" * 60)

# --- InjecAgent ---
print("\n--- InjecAgent ---")
inj = load(EVALS / "injecagent/results/details.json")
ic = inj["complete"]
ds_total = ic["data_stealing"]["total"]
dh_total = ic["direct_harm"]["total"]
ds_asr = ic["data_stealing"]["asr"] * 100
dh_asr = ic["direct_harm"]["asr"] * 100
check("Total cases", 1054, ds_total + dh_total)
check("Data Stealing cases", 544, ds_total)
check("Direct Harm cases", 510, dh_total)
check("Data Stealing ASR (Complete X)", 0.0, ds_asr)
check("Direct Harm ASR (Complete X)", 60.4, dh_asr)

ip = inj["incomplete"]
check("Partial X - Data Stealing ASR", 39.9, ip["data_stealing"]["asr"] * 100)
check("Partial X - Direct Harm ASR", 82.0, ip["direct_harm"]["asr"] * 100)

# --- ASB ---
print("\n--- ASB ---")
asb = load(EVALS / "asb/results/summary.json")
ac = asb["complete"]
check("Total", 400, ac["total"])
check("Blocked", 340, ac["blocked"])
check("Stealthy ASR", 30.0, ac["stealthy_asr"] * 100)
check("Disruptive ASR", 0.0, ac["disruptive_asr"] * 100)
ap = asb["partial"]
check("Partial - Stealthy ASR", 60.0, ap["stealthy_asr"] * 100)
check("Partial - Disruptive ASR", 100.0, ap["disruptive_asr"] * 100)

# --- AgentDojo Utility (multirun2) ---
# Table 7 (3-run means) is validated in scripts/verify_paper_numbers.py. Here we
# assert that each multirun2 summary is internally consistent with its own raw
# per-run values, so a corrupted checkpoint cannot pass unnoticed.
print("\n--- AgentDojo Utility (multirun2 self-consistency) ---")
for suite in ["banking", "travel", "slack"]:
    s = load(EVALS / f"agentdojo/results/multirun2/{suite}-runs/summary.json")
    for cond in ["baseline", "apc-strict", "apc-approved"]:
        agg = s["aggregated"][cond]
        raw = agg["raw_uprs"]
        check(f"{suite}/{cond} run count", 2, agg["n"])
        check(f"{suite}/{cond} mean matches raw runs",
              round(sum(raw) / len(raw) * 100, 4), round(agg["upr_mean"] * 100, 4))

# --- AgentDojo Compromised (4 domains) ---
print("\n--- AgentDojo Compromised ---")
compromised_runs = 0
for suite in ["workspace", "banking", "slack", "travel"]:
    p = EVALS / f"agentdojo/results/compromised-{suite}-haiku/summary.json"
    if not p.exists():
        errors.append(f"MISSING compromised artifact for {suite}: {p}")
        print(f"  ✗ {suite}: result file not found")
        continue
    comp = load(p)
    cn = comp["compromised-no-apc"]
    ca = comp["compromised-apc"]
    compromised_runs += cn["total_runs"]
    print(f"  ✓ {suite}: no-APC ASR={cn['asr']*100:.1f}%, "
          f"APC ASR={ca['asr']*100:.1f}%, runs={cn['total_runs']}")
check("Compromised cohort pairs", 609, compromised_runs)

# --- Adaptive ---
print("\n--- Adaptive ---")
adp = load(EVALS / "adaptive/results/summary.json")
adc = adp["apc_complete"]
check("Total attacks", 23, adc["total_attacks"])
check("Blocked", 23, adc["blocked"])
check("Total variants", 43, adc["total_variants"])

# --- Delegation ---
print("\n--- Delegation ---")
dlg = load(EVALS / "delegation/results/summary.json")
dc = dlg["apc_complete"]
check("Total scenarios", 99, dc["total_scenarios"])
check("Attacks blocked", 76, dc["blocked"])
check("Total attacks", 76, dc["total_attacks"])
check("Scenarios correct", 99, dc["scenarios_correct"])

# --- Total ---
print("\n--- Total ---")
# 1054 (InjecAgent) + 400 (ASB) + 949 (AgentDojo utility, 4 suites)
# + 609 (AgentDojo compromised, 4 suites) + 43 (adaptive variants) + 99 (delegation)
total = 1054 + 400 + 949 + 609 + 43 + 99
check("Total scenarios", 3154, total)

# --- Cross-check with evaluation.html ---
print("\n" + "=" * 60)
print("EVALUATION.HTML CROSS-CHECK")
print("=" * 60)

with open(ROOT / "docs/evaluation.html", encoding="utf-8") as f:
    html = f.read()

checks_html = [
    ("Hero total", r"(\d[,\d]+) evaluation instances", "3,154"),
    ("AgentDojo Utility badge", r'AgentDojo — Utility.*?bench-badge">(949 runs[^<]*)', "949 runs × 3 conditions"),
    ("AgentDojo Compromised badge", r'AgentDojo — Compromised.*?bench-badge">([\d,]+ runs)', "1,218 runs"),
    ("InjecAgent badge", r'bench-name">InjecAgent<.*?bench-badge">([\d,]+ cases)', "1,054 cases"),
    ("ASB badge", r'bench-name">Agent Security Bench.*?bench-badge">([\d,]+ cases)', "400 cases"),
    ("Adaptive badge", r'bench-name">Adaptive.*?bench-badge">([\d,]+ cases)', "43 cases"),
    ("Delegation badge", r'bench-name">Multi-hop.*?bench-badge">([\d,]+ cases)', "99 cases"),
]
for label, pattern, expected in checks_html:
    found = re.search(pattern, html, re.DOTALL)
    found = found.group(1) if found else None
    if found == expected:
        print(f"  ✓ {label}: {found}")
    else:
        errors.append(f"HTML MISMATCH {label}: expected '{expected}', found '{found}'")
        print(f"  ✗ {label}: expected '{expected}', found '{found}'")

# --- Cross-check with paper ---
print("\n" + "=" * 60)
print("PAPER CROSS-CHECK")
print("=" * 60)

tex_path = ROOT / "paper" / "main.tex"

if not tex_path.exists():
    print("  SKIP: paper .tex not found")
else:
    with open(tex_path, encoding="utf-8") as f:
        tex = f.read()
    print(f"  Using: {tex_path.relative_to(ROOT)}")

    paper_checks = [
        ("Total evaluation instances", r"(\d[,\d]+) evaluation instances", "3,154"),
        ("Compromised cohort size", r"\((\d+) versus 949 pairs\)", "609"),
        ("Utility cohort size",
         r"across the (\d+) task--injection pairs",
         "949"),
    ]
    for label, pattern, expected in paper_checks:
        m = re.search(pattern, tex)
        if m:
            found = m.group(1) if m.lastindex else m.group(0)
            if expected is None or found == expected:
                print(f"  ✓ {label}: {found}")
            else:
                errors.append(f"PAPER MISMATCH {label}: expected '{expected}', found '{found}'")
                print(f"  ✗ {label}: expected '{expected}', found '{found}'")
        else:
            errors.append(f"PAPER NOT FOUND: {label} (pattern: {pattern})")
            print(f"  ? {label}: pattern not found")

print("\n" + "=" * 60)
if errors:
    print(f"ERRORS: {len(errors)}")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("ALL CHECKS PASSED ✓")
