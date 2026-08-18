# Head-to-Head: APC vs SEAgent vs Progent

Static (no LLM) comparison of three deterministic defense frameworks
on InjecAgent and ASB benchmarks.

## Frameworks

- **APC** (ours): Composition closure — blocks prohibited action *sequences*
- **SEAgent** (Ji et al., 2026): ABAC-based MAC — blocks tool calls via
  attribute-based policies on an information flow graph
- **Progent** (Shi et al., 2025): Programmable privilege control — blocks
  tool calls via DSL allow/deny policies on tool names and arguments

## Methodology

All three frameworks are evaluated as **deterministic policy checkers**
over the same static test cases. No LLM is involved.

For each test case, we ask: "Given the session history, would the defense
block the attacker tool call?"

### SEAgent simulation

SEAgent uses ABAC policies that classify tools by attributes (action type,
sensitivity, data category) and enforce mandatory access control rules.
We simulate this as:
1. Each tool has attributes from our existing tool profiles
2. Policy rules deny tool calls where attributes match prohibited patterns
3. Information flow tracking: if a sensitive read preceded the current call,
   subsequent send_external/transfer/physical actions are denied

### Progent simulation

Progent uses a DSL with explicit allow/deny rules per tool name.
We simulate this as:
1. An allowlist of tools permitted for the task (user tools only)
2. Any tool not on the allowlist is denied
3. Argument-level constraints (e.g., recipient must match known contacts)

## Usage

```bash
python run_head_to_head.py
```

## Output

- `results/injecagent_comparison.json` — Per-framework results on InjecAgent
- `results/asb_comparison.json` — Per-framework results on ASB
- `results/summary.json` — Combined comparison table
