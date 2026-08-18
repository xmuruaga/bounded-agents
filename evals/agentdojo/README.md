# AgentDojo × APC Integration

Live LLM evaluation using Claude Sonnet 4.6 (utility) and Claude Haiku 4.5
(compromised-model) via AWS Bedrock.

## Setup

1. Copy `.env.example` to `.env` and fill in your Bedrock credentials
2. Install dependencies: `pip install agentdojo anthropic python-dotenv`
3. Run utility: `python -u run_multirun2.py --suite workspace --runs 3`
4. Run compromised-model: `python -u run_compromised.py --suite workspace`

## Configuration

All config comes from `.env` and `suite_config.py`:
- `LLM_PROVIDER`: `bedrock` or `anthropic`
- `LLM_MODEL`: fallback model ID (eval scripts override from `suite_config.py`)
- `AWS_DEFAULT_REGION`: Bedrock region (default: `eu-central-1`)
- `AWS_BEARER_TOKEN_BEDROCK`: ABSK API key
- `SSL_VERIFY`: `false` for corporate proxy
- `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`: offline mode

Model IDs used in the paper are defined in `suite_config.py`:
- Utility: `eu.anthropic.claude-sonnet-4-6`
- Compromised-model: `eu.anthropic.claude-haiku-4-5-20251001-v1:0`

## Structure

```
agentdojo/
├── apc_defense/
│   ├── pipeline_element.py            # APCDefenseElement (BasePipelineElement)
│   ├── action_classifier.py           # Tool → APC action type mapping
│   ├── compromised_model_injector.py  # Compromised-model injection element
│   ├── scope_registry.py             # Suite → scope + k-tuple restrictions
│   ├── session_state.py              # Per-task session with intent parsing
│   └── evidence_sink.py             # Metrics collection
├── experiments/
│   └── llm_factory.py               # BedrockLLM factory
├── results/
│   ├── MANIFEST.md                    # Documented run selection for Table 7
│   ├── utility-*-sonnet/              # Run 0 per suite (Table 7)
│   ├── multirun2/                     # Runs 1+2 per suite (Table 7)
│   └── compromised-*-haiku/           # Compromised-model (Table 8)
├── run_compromised.py                # Compromised-model evaluation
├── run_multirun2.py                  # Multi-run utility evaluation
├── suite_config.py                   # Per-domain config and model IDs
├── .env.example                      # Config template
└── .env                              # Your credentials (not committed)
```

## Published results

Results reported in the paper (Table 7, means ± std over 3 independent runs):

| Suite | Baseline UPR | Interactive UPR | Δ inter |
|-------|-------------|-----------------|---------|
| Workspace (560 pairs) | 96.2 ± 0.2% | 86.7 ± 0.4% | −9.6% |
| Banking (144 pairs) | 68.8 ± 1.2% | 58.8 ± 1.7% | −10.0% |
| Travel (140 pairs) | 59.8 ± 1.1% | 60.0 ± 1.4% | +0.2% |
| Slack (105 pairs) | 73.0 ± 1.5% | 60.0 ± 4.4% | −13.0% |

Pair-weighted aggregate Δ interactive: **−8.6 pp** (N=949).

Compromised-model evaluation (Table 8): exfiltration **0%** in all four domains.

See `results/MANIFEST.md` for the exact run-file selection, the workspace
duplicate-run trap, and the derivation of every figure in Table 7.
