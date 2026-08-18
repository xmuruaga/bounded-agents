"""Suite configuration: maps suite names to classifiers and scopes."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from apc_defense.action_classifier import ActionClassifier
from apc_defense.scope_registry import ScopeRegistry


SUITE_CONFIG = {
    "workspace": {
        "classifier": ActionClassifier.for_workspace,
        "scope": ScopeRegistry.workspace_complete,
        "max_tasks": 40,
    },
    "banking": {
        "classifier": ActionClassifier.for_banking,
        "scope": ScopeRegistry.banking_complete,
        "max_tasks": 16,
    },
    "travel": {
        "classifier": ActionClassifier.for_travel,
        "scope": ScopeRegistry.travel_complete,
        "max_tasks": 20,
    },
    "slack": {
        "classifier": ActionClassifier.for_slack,
        "scope": ScopeRegistry.slack_complete,
        "max_tasks": 21,
    },
}

ALL_SUITES = list(SUITE_CONFIG.keys())

MODELS = {
    "haiku": "eu.anthropic.claude-haiku-4-5-20251001-v1:0",
    "sonnet": "eu.anthropic.claude-sonnet-4-6",
}


def get_suite_config(suite_name):
    """Return (classifier, scope, max_tasks) for a suite."""
    cfg = SUITE_CONFIG[suite_name]
    return cfg["classifier"](), cfg["scope"](), cfg["max_tasks"]
