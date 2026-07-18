"""Planner — repo-native rule authoring phase.

The Planner runs after Recon and before Investigate. It reads a
lightweight index of the target repo (file tree, top-level imports,
decorator names, class/function name shortlist) and asks a model to
propose rules TUNED TO THIS REPO — custom deserialization sinks, auth
wrappers, request-source helpers, sanitizer functions, framework
identification. The proposals are validated against the actual codebase
(the grep gate) and then fed downstream:

  * sg-core           — extra sinks unioned into the per-sweep SINKS
                        override; extra sanitizer callable names added
                        to the sanitizer heuristic.
  * Semgrep adapter   — planner-authored YAML rulepack appended to
                        semgrep --config alongside p/default.
  * ConsensusKernel   — hits from planner-inferred rules count under a
                        new `planner_inferred` modality (ranked below
                        static_analysis_fact, at parity with
                        external_signal from Semgrep).

Three tiers of downstream compatibility (see design doc):
  T1  Extension of an existing class (SINKS["deserialization"] += …)
  T2  Novel sink with a mappable CWE — new class label auto-registered
  T3  Novel sink with no canonical mapping — external:planner:<slug>
      class, same fallback shape as Semgrep passthrough.
"""
from .planner import PlanOutput, Planner, PlanRule, RuleValidationReport
from .validator import GrepValidator

__all__ = [
    "Planner",
    "PlanOutput",
    "PlanRule",
    "RuleValidationReport",
    "GrepValidator",
]
