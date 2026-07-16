"""Spotlight redaction pipeline.

Phase-2 Tranche A6: stop secrets in a scanned target from leaking into
model prompts, event logs, or API responses. Three chokepoints wrap this
module:

  (a) `spotlight.agents.moonshot._prompts_for` — outbound prompt scrub.
  (b) `spotlight.orchestrator.events.EventBus.emit` — event payload scrub.
  (c) `spotlight.api.app._redact_response` — HTTP response scrub.

Paranoid defaults: over-redact on ambiguity. A false positive means an
analyst sees `[REDACTED:...]`; a false negative means a live key ends up
in a model log. We prefer the former.
"""
from .pipeline import RedactionMatch, Redactor, redact

__all__ = ["Redactor", "redact", "RedactionMatch"]
