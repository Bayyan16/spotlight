"""Git operations module — shallow clones, branch/commit ops, and `gh pr create`.

Used by the API layer to clone target repos and by the Remediator to open real
PRs. All shell-outs are arg-list based (never shell=True).
"""
from .ops import GitOps, PROpenResult, format_non_repudiation_footer

__all__ = ["GitOps", "PROpenResult", "format_non_repudiation_footer"]
