"""Non-repudiation ledger — Ed25519 signing + signed chain-of-custody.

Every finding produced by Spotlight ships with a chain_of_custody: a
signed, append-only list of the actions the agents (and any human
reviewers) took while producing it. Each git commit that Spotlight
opens against a customer repo carries a ``Signed-off-by-agent`` trailer
that links back to that chain — so when something goes wrong the bank
can point at the *agent* that did it, not the human whose keys were
attached to the sweep.

Public surface:

- :class:`Signer` — hold a workspace signing key, sign entries.
- :func:`sign_action` — one-shot sign convenience.
- :func:`verify_action` — verify a single signed entry.
- :func:`get_or_create_workspace_keys` — load or generate key material.
- :class:`ChainOfCustody` — accumulator for a finding's audit trail.
"""
from .chain import ChainOfCustody
from .signing import (
    Signer,
    SigningKey,
    VerifyKey,
    get_or_create_workspace_keys,
    sign_action,
    verify_action,
)

__all__ = [
    "ChainOfCustody",
    "Signer",
    "SigningKey",
    "VerifyKey",
    "get_or_create_workspace_keys",
    "sign_action",
    "verify_action",
]
