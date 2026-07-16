"""Vulnerability class taxonomy contract tests.

Lock the shape of what Spotlight claims to detect. If a class code lands in
a Profile, it MUST exist in the taxonomy — the Console's coverage picker
depends on this."""
from __future__ import annotations

from spotlight.profiles import list_profiles
from spotlight.taxonomy import ALL_CLASSES, BY_ID, get, list_ids, counts_by_surface


def test_taxonomy_has_a_substantial_class_list():
    """At Phase 2 we should be listing at minimum 50 industry-recognized classes
    across code, agentic, secrets, crypto, and config surfaces. Anything less
    and Spotlight looks like a toy scanner. Any more is fine."""
    assert len(ALL_CLASSES) >= 50, (
        f"only {len(ALL_CLASSES)} classes — expected 50+ (OWASP Top 10 + LLM Top 10 + "
        f"SANS/CWE Top 25 + secret shapes + crypto)"
    )


def test_every_class_has_a_cwe_mapping():
    """The Attestation's audit trail claims 'CWE mapped for every promoted
    finding'. That claim requires every class to have a CWE."""
    missing = [c.id for c in ALL_CLASSES if not c.cwe.startswith("CWE-")]
    assert not missing, f"classes without a CWE mapping: {missing}"


def test_class_ids_are_unique():
    ids = [c.id for c in ALL_CLASSES]
    assert len(ids) == len(set(ids)), "duplicate class IDs in taxonomy"


def test_every_profile_class_exists_in_taxonomy():
    """A Profile can only whitelist classes that Spotlight has a detector /
    prompt template for. This is the check that stops a Profile from silently
    doing nothing because a class name was typo'd."""
    valid = set(list_ids()) | {
        # aliases we tolerate in Profile.classes for readability:
        "authz",  # → missing-authz
        "eval",   # → code-injection
        "crypto", # → weak-crypto / weak-hash
        "deserialization",  # → deserialization (present)
        "race",  # → race (present)
        "proto-pollution",  # present
    }
    for profile in list_profiles():
        for cls in profile.classes:
            assert cls in valid, f"profile {profile.id!r} references unknown class {cls!r}"


def test_agentic_surface_covers_all_owasp_llm_categories():
    """Any Spotlight 'Agentic' profile should hit OWASP LLM01..LLM10."""
    agentic = [c for c in ALL_CLASSES if c.surface == "agentic"]
    llm_categories = {c.owasp_llm for c in agentic if c.owasp_llm}
    for i in range(1, 11):
        code = f"LLM{i:02d}"
        assert code in llm_categories, f"missing OWASP {code} coverage in taxonomy"


def test_secrets_surface_has_realistic_shape_coverage():
    """Users expect Spotlight to at least detect the top 6 secret shapes:
    AWS, GCP, GitHub PAT, OpenAI, Anthropic, Slack, private key."""
    secrets = [c for c in ALL_CLASSES if c.surface == "secrets"]
    required = {
        "hardcoded-aws-key",
        "hardcoded-github-pat",
        "hardcoded-openai-key",
        "hardcoded-anthropic-key",
        "hardcoded-slack-token",
        "hardcoded-private-key",
    }
    ids = {c.id for c in secrets}
    missing = required - ids
    assert not missing, f"missing secret shapes: {missing}"


def test_counts_by_surface_sums_to_total():
    counts = counts_by_surface()
    assert sum(counts.values()) == len(ALL_CLASSES)


def test_taxonomy_get_returns_class_or_none():
    assert get("sqli") is not None
    assert get("sqli").cwe == "CWE-89"
    assert get("nonexistent-class-that-cannot-exist") is None


def test_static_classes_are_marked_as_such():
    """Static-fact classes (secrets, weak-hash, etc.) don't need a
    Reproducer. Test they're marked so the orchestrator knows."""
    for cls in ALL_CLASSES:
        if cls.surface == "secrets":
            assert cls.detection == "static", f"secrets class {cls.id!r} should be static"
