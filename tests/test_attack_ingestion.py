"""Tests for MITRE ATT&CK ingestion module."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from sigmagen.ingestion.attack import AttackTechnique, parse_attack_json


def _make_stix_bundle(objects: list[dict]) -> dict:
    """Helper to build a minimal STIX bundle."""
    return {"type": "bundle", "id": "bundle--test", "objects": objects}


def _make_attack_pattern(
    technique_id: str = "T1059",
    name: str = "Command and Scripting Interpreter",
    deprecated: bool = False,
    revoked: bool = False,
    is_subtechnique: bool = False,
    tactics: list[str] | None = None,
) -> dict:
    """Helper to build a minimal attack-pattern STIX object."""
    obj: dict = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{technique_id.lower()}",
        "name": name,
        "description": f"Description for {technique_id}.",
        "x_mitre_detection": f"Monitor for {technique_id}.",
        "x_mitre_data_sources": ["Process: Process Creation"],
        "x_mitre_platforms": ["Windows"],
        "x_mitre_is_subtechnique": is_subtechnique,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }
        ],
    }
    if deprecated:
        obj["x_mitre_deprecated"] = True
    if revoked:
        obj["revoked"] = True
    if tactics:
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics
        ]
    return obj


@pytest.fixture()
def stix_bundle_path(tmp_path: Path) -> Path:
    """Write a synthetic STIX bundle to a temp file and return its path."""
    objects = [
        _make_attack_pattern("T1059", tactics=["execution"]),
        _make_attack_pattern(
            "T1059.001",
            name="PowerShell",
            is_subtechnique=True,
            tactics=["execution"],
        ),
        _make_attack_pattern("T9999", deprecated=True),
        _make_attack_pattern("T9998", revoked=True),
        # Object without mitre-attack reference
        {
            "type": "attack-pattern",
            "id": "attack-pattern--no-ref",
            "name": "No Ref",
            "external_references": [{"source_name": "other", "external_id": "X001"}],
        },
        # Non attack-pattern object (should be ignored)
        {"type": "identity", "id": "identity--test", "name": "Test"},
    ]
    bundle = _make_stix_bundle(objects)
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def test_parse_produces_correct_count(stix_bundle_path: Path) -> None:
    """Only non-deprecated, non-revoked attack-patterns with mitre-attack refs are kept."""
    techniques = parse_attack_json(stix_bundle_path)
    assert len(techniques) == 2


def test_deprecated_techniques_are_filtered(stix_bundle_path: Path) -> None:
    """Deprecated techniques must not appear in the result."""
    techniques = parse_attack_json(stix_bundle_path)
    ids = {t.technique_id for t in techniques}
    assert "T9999" not in ids


def test_revoked_techniques_are_filtered(stix_bundle_path: Path) -> None:
    """Revoked techniques must not appear in the result."""
    techniques = parse_attack_json(stix_bundle_path)
    ids = {t.technique_id for t in techniques}
    assert "T9998" not in ids


def test_technique_ids_are_normalised(stix_bundle_path: Path) -> None:
    """Technique IDs should be uppercase TXXXX or TXXXX.XXX."""
    techniques = parse_attack_json(stix_bundle_path)
    ids = {t.technique_id for t in techniques}
    assert "T1059" in ids
    assert "T1059.001" in ids


def test_to_document_contains_expected_fields() -> None:
    """to_document() output includes technique ID, name, tactics, and detection."""
    t = AttackTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        description="Adversaries may abuse PowerShell.",
        detection="Monitor for process creation events.",
        data_sources=["Process: Process Creation"],
        tactics=["execution"],
        platforms=["Windows"],
    )
    doc = t.to_document()
    assert "T1059.001" in doc
    assert "PowerShell" in doc
    assert "execution" in doc
    assert "Monitor for process creation" in doc


def test_to_metadata_values_are_primitive() -> None:
    """All metadata values must be str, int, float, or bool for ChromaDB."""
    t = AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactics=["execution"],
        platforms=["Windows", "Linux"],
        data_sources=["Process: Process Creation"],
        is_subtechnique=False,
        url="https://example.com",
        stix_id="attack-pattern--test",
    )
    meta = t.to_metadata()
    for key, value in meta.items():
        assert isinstance(value, (str, int, float, bool)), (
            f"Metadata key '{key}' has non-primitive type {type(value).__name__}"
        )


def test_parent_technique_id_for_subtechnique() -> None:
    """Sub-techniques should report their parent ID."""
    t = AttackTechnique(technique_id="T1059.001", name="PowerShell", is_subtechnique=True)
    assert t.parent_technique_id == "T1059"


def test_parent_technique_id_for_base_technique() -> None:
    """Base techniques return None for parent_technique_id."""
    t = AttackTechnique(technique_id="T1059", name="CSI", is_subtechnique=False)
    assert t.parent_technique_id is None
