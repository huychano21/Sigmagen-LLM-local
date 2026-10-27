"""Tests for Sigma rule ingestion module."""
from __future__ import annotations

from pathlib import Path

import pytest

from sigmagen.ingestion.sigma import SigmaRule, parse_sigma_rule

VALID_SIGMA_YAML = """\
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-8ec2-4991-b5f0-eb2e8bad3e23
status: experimental
description: Detects PowerShell download cradle usage.
author: Test Author
date: 2024/01/01
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'downloadstring'
    condition: selection
falsepositives:
    - Legitimate admin scripts
level: high
"""

MISSING_TITLE_YAML = """\
id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
status: experimental
description: No title here.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
level: medium
"""

NO_CONDITION_YAML = """\
title: Rule Without Condition
id: 11111111-2222-3333-4444-555555555555
description: Missing condition key in detection.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
level: medium
"""


@pytest.fixture()
def valid_sigma_path(tmp_path: Path) -> Path:
    """Write valid Sigma YAML to a temp file."""
    path = tmp_path / "valid_rule.yml"
    path.write_text(VALID_SIGMA_YAML, encoding="utf-8")
    return path


@pytest.fixture()
def missing_title_path(tmp_path: Path) -> Path:
    """Write Sigma YAML missing a title to a temp file."""
    path = tmp_path / "no_title.yml"
    path.write_text(MISSING_TITLE_YAML, encoding="utf-8")
    return path


@pytest.fixture()
def no_condition_path(tmp_path: Path) -> Path:
    """Write Sigma YAML with detection lacking a condition key."""
    path = tmp_path / "no_condition.yml"
    path.write_text(NO_CONDITION_YAML, encoding="utf-8")
    return path


def test_parse_valid_rule(valid_sigma_path: Path) -> None:
    """A well-formed Sigma YAML should parse into a SigmaRule."""
    rule = parse_sigma_rule(valid_sigma_path)
    assert rule is not None
    assert rule.title == "Suspicious PowerShell Download Cradle"
    assert rule.level == "high"
    assert "attack.t1059.001" in rule.tags


def test_parse_returns_none_for_missing_title(missing_title_path: Path) -> None:
    """YAML without a title field should return None."""
    rule = parse_sigma_rule(missing_title_path)
    assert rule is None


def test_parse_returns_none_for_no_condition(no_condition_path: Path) -> None:
    """Detection block without a condition key should return None."""
    rule = parse_sigma_rule(no_condition_path)
    assert rule is None


def test_technique_ids_normalised() -> None:
    """Tags like attack.t1059.001 should normalise to T1059.001."""
    rule = SigmaRule(tags=["attack.execution", "attack.t1059.001", "attack.t1105"])
    assert "T1059.001" in rule.technique_ids
    assert "T1105" in rule.technique_ids


def test_tactic_tags() -> None:
    """Tactic tags should be extracted from attack.<tactic> format."""
    rule = SigmaRule(tags=["attack.execution", "attack.t1059.001", "attack.persistence"])
    assert "execution" in rule.tactic_tags
    assert "persistence" in rule.tactic_tags


def test_to_metadata_returns_flat_dict() -> None:
    """All metadata values must be str, int, float, or bool."""
    rule = SigmaRule(
        rule_id="3b6ab547-8ec2-4991-b5f0-eb2e8bad3e23",
        title="Test Rule",
        status="experimental",
        level="high",
        tags=["attack.execution", "attack.t1059.001"],
        logsource={"category": "process_creation", "product": "windows"},
        detection={"selection": {"CommandLine|contains": "test"}, "condition": "selection"},
        author="Author",
        file_path="rules/test.yml",
        references=["https://example.com"],
    )
    meta = rule.to_metadata()
    for key, value in meta.items():
        assert isinstance(value, (str, int, float, bool)), (
            f"Metadata key '{key}' has non-primitive type {type(value).__name__}"
        )


def test_logsource_properties() -> None:
    """Logsource properties should extract category, product, and service."""
    rule = SigmaRule(
        logsource={"category": "process_creation", "product": "windows", "service": "sysmon"}
    )
    assert rule.logsource_category == "process_creation"
    assert rule.logsource_product == "windows"
    assert rule.logsource_service == "sysmon"


def test_to_document_contains_title() -> None:
    """to_document() should include the rule title."""
    rule = SigmaRule(title="My Detection Rule", description="Detects bad stuff.")
    doc = rule.to_document()
    assert "My Detection Rule" in doc
    assert "Detects bad stuff" in doc
