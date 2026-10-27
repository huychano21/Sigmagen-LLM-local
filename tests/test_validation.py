"""Tests for the Sigma rule validation module."""
from __future__ import annotations

import pytest

from sigmagen.validation.validator import validate_sigma_rule, ValidationResult


def _valid_rule() -> dict:
    """Return a minimal valid Sigma rule dict."""
    return {
        "title": "Test Detection Rule",
        "id": "3b6ab547-8ec2-4991-b5f0-eb2e8bad3e23",
        "status": "experimental",
        "description": "Detects test activity.",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"CommandLine|contains": "certutil"},
            "condition": "selection",
        },
        "tags": ["attack.execution", "attack.t1059.001"],
        "falsepositives": ["Legitimate admin usage"],
        "level": "high",
    }


def test_valid_rule_passes() -> None:
    """A well-formed rule should pass validation with no errors."""
    result = validate_sigma_rule(_valid_rule())
    assert result.valid is True
    assert result.errors == []


def test_missing_title() -> None:
    """Missing title should produce an error."""
    rule = _valid_rule()
    del rule["title"]
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("title" in e for e in result.errors)


def test_missing_description() -> None:
    """Missing description should produce an error."""
    rule = _valid_rule()
    del rule["description"]
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("description" in e for e in result.errors)


def test_missing_logsource() -> None:
    """Missing logsource should produce an error."""
    rule = _valid_rule()
    del rule["logsource"]
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("logsource" in e for e in result.errors)


def test_missing_detection() -> None:
    """Missing detection should produce an error."""
    rule = _valid_rule()
    del rule["detection"]
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("detection" in e for e in result.errors)


def test_detection_without_condition() -> None:
    """Detection missing a condition key should produce an error."""
    rule = _valid_rule()
    rule["detection"] = {"selection": {"CommandLine|contains": "test"}}
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("condition" in e for e in result.errors)


def test_detection_without_selection() -> None:
    """Detection with only a condition (no selection) should produce an error."""
    rule = _valid_rule()
    rule["detection"] = {"condition": "selection"}
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("selection" in e.lower() for e in result.errors)


def test_invalid_level() -> None:
    """An unrecognised level value should produce an error."""
    rule = _valid_rule()
    rule["level"] = "extreme"
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("level" in e.lower() for e in result.errors)


def test_invalid_status() -> None:
    """An unrecognised status value should produce an error."""
    rule = _valid_rule()
    rule["status"] = "production"
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("status" in e.lower() for e in result.errors)


def test_invalid_uuid() -> None:
    """A malformed UUID should produce an error."""
    rule = _valid_rule()
    rule["id"] = "not-a-uuid"
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("UUID" in e or "uuid" in e.lower() for e in result.errors)


def test_missing_attack_tags_is_warning_not_error() -> None:
    """Missing ATT&CK tags should produce a warning, not an error."""
    rule = _valid_rule()
    rule["tags"] = ["custom.tag"]
    result = validate_sigma_rule(rule)
    assert result.valid is True  # Still valid
    assert any("ATT&CK" in w for w in result.warnings)


def test_missing_falsepositives_is_warning() -> None:
    """Missing falsepositives should produce a warning, not an error."""
    rule = _valid_rule()
    del rule["falsepositives"]
    result = validate_sigma_rule(rule)
    assert result.valid is True
    assert any("falsepositives" in w for w in result.warnings)


def test_logsource_without_required_keys() -> None:
    """Logsource without category, product, or service should error."""
    rule = _valid_rule()
    rule["logsource"] = {"custom_field": "value"}
    result = validate_sigma_rule(rule)
    assert result.valid is False
    assert any("category" in e or "product" in e or "service" in e for e in result.errors)
