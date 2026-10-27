"""Pure-Python Sigma rule schema validation (no sigma-cli dependency required)."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REQUIRED_FIELDS = {"title", "description", "logsource", "detection"}
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
ATTACK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


@dataclass
class ValidationResult:
    """Result of validating a Sigma rule."""

    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: ValidationResult) -> None:
        """Merge another result into this one."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if other.errors:
            self.valid = False


def validate_sigma_rule(data: dict) -> ValidationResult:
    """Validate a parsed Sigma rule dict against the schema.

    Checks:
    1. Required fields present
    2. title is non-empty string
    3. description is non-empty string
    4. logsource is non-empty dict with category, product, or service
    5. detection has "condition" key
    6. detection has at least one selection key
    7. level is valid (if present)
    8. status is valid (if present)
    9. tags is a list (if present)
    10. id is a valid UUID (if present)
    11. Warn if no ATT&CK technique tags
    12. Warn if falsepositives missing or empty
    """
    result = ValidationResult()

    # 1. Required fields
    for field_name in REQUIRED_FIELDS:
        if field_name not in data:
            result.errors.append(f"Missing required field: {field_name}")
            result.valid = False

    # 2. title
    title = data.get("title")
    if isinstance(title, str):
        if not title.strip():
            result.errors.append("title must be a non-empty string")
            result.valid = False
    elif title is not None:
        result.errors.append("title must be a string")
        result.valid = False

    # 3. description
    description = data.get("description")
    if isinstance(description, str):
        if not description.strip():
            result.errors.append("description must be a non-empty string")
            result.valid = False
    elif "description" in data:
        result.errors.append("description must be a string")
        result.valid = False

    # 4. logsource
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not logsource:
            result.errors.append("logsource must be a non-empty dict")
            result.valid = False
        elif not any(k in logsource for k in ("category", "product", "service")):
            result.errors.append(
                "logsource must contain at least one of: category, product, service"
            )
            result.valid = False
    elif "logsource" in data:
        result.errors.append("logsource must be a dict")
        result.valid = False

    # 5 & 6. detection
    detection = data.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            result.errors.append("detection must contain a 'condition' key")
            result.valid = False
        selection_keys = [k for k in detection if k != "condition"]
        if not selection_keys:
            result.errors.append(
                "detection must have at least one selection key besides 'condition'"
            )
            result.valid = False
    elif "detection" in data:
        result.errors.append("detection must be a dict")
        result.valid = False

    # 7. level
    level = data.get("level")
    if level is not None:
        if str(level).lower() not in VALID_LEVELS:
            result.errors.append(
                f"Invalid level '{level}'. Must be one of: {', '.join(sorted(VALID_LEVELS))}"
            )
            result.valid = False

    # 8. status
    status = data.get("status")
    if status is not None:
        if str(status).lower() not in VALID_STATUSES:
            result.errors.append(
                f"Invalid status '{status}'. "
                f"Must be one of: {', '.join(sorted(VALID_STATUSES))}"
            )
            result.valid = False

    # 9. tags
    tags = data.get("tags")
    if tags is not None and not isinstance(tags, list):
        result.errors.append("tags must be a list")
        result.valid = False

    # 10. id (UUID)
    rule_id = data.get("id")
    if rule_id is not None:
        if not UUID_RE.match(str(rule_id)):
            result.errors.append(f"id '{rule_id}' is not a valid UUID")
            result.valid = False

    # 11. Warn if no ATT&CK technique tags
    if isinstance(tags, list):
        has_attack = any(ATTACK_TAG_RE.match(str(t)) for t in tags)
        if not has_attack:
            result.warnings.append("No ATT&CK technique tags found in tags list")
    elif tags is None:
        result.warnings.append("No tags field — consider adding ATT&CK technique tags")

    # 12. Warn if falsepositives missing or empty
    fps = data.get("falsepositives")
    if not fps:
        result.warnings.append("falsepositives is missing or empty")

    return result


def validate_sigma_yaml(yaml_text: str) -> ValidationResult:
    """Parse a YAML string and validate each document as a Sigma rule.

    Returns a merged ``ValidationResult`` covering all documents.
    """
    merged = ValidationResult()

    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        merged.errors.append(f"YAML parse error: {exc}")
        merged.valid = False
        return merged

    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            merged.errors.append(f"Document {i + 1} is not a YAML mapping")
            merged.valid = False
            continue
        result = validate_sigma_rule(doc)
        if len(docs) > 1:
            result.errors = [f"[Doc {i + 1}] {e}" for e in result.errors]
            result.warnings = [f"[Doc {i + 1}] {w}" for w in result.warnings]
        merged.merge(result)

    return merged


def validate_with_sigma_cli(yaml_path: Path) -> ValidationResult:
    """Run sigma-cli validation on a YAML file if available.

    Returns a ``ValidationResult`` with warnings if sigma-cli is not installed.
    """
    result = ValidationResult()

    try:
        proc = subprocess.run(
            ["sigma", "check", str(yaml_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        result.warnings.append(
            "sigma-cli not installed, using built-in validator only. "
            "Install with: pip install sigma-cli"
        )
        return result
    except subprocess.TimeoutExpired:
        result.warnings.append("sigma-cli timed out")
        return result

    if proc.returncode != 0:
        # Parse stderr for error messages
        for line in proc.stderr.strip().splitlines():
            line = line.strip()
            if line:
                result.errors.append(f"sigma-cli: {line}")
        if result.errors:
            result.valid = False
        # Also check stdout for warnings
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if line:
                result.warnings.append(f"sigma-cli: {line}")
    else:
        for line in proc.stdout.strip().splitlines():
            line = line.strip()
            if line:
                result.warnings.append(f"sigma-cli: {line}")

    return result


def validate_generated_rules(yaml_text: str) -> list[ValidationResult]:
    """Split a multi-document YAML string and validate each block independently.

    Returns one ``ValidationResult`` per YAML block.
    """
    blocks = yaml_text.split("\n---\n")
    results: list[ValidationResult] = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        result = ValidationResult()
        try:
            parsed = yaml.safe_load(block)
        except yaml.YAMLError as exc:
            result.errors.append(f"YAML parse error: {exc}")
            result.valid = False
            results.append(result)
            continue

        if not isinstance(parsed, dict):
            result.errors.append("Parsed YAML is not a mapping")
            result.valid = False
            results.append(result)
            continue

        results.append(validate_sigma_rule(parsed))

    return results
