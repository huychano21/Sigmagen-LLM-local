"""Deterministic Sigma YAML (.yml) to Wazuh XML (.xml) Compiler, Validator & Auto-ID Allocator.

Converts verified Sigma detection rules into production-ready Wazuh XML rules
compatible with the `LLM_API` deployment pipeline:
- Group wrapper: `<group name="ml_generated,sysmon,">` (configurable)
- Rule ID range: `100100` to `109999` (configurable via `RULE_ID_MIN`, `RULE_ID_MAX`)
- Automatic Persistent Rule ID Allocator (`allocate_next_wazuh_rule_id`): scans `rule_registry.json`
  and existing `ml_generated_*.xml` files in `./output` so rule IDs are assigned automatically
  without manual user input.
- Parent inheritance: maps Sigma `logsource` / Alert EventID to exact Wazuh Sysmon group
  names (`sysmon_event1`, `sysmon_event3`, `sysmon_event_11`, `sysmon_event_13`, etc.)
- Field conditions: maps Sigma `Field|modifier` clauses to `<field name="win.eventdata.<camelCase>" type="pcre2">(?i)...</field>`
  with automatic Windows backslash escaping (`\\+`) so Wazuh's double-escaped eventchannel JSON matches reliably.
- Validates the resulting XML using the same strict syntax rules as `LLM_API/rag/app/validator.py`.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

import yaml

from sigmagen.ingestion.alert_adapter import (
    FIELD_ALIASES,
    NormalizedAlertBundle,
)

RULE_ID_MIN_DEFAULT = 100100
RULE_ID_MAX_DEFAULT = 109999

SIGMA_LEVEL_TO_WAZUH: dict[str, int] = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}

CATEGORY_TO_WAZUH_GROUP: dict[str, str] = {
    "process_creation": "sysmon_event1",
    "network_connection": "sysmon_event3",
    "image_load": "sysmon_event7",
    "create_remote_thread": "sysmon_event8",
    "process_access": "sysmon_event10",
    "file_event": "sysmon_event_11",
    "file_create": "sysmon_event_11",
    "registry_event": "sysmon_event_13",
    "registry_set": "sysmon_event_13",
    "registry_add": "sysmon_event_12",
    "registry_delete": "sysmon_event_12",
    "dns_query": "sysmon_event_22",
}


def allocate_next_wazuh_rule_id(
    output_dir: Path | str = "./output",
    alert_id: str | None = None,
    rule_id_min: int = RULE_ID_MIN_DEFAULT,
    rule_id_max: int = RULE_ID_MAX_DEFAULT,
    reuse_for_same_alert: bool = True,
) -> int:
    """Automatically allocate the next available Wazuh Rule ID in [100100, 109999].

    Scans both `rule_registry.json` and any `*.xml` / `*.eval.json` files inside `output_dir`
    (and its subdirectories) so IDs never collide and require zero manual user input.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    registry_path = out_path / "rule_registry.json"

    registry: dict[str, Any] = {"next_id": rule_id_min, "alert_to_rule_id": {}, "history": []}
    if registry_path.exists():
        try:
            loaded = json.loads(registry_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                registry.update(loaded)
                if not isinstance(registry.get("alert_to_rule_id"), dict):
                    registry["alert_to_rule_id"] = {}
                if not isinstance(registry.get("history"), list):
                    registry["history"] = []
        except Exception:
            pass

    # If this exact alert_id already has a registered rule ID in range, reuse it if requested
    if reuse_for_same_alert and alert_id and alert_id in registry["alert_to_rule_id"]:
        existing_id = int(registry["alert_to_rule_id"][alert_id])
        if rule_id_min <= existing_id <= rule_id_max:
            return existing_id

    used_ids: set[int] = set()
    for aid_val in registry["alert_to_rule_id"].values():
        try:
            used_ids.add(int(aid_val))
        except (TypeError, ValueError):
            pass

    # Scan existing ml_generated_*.xml and *.eval.json files in output_dir
    for xml_file in out_path.rglob("*.xml"):
        m = re.search(r"(\d{6})", xml_file.stem)
        if m:
            rid = int(m.group(1))
            if rule_id_min <= rid <= rule_id_max:
                used_ids.add(rid)
        try:
            xml_txt = xml_file.read_text(encoding="utf-8-sig")
            for m_id in re.findall(r'<rule\s+id=["\'](\d+)["\']', xml_txt):
                rid = int(m_id)
                if rule_id_min <= rid <= rule_id_max:
                    used_ids.add(rid)
        except Exception:
            pass

    candidate = max(int(registry.get("next_id") or rule_id_min), rule_id_min)
    if used_ids:
        candidate = max(candidate, max(used_ids) + 1)
    while candidate in used_ids and candidate <= rule_id_max:
        candidate += 1

    if candidate > rule_id_max:
        # Wrap around to find any gap in [rule_id_min, rule_id_max]
        for rid in range(rule_id_min, rule_id_max + 1):
            if rid not in used_ids:
                candidate = rid
                break

    if alert_id:
        registry["alert_to_rule_id"][alert_id] = candidate
    registry["next_id"] = min(candidate + 1, rule_id_max)
    registry["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        registry_path.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

    return candidate


def register_generated_rule_metadata(
    output_dir: Path | str,
    entry: dict[str, Any],
) -> None:
    """Record a generated & verified rule entry into `output/rule_registry.json` for dashboard display."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    registry_path = out_path / "rule_registry.json"

    registry: dict[str, Any] = {"next_id": RULE_ID_MIN_DEFAULT, "alert_to_rule_id": {}, "history": []}
    if registry_path.exists():
        try:
            loaded = json.loads(registry_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                registry.update(loaded)
        except Exception:
            pass

    history: list[dict[str, Any]] = registry.get("history") if isinstance(registry.get("history"), list) else []
    alert_id = entry.get("alert_id")
    rule_id = entry.get("wazuh_rule_id")

    if alert_id and rule_id:
        registry.setdefault("alert_to_rule_id", {})[str(alert_id)] = int(rule_id)
        try:
            registry["next_id"] = max(int(registry.get("next_id") or RULE_ID_MIN_DEFAULT), int(rule_id) + 1)
        except (TypeError, ValueError):
            pass

    # Replace existing entry for same alert_id or wazuh_rule_id, or prepend
    filtered = [
        item for item in history
        if not (
            (alert_id and item.get("alert_id") == alert_id)
            or (rule_id and item.get("wazuh_rule_id") == rule_id and item.get("sigma_yaml_file") == entry.get("sigma_yaml_file"))
        )
    ]
    filtered.insert(0, entry)
    registry["history"] = filtered[:200]
    registry["updated_at"] = datetime.now(timezone.utc).isoformat()

    try:
        registry_path.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def sigma_field_to_wazuh_field(sigma_field: str) -> str:
    """Convert a Sigma field name (e.g. `Image`, `TargetFilename`) to Wazuh `win.eventdata.<camelCase>`."""
    f_clean = sigma_field.strip()
    f_low = f_clean.lower()
    if f_low in ("eventid", "win.system.eventid"):
        return "win.system.eventID"
    if f_low in ("channel", "win.system.channel"):
        return "win.system.channel"
    if f_low in FIELD_ALIASES:
        return FIELD_ALIASES[f_low][1]
    if f_clean.startswith("win."):
        return f_clean
    return f"win.eventdata.{f_clean[0].lower() + f_clean[1:]}"


def _escape_pcre2_literal_with_win_paths(val: str) -> str:
    """Escape a literal string for Wazuh PCRE2 while converting path separators `\\` into `\\\\+`."""
    norm = re.sub(r"\\{2,}", r"\\", val.strip())
    segments = norm.split("\\")
    escaped_segments = [re.escape(seg) for seg in segments]
    return r"\\+".join(escaped_segments)


def sigma_clause_to_pcre2(modifiers: list[str], raw_val: Any) -> list[tuple[str, bool]]:
    """Convert a Sigma modifier list and value(s) into one or more `(pcre2_pattern, negate_bool)` tuples."""
    mods = [m.lower() for m in modifiers]
    require_all = "all" in mods
    is_regex = "re" in mods
    is_startswith = "startswith" in mods
    is_endswith = "endswith" in mods
    is_contains = "contains" in mods

    vals = raw_val if isinstance(raw_val, list) else [raw_val]
    vals = [str(v) for v in vals if v is not None and str(v) != ""]
    if not vals:
        return []

    def _convert_one(v: str) -> str:
        if is_regex:
            return v if v.startswith("(?i)") else f"(?i){v}"
        esc = _escape_pcre2_literal_with_win_paths(v)
        if is_startswith and is_endswith:
            return f"^{esc}$"
        if is_startswith:
            return f"^{esc}"
        if is_endswith:
            return f"{esc}$"
        if is_contains:
            return esc
        if "*" in v or "?" in v:
            parts = re.split(r"(\*|\?)", re.sub(r"\\{2,}", r"\\", v))
            out = []
            for p in parts:
                if p == "*":
                    out.append(".*")
                elif p == "?":
                    out.append(".")
                elif p:
                    out.append(_escape_pcre2_literal_with_win_paths(p))
            return "".join(out)
        return f"^{esc}$"

    if require_all:
        return [(f"(?i){_convert_one(v)}", False) for v in vals]

    converted = [_convert_one(v) for v in vals]
    if len(converted) == 1:
        return [(f"(?i){converted[0]}", False)]
    joined = "|".join(converted)
    return [(f"(?i)(?:{joined})", False)]


@dataclass
class WazuhConversionResult:
    """Result of compiling a Sigma YAML rule to Wazuh XML and validating it."""

    rule_id: int
    group_wrapper: str
    wazuh_xml: str
    xml_valid: bool
    xml_errors: list[str] = field(default_factory=list)
    xml_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compile_sigma_to_wazuh_xml(
    raw_yaml: str,
    rule_id: int = RULE_ID_MIN_DEFAULT,
    bundle: NormalizedAlertBundle | None = None,
    group_wrapper: str = "ml_generated,sysmon,",
    rule_id_min: int = RULE_ID_MIN_DEFAULT,
    rule_id_max: int = RULE_ID_MAX_DEFAULT,
) -> WazuhConversionResult:
    """Compile a Sigma YAML rule into a Wazuh XML `<group><rule>...</rule></group>` block."""
    try:
        parsed = yaml.safe_load(raw_yaml)
    except Exception as exc:
        return WazuhConversionResult(
            rule_id=rule_id,
            group_wrapper=group_wrapper,
            wazuh_xml="",
            xml_valid=False,
            xml_errors=[f"Invalid YAML syntax: {exc}"],
        )

    if not isinstance(parsed, dict):
        return WazuhConversionResult(
            rule_id=rule_id,
            group_wrapper=group_wrapper,
            wazuh_xml="",
            xml_valid=False,
            xml_errors=["Input Sigma YAML is not a valid mapping"],
        )

    title = str(parsed.get("title") or "Sigma Generated Detection Rule").strip()
    level_str = str(parsed.get("level") or "medium").lower()
    wazuh_level = SIGMA_LEVEL_TO_WAZUH.get(level_str, 10)

    logsource = parsed.get("logsource") or {}
    cat = str(logsource.get("category") or "").lower()
    parent_group = CATEGORY_TO_WAZUH_GROUP.get(cat, "")

    if not parent_group and bundle and bundle.primary_events:
        parent_group = bundle.primary_events[0].expected_wazuh_group
    if not parent_group:
        parent_group = "sysmon_event1"

    is_sysmon_group = parent_group.startswith("sysmon_event")

    detection = parsed.get("detection") or {}
    field_elements: list[tuple[str, str, bool]] = []

    if isinstance(detection, dict):
        for b_name, b_val in detection.items():
            if b_name in ("condition", "timeframe"):
                continue
            is_filter = b_name.lower().startswith("filter")

            if isinstance(b_val, dict):
                for spec_k, exp_v in b_val.items():
                    parts = [p.strip() for p in str(spec_k).split("|") if p.strip()]
                    f_name = parts[0]
                    if is_sysmon_group and f_name.lower() in ("eventid", "channel"):
                        continue
                    w_field = sigma_field_to_wazuh_field(f_name)
                    mods = parts[1:]
                    clauses = sigma_clause_to_pcre2(mods, exp_v)
                    for pat, neg in clauses:
                        field_elements.append((w_field, pat, True if is_filter else neg))
            elif isinstance(b_val, list):
                for sub in b_val:
                    if isinstance(sub, dict):
                        for spec_k, exp_v in sub.items():
                            parts = [p.strip() for p in str(spec_k).split("|") if p.strip()]
                            f_name = parts[0]
                            if is_sysmon_group and f_name.lower() in ("eventid", "channel"):
                                continue
                            w_field = sigma_field_to_wazuh_field(f_name)
                            clauses = sigma_clause_to_pcre2(parts[1:], exp_v)
                            for pat, neg in clauses:
                                field_elements.append((w_field, pat, True if is_filter else neg))

    mitre_ids: list[str] = []
    tags = parsed.get("tags") or []
    if isinstance(tags, list):
        for t in tags:
            m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", str(t).strip(), re.I)
            if m:
                tid = m.group(1).upper()
                if tid not in mitre_ids:
                    mitre_ids.append(tid)

    xml_lines = [
        f'<group name="{xml_escape(group_wrapper)}">',
        f'  <rule id="{rule_id}" level="{wazuh_level}">',
        f"    <if_group>{xml_escape(parent_group)}</if_group>",
    ]

    for w_field, pat, neg in field_elements:
        neg_attr = ' negate="yes"' if neg else ""
        xml_lines.append(
            f'    <field name="{xml_escape(w_field)}" type="pcre2"{neg_attr}>{xml_escape(pat)}</field>'
        )

    desc_text = title
    if bundle and bundle.alert_id:
        desc_text = f"{title} [Alert: {bundle.alert_id}]"
    xml_lines.append(f"    <description>{xml_escape(desc_text)}</description>")

    if mitre_ids:
        xml_lines.append("    <mitre>")
        for tid in mitre_ids:
            xml_lines.append(f"      <id>{xml_escape(tid)}</id>")
        xml_lines.append("    </mitre>")

    xml_lines.append("  </rule>")
    xml_lines.append("</group>")
    wazuh_xml = "\n".join(xml_lines)

    errors, warnings = validate_wazuh_xml_syntax(wazuh_xml, rule_id, rule_id_min, rule_id_max)
    return WazuhConversionResult(
        rule_id=rule_id,
        group_wrapper=group_wrapper,
        wazuh_xml=wazuh_xml,
        xml_valid=(len(errors) == 0),
        xml_errors=errors,
        xml_warnings=warnings,
    )


def validate_wazuh_xml_syntax(
    xml_str: str,
    expected_id: int,
    id_min: int = RULE_ID_MIN_DEFAULT,
    id_max: int = RULE_ID_MAX_DEFAULT,
) -> tuple[list[str], list[str]]:
    """Validate Wazuh XML rule syntax according to LLM_API `validator.py` rules."""
    errors: list[str] = []
    warnings: list[str] = []

    if not xml_str or not xml_str.strip():
        return ["Empty XML string"], warnings

    try:
        root = ET.fromstring(xml_str.strip())
    except ET.ParseError as exc:
        return [f"Invalid XML syntax: {exc}"], warnings

    if root.tag != "group":
        errors.append(f"Root tag must be <group>, got <{root.tag}>")

    rules = list(root.iter("rule"))
    if len(rules) != 1:
        errors.append(f"Must contain exactly 1 <rule>, found {len(rules)}")
        return errors, warnings

    r_el = rules[0]
    try:
        rid = int(r_el.get("id", ""))
    except ValueError:
        rid = -1
    if rid != expected_id:
        errors.append(f"Rule id={rid} does not match assigned ID {expected_id}")
    if not (id_min <= rid <= id_max):
        errors.append(f"Rule id={rid} outside allowed range {id_min}-{id_max}")

    try:
        lvl = int(r_el.get("level", ""))
    except ValueError:
        lvl = -1
    if not (0 <= lvl <= 15):
        errors.append(f"Rule level={lvl} must be between 0 and 15")

    has_parent = any(r_el.find(t) is not None for t in ("if_group", "if_sid", "decoded_as"))
    if not has_parent:
        errors.append("Rule is missing parent tag (<if_group> or <if_sid>)")

    fields = r_el.findall("field")
    if not fields and r_el.find("match") is None and r_el.find("regex") is None:
        errors.append("Rule has no <field>, <match>, or <regex> detection conditions")

    for f_el in fields:
        f_name = f_el.get("name", "")
        f_pat = (f_el.text or "").strip()
        if not f_name:
            errors.append("<field> is missing 'name' attribute")
        if not f_pat:
            errors.append(f"<field name='{f_name}'> has empty pattern")
        if f_el.get("type") == "pcre2":
            try:
                re.compile(f_pat)
            except re.error as exc:
                warnings.append(f"PCRE2 pattern '{f_pat}' warning in Python re: {exc}")

    if r_el.find("description") is None or not (r_el.find("description").text or "").strip():
        errors.append("Rule is missing <description>")

    return errors, warnings
