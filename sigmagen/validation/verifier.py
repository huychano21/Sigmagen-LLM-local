"""Multi-Stage Sigma Rule Verification & Quantitative Scoring Engine (Vòng A & Vòng B).

Answers the 3 mandatory thesis verification questions + Alert Linkage requirement:
1) Question 1 (Syntax & Schema Validity - Weight 20%):
   - Valid YAML mapping, required Sigma fields (`title`, `id`, `status`, `description`, `logsource`, `detection`, `level`, `falsepositives`)
   - Valid Sigma modifiers (`contains`, `endswith`, `startswith`, `all`, `re`, `cidr`, `base64offset`)
   - Valid boolean `condition` expression referencing defined selection/filter blocks
   - Valid canonical MITRE ATT&CK tags (`attack.tXXXX`)
2) Question 2 (Data Match & Alert Linkage - Weight 30%):
   - Logsource alignment with input event family/EventID (e.g. Sysmon EID 1 -> `process_creation`, Sysmon EID 11 -> `file_event`, Sysmon EID 13 -> `registry_set`/`registry_event`)
   - Non-null field grounding: Every field queried in `detection` selections MUST exist and be non-null in the alert's primary event(s) (catches LLM hallucinating `CommandLine` on `file_create` events where `command_line` is `null`)
   - Alert & MITRE context linkage: Rule links back to the input alert ID / MITRE technique context
3) Question 3 (Behavioral Detection & Quality Gate Vòng A & Vòng B - Weight 50%):
   - Vòng A (Rule Correctness & Replay on Primary Attack Telemetry): Deterministic In-Memory Sigma Engine evaluates the rule against all `primary_events` of the alert + `generalized_variants` (mutated usernames/temp tokens to penalize overfitting).
   - Vòng B (Detection Quality & False Positive Evaluation on Background Corpus): Evaluates the rule against `context_events` (non-primary) and the `benign_background` corpus (`ossec-alerts-29.json`, `benign_single_field.json`, Windows/AD baseline events).
   - Computes confusion matrix & metrics: `TP`, `FP`, `FN`, `TN`, `Precision`, `Recall`, `F1-Score`, `Generalization_Rate`, `False_Positive_Rate`, `Confidence_Score` (0-100%), and `Quality_Gate` (`PASS - RECOMMEND_ADD`, `WARN - NEEDS_TUNING`, `FAIL - REJECT`).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

from sigmagen.ingestion.alert_adapter import (
    FIELD_ALIASES,
    NormalizedAlertBundle,
    NormalizedEvent,
)
from sigmagen.validation.validator import validate_sigma_rule

VALID_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "base64",
    "base64offset",
    "cidr",
    "windash",
    "cased",
    "exists",
}

# Compatible Sigma logsource categories for each Sysmon EventID
COMPATIBLE_CATEGORIES: dict[int, set[str]] = {
    1: {"process_creation"},
    3: {"network_connection"},
    7: {"image_load"},
    8: {"create_remote_thread"},
    10: {"process_access"},
    11: {"file_event", "file_create"},
    12: {"registry_event", "registry_add", "registry_delete"},
    13: {"registry_set", "registry_event"},
    15: {"file_event", "file_createstreamhash"},
    22: {"dns_query", "dns"},
}

# Fields where LLMs frequently omit `|contains` or `|endswith` and write a substring/basename
SUBSTRING_TOLERANT_FIELDS = {
    "commandline",
    "parentcommandline",
    "details",
    "targetobject",
    "targetfilename",
    "image",
    "parentimage",
}

# Patterns indicating hardcoded random artifacts (overfitting)
OVERFIT_PATTERNS = [
    (re.compile(r"__PSScriptPolicyTest_[a-z0-9]{6,}\.[a-z0-9]{2,}\.ps1", re.I), "Hardcoded random PowerShell policy test filename suffix"),
    (re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I), "Hardcoded ProcessGuid/LogonGuid"),
    (re.compile(r"\\Users\\mari\\", re.I), "Hardcoded specific username path '\\Users\\mari\\' instead of generic path '\\AppData\\Local\\Temp\\'"),
]


def _normalize_ws_and_quotes(s: str) -> str:
    """Normalize multiple spaces, escaped quotes, and HKLM/HKEY_LOCAL_MACHINE aliases for resilient comparison."""
    out = re.sub(r"\\{2,}", r"\\", s)
    out = out.replace('\\"', '"').replace("'", "")
    out = re.sub(r"hkey_local_machine\\", r"hklm\\", out, flags=re.I)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def resolve_sigma_field_value(field_name: str, ev: NormalizedEvent) -> str | None:
    """Resolve a Sigma field name (e.g. `Image`, `CommandLine`, `TargetFilename`) against a NormalizedEvent."""
    f_clean = field_name.strip()
    f_lower = f_clean.lower()

    for k, v in ev.sigma_fields.items():
        if k.lower() == f_lower:
            return v

    if f_lower in FIELD_ALIASES:
        s_key, _ = FIELD_ALIASES[f_lower]
        for k, v in ev.sigma_fields.items():
            if k.lower() == s_key.lower():
                return v

    for k, v in ev.wazuh_fields.items():
        if k.lower() == f_lower or k.lower().endswith("." + f_lower):
            return v

    return None


def eval_sigma_field_spec(spec_key: str, expected_val: Any, ev: NormalizedEvent) -> tuple[bool, str]:
    """Evaluate a single Sigma `field|modifier1|modifier2: value` clause against a NormalizedEvent.

    Includes resilient normalization for whitespace (`reg  query` vs `reg query`), quotes,
    and substring/basename matching when a local 7B model omits `|contains` / `|endswith`.
    """
    parts = [p.strip() for p in spec_key.split("|") if p.strip()]
    field_name = parts[0]
    f_low = field_name.lower()
    modifiers = [m.lower() for m in parts[1:]]

    actual_val = resolve_sigma_field_value(field_name, ev)

    if "exists" in modifiers:
        want_exists = str(expected_val).lower() in ("true", "1", "yes")
        has_val = actual_val is not None and actual_val != ""
        return (has_val == want_exists, f"field '{field_name}' exists={has_val}")

    if actual_val is None:
        return (False, f"event does NOT have field '{field_name}' (actual is NULL)")

    case_sensitive = "cased" in modifiers
    require_all = "all" in modifiers
    act_cmp = actual_val if case_sensitive else actual_val.lower()
    act_norm = _normalize_ws_and_quotes(act_cmp)

    if isinstance(expected_val, list):
        exp_list = expected_val
    else:
        exp_list = [expected_val]

    def _match_single(exp_item: Any) -> bool:
        if exp_item is None:
            return False
        s_exp = str(exp_item)
        s_exp_norm = re.sub(r"\\{2,}", r"\\", s_exp)
        exp_cmp = s_exp_norm if case_sensitive else s_exp_norm.lower()
        exp_ws_norm = _normalize_ws_and_quotes(exp_cmp)

        if "re" in modifiers:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                return (
                    re.search(s_exp, actual_val, flags) is not None
                    or re.search(s_exp_norm, actual_val, flags) is not None
                    or re.search(s_exp_norm, act_norm, flags) is not None
                )
            except re.error:
                return exp_cmp in act_cmp or exp_ws_norm in act_norm

        if "startswith" in modifiers:
            return act_cmp.startswith(exp_cmp) or act_norm.startswith(exp_ws_norm)
        if "endswith" in modifiers:
            return (
                act_cmp.endswith(exp_cmp)
                or act_norm.endswith(exp_ws_norm)
                or (f_low in ("image", "parentimage", "targetfilename") and act_cmp.endswith(exp_cmp.lstrip("\\")))
            )
        if "contains" in modifiers:
            return exp_cmp in act_cmp or exp_ws_norm in act_norm

        # Default Sigma exact match (supports `*` and `?` wildcards)
        if "*" in exp_cmp or "?" in exp_cmp:
            return fnmatch.fnmatchcase(act_cmp, exp_cmp) or fnmatch.fnmatchcase(act_norm, exp_ws_norm)

        if act_cmp == exp_cmp or act_norm == exp_ws_norm:
            return True

        # Fix #2: Substring / Basename tolerance when Qwen 2.5 7B omits `|contains` or `|endswith`
        if f_low in SUBSTRING_TOLERANT_FIELDS and len(exp_ws_norm) >= 3:
            if f_low in ("image", "parentimage"):
                # e.g. Image: powershell.exe or \powershell.exe
                base_exp = exp_ws_norm.rsplit("\\", 1)[-1]
                base_act = act_norm.rsplit("\\", 1)[-1]
                if base_exp == base_act:
                    return True
            elif exp_ws_norm in act_norm:
                return True
            elif f_low == "details" and exp_ws_norm in ("1", "0x1", "0x00000001", "dword (0x00000001)") and "0x00000001" in act_norm:
                return True

        return False

    results = [_match_single(x) for x in exp_list]
    if not results:
        return (False, f"empty pattern on '{field_name}'")

    matched = all(results) if require_all else any(results)
    if matched:
        return (True, f"matched '{field_name}' (actual={actual_val!r})")
    return (
        False,
        f"field '{field_name}' mismatch: rule expected {expected_val!r} ({'|'.join(modifiers) or 'exact'}), actual={actual_val!r}",
    )


def eval_selection_block(block: Any, ev: NormalizedEvent) -> tuple[bool, list[str]]:
    """Evaluate a named selection/filter block (dict or list of dicts/strings) against an event."""
    reasons: list[str] = []
    if isinstance(block, dict):
        all_ok = True
        for k, v in block.items():
            ok, msg = eval_sigma_field_spec(str(k), v, ev)
            reasons.append(msg)
            if not ok:
                all_ok = False
        return all_ok, reasons

    if isinstance(block, list):
        if all(isinstance(x, dict) for x in block):
            for sub in block:
                ok, sub_reasons = eval_selection_block(sub, ev)
                if ok:
                    return True, sub_reasons
                reasons.extend(sub_reasons)
            return False, reasons
        full_text = " ".join(ev.sigma_fields.values()).lower()
        for kw in block:
            if str(kw).lower() in full_text:
                return True, [f"keyword {kw!r} matched"]
        return False, [f"no keyword in {block!r} matched"]

    return False, ["unsupported selection block structure"]


def check_logsource_compatible(logsource: dict[str, Any], ev: NormalizedEvent) -> tuple[bool, str]:
    """Check whether a Sigma rule's `logsource` is compatible with a NormalizedEvent."""
    if not isinstance(logsource, dict):
        return False, "logsource is not a dict"

    cat = str(logsource.get("category") or "").strip().lower()
    prod = str(logsource.get("product") or "").strip().lower()
    srv = str(logsource.get("service") or "").strip().lower()

    if prod and prod != "windows" and ev.event_family in ("sysmon", "windows_security", "service_control"):
        return False, f"logsource product={prod!r} does not match Windows/Sysmon telemetry"

    if ev.event_family == "sysmon" and ev.event_code in COMPATIBLE_CATEGORIES:
        allowed_cats = COMPATIBLE_CATEGORIES[ev.event_code]
        if cat:
            if cat in allowed_cats:
                return True, f"logsource category={cat!r} matches Sysmon EventID {ev.event_code}"
            return False, (
                f"logsource category={cat!r} does NOT match Sysmon EventID {ev.event_code} "
                f"(expected category in {sorted(allowed_cats)})"
            )
        if srv in ("sysmon", "security", "powershell"):
            return True, f"logsource service={srv!r} accepted"

    if ev.event_family == "windows_security":
        if srv == "security" or cat == "process_creation":
            return True, "logsource matches Windows Security"
        return False, f"logsource (category={cat!r}, service={srv!r}) does not match Windows Security event {ev.event_code}"

    if ev.event_family == "service_control":
        if srv == "system" or prod == "windows":
            return True, "logsource matches Windows System Service Control"

    if ev.event_family == "ossec":
        return False, "non-Windows ossec event"

    return True, "logsource compatible"


def evaluate_sigma_condition(condition_str: str, block_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma `condition:` boolean expression (`selection and not filter`, `1 of selection_*`, etc.)."""
    expr = condition_str.strip()
    if not expr:
        return False

    def _replace_quantifier(match: re.Match) -> str:
        quant = match.group(1).lower()
        target = match.group(2).strip()
        if target == "them":
            matched_keys = [k for k in block_results if not k.lower().startswith("filter")]
        else:
            pat = target.replace("*", ".*")
            matched_keys = [k for k in block_results if re.fullmatch(pat, k)]
        if not matched_keys:
            return "False"
        vals = [block_results[k] for k in matched_keys]
        res = all(vals) if quant == "all" else any(vals)
        return "True" if res else "False"

    expr = re.sub(r"\b(1|any|all)\s+of\s+([a-zA-Z0-9_*]+)", _replace_quantifier, expr, flags=re.I)

    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*-]+", expr, flags=re.I)
    py_tokens: list[str] = []
    for tok in tokens:
        t_low = tok.lower()
        if t_low in ("and", "or", "not", "(", ")"):
            py_tokens.append(t_low)
        elif tok in ("True", "False"):
            py_tokens.append(tok)
        elif tok in block_results:
            py_tokens.append("True" if block_results[tok] else "False")
        else:
            py_tokens.append("False")

    try:
        return bool(eval(" ".join(py_tokens), {"__builtins__": {}}, {}))
    except Exception:
        return False


def evaluate_sigma_rule_on_event(parsed_rule: dict[str, Any], ev: NormalizedEvent) -> dict[str, Any]:
    """Run a parsed Sigma YAML rule against a single NormalizedEvent."""
    logsource = parsed_rule.get("logsource") or {}
    ls_ok, ls_msg = check_logsource_compatible(logsource, ev)

    detection = parsed_rule.get("detection") or {}
    if not isinstance(detection, dict) or "condition" not in detection:
        return {
            "event_id": ev.event_id_uid,
            "role": ev.role,
            "matched": False,
            "logsource_ok": ls_ok,
            "logsource_msg": ls_msg,
            "block_results": {},
            "diagnostics": ["Invalid detection block"],
        }

    block_results: dict[str, bool] = {}
    diagnostics: list[str] = []
    if not ls_ok:
        diagnostics.append(f"Logsource mismatch: {ls_msg}")

    for k, v in detection.items():
        if k == "condition" or k == "timeframe":
            continue
        b_ok, b_reasons = eval_selection_block(v, ev)
        block_results[k] = b_ok
        diagnostics.extend([f"[{k}] {r}" for r in b_reasons])

    cond_str = str(detection["condition"])
    cond_ok = evaluate_sigma_condition(cond_str, block_results)
    final_match = ls_ok and cond_ok

    return {
        "event_id": ev.event_id_uid,
        "role": ev.role,
        "matched": final_match,
        "logsource_ok": ls_ok,
        "condition_ok": cond_ok,
        "block_results": block_results,
        "diagnostics": diagnostics,
    }


@dataclass
class VerificationReport:
    """Comprehensive verification & scoring report answering the 3 thesis questions + Vòng A/B metrics."""

    alert_id: str
    rule_title: str
    rule_id: str
    # Question 1: Syntax & Schema (20%)
    q1_syntax_valid: bool
    q1_syntax_score: float  # 0.0 - 100.0
    q1_errors: list[str] = field(default_factory=list)
    q1_warnings: list[str] = field(default_factory=list)

    # Question 2: Data Match & Alert Linkage (30%)
    q2_data_match_valid: bool = False
    q2_data_linkage_score: float = 0.0  # 0.0 - 100.0
    q2_logsource_matched: bool = False
    q2_all_fields_present_in_event: bool = False
    q2_mitre_linked: bool = False
    q2_overfit_warnings: list[str] = field(default_factory=list)
    q2_errors: list[str] = field(default_factory=list)

    # Question 3: Behavioral Detection & Replay Vòng A + Vòng B (50%)
    q3_behavior_valid: bool = False
    q3_behavior_score: float = 0.0  # 0.0 - 100.0
    # Vòng A & B Confusion Matrix & Metrics
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    generalization_hits: int = 0
    generalization_total: int = 0
    generalization_rate: float = 0.0
    false_positive_rate: float = 0.0
    q3_errors: list[str] = field(default_factory=list)
    replay_details: list[dict[str, Any]] = field(default_factory=list)

    # Overall Score & Decision Gate
    confidence_score: float = 0.0  # 0.0 - 100.0
    quality_gate: str = "FAIL - REJECT"  # "PASS - RECOMMEND_ADD" | "WARN - NEEDS_TUNING" | "FAIL - REJECT"
    recommendation_reason: str = ""
    all_repair_issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return dictionary representation for JSON serialization."""
        return asdict(self)


def verify_and_score_sigma_rule(
    raw_yaml: str,
    bundle: NormalizedAlertBundle,
    benign_corpus: list[NormalizedEvent],
) -> VerificationReport:
    """Execute the complete 3-Question (Vòng A + Vòng B) verification and scoring pipeline."""
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        return VerificationReport(
            alert_id=bundle.alert_id,
            rule_title="YAML_PARSE_ERROR",
            rule_id="",
            q1_syntax_valid=False,
            q1_syntax_score=0.0,
            q1_errors=[f"YAML parse error: {exc}"],
            all_repair_issues=[f"[Syntax] YAML parse error: {exc}. Remember to wrap Windows paths in single quotes '...' instead of double quotes!"],
            recommendation_reason="Rule failed YAML parsing.",
        )

    if not isinstance(parsed, dict):
        return VerificationReport(
            alert_id=bundle.alert_id,
            rule_title="NOT_A_MAPPING",
            rule_id="",
            q1_syntax_valid=False,
            q1_syntax_score=0.0,
            q1_errors=["Parsed YAML is not a dictionary mapping."],
            all_repair_issues=["[Syntax] Parsed YAML is not a dictionary mapping."],
            recommendation_reason="Rule is not a YAML mapping.",
        )

    title = str(parsed.get("title") or "Untitled Rule")
    rule_id = str(parsed.get("id") or "")

    # =========================================================================
    # QUESTION 1: SYNTAX & SCHEMA VALIDATION (Weight: 20%)
    # =========================================================================
    base_val = validate_sigma_rule(parsed)
    q1_errors = list(base_val.errors)
    q1_warnings = list(base_val.warnings)

    detection = parsed.get("detection")
    selection_fields_used: list[tuple[str, str, Any]] = []

    if isinstance(detection, dict):
        cond_str = str(detection.get("condition") or "")
        defined_blocks = {k for k in detection if k not in ("condition", "timeframe")}

        for b_name in defined_blocks:
            b_val = detection[b_name]
            if isinstance(b_val, dict):
                for spec_k, exp_v in b_val.items():
                    parts = [p.strip() for p in str(spec_k).split("|") if p.strip()]
                    f_name = parts[0]
                    mods = [m.lower() for m in parts[1:]]
                    for m in mods:
                        if m not in VALID_MODIFIERS:
                            q1_errors.append(f"Invalid Sigma modifier '{m}' in '{spec_k}'")
                    if exp_v in ("", "*", ".*", None) or exp_v == []:
                        q1_errors.append(f"Overly generic/empty detection value in '{spec_k}: {exp_v}'")
                    selection_fields_used.append((b_name, f_name, exp_v))
            elif isinstance(b_val, list):
                for sub in b_val:
                    if isinstance(sub, dict):
                        for spec_k, exp_v in sub.items():
                            parts = [p.strip() for p in str(spec_k).split("|") if p.strip()]
                            selection_fields_used.append((b_name, parts[0], exp_v))

        tokens = re.findall(r"[A-Za-z0-9_*]+", cond_str)
        reserved = {"and", "or", "not", "1", "any", "all", "of", "them"}
        for tok in tokens:
            if tok.lower() in reserved:
                continue
            if "*" in tok:
                pat = tok.replace("*", ".*")
                if not any(re.fullmatch(pat, b) for b in defined_blocks):
                    q1_errors.append(f"Condition pattern '{tok}' does not match any selection block in {sorted(defined_blocks)}")
            elif tok not in defined_blocks:
                q1_errors.append(f"Condition references undefined block '{tok}' (defined: {sorted(defined_blocks)})")

    q1_valid = len(q1_errors) == 0
    if not q1_valid:
        q1_score = 0.0
    else:
        q1_score = max(60.0, 100.0 - 10.0 * len(q1_warnings))

    # =========================================================================
    # QUESTION 2: DATA MATCH & ALERT LINKAGE (Weight: 30%)
    # =========================================================================
    q2_errors: list[str] = []
    q2_overfit_warnings: list[str] = []

    primary_evs = bundle.primary_events
    logsource = parsed.get("logsource") or {}

    ls_matched_any = False
    ls_diag = ""
    if primary_evs:
        for pev in primary_evs:
            ok, msg = check_logsource_compatible(logsource, pev)
            if ok:
                ls_matched_any = True
                break
            ls_diag = msg
        if not ls_matched_any:
            exp_ls = primary_evs[0].expected_sigma_logsource
            q2_errors.append(
                f"Logsource mismatch: {ls_diag}. For this alert ({primary_evs[0].event_family} EventID {primary_evs[0].event_code}), "
                f"logsource MUST be {exp_ls}."
            )
    else:
        q2_errors.append("Alert has no usable primary events.")

    positive_fields = [
        (b_name, f_name, exp_v)
        for b_name, f_name, exp_v in selection_fields_used
        if not b_name.lower().startswith("filter")
    ]
    missing_fields_in_event: list[str] = []
    if primary_evs and positive_fields:
        for b_name, f_name, exp_v in positive_fields:
            if not any(resolve_sigma_field_value(f_name, pev) is not None for pev in primary_evs):
                avail = sorted(primary_evs[0].sigma_fields.keys())
                missing_fields_in_event.append(f_name)
                q2_errors.append(
                    f"Hallucinated/null field '{f_name}' in block '{b_name}': primary event does NOT have '{f_name}' "
                    f"(value is NULL). Available non-null fields are: {avail}."
                )
    all_fields_present = len(positive_fields) > 0 and len(missing_fields_in_event) == 0

    for _, f_name, exp_v in positive_fields:
        val_str = str(exp_v)
        for pat, desc in OVERFIT_PATTERNS:
            if pat.search(val_str):
                q2_overfit_warnings.append(f"{desc} in field '{f_name}': {val_str!r}")

    # Check if rule explicitly references a DIFFERENT alert_id in description or title
    desc_and_title = f"{parsed.get('title', '')} {parsed.get('description', '')}"
    m_alert_ref = re.search(r"\b(AI-\d{8}_\d{6}\.\d{3}-[a-f0-9]+|ALERT-\d{3})\b", desc_and_title, re.I)
    if m_alert_ref and bundle.alert_id and m_alert_ref.group(1).lower() != bundle.alert_id.lower():
        q2_errors.append(
            f"Rule <-> Evidence mismatch: Rule belongs to alert '{m_alert_ref.group(1)}' "
            f"but is being verified against alert/evidence '{bundle.alert_id}'."
        )

    tags = [str(t).lower() for t in (parsed.get("tags") or []) if t]
    rule_techs = {t.removeprefix("attack.").upper() for t in tags if t.startswith("attack.t")}
    expected_techs = {t.upper() for t in bundle.mitre_techniques if t}
    if expected_techs:
        mitre_linked = bool(rule_techs & expected_techs)
        if not mitre_linked:
            q2_overfit_warnings.append(
                f"Rule tags {sorted(rule_techs)} do not include alert's MITRE technique(s) {sorted(expected_techs)}"
            )
    else:
        mitre_linked = True

    q2_score = 0.0
    if ls_matched_any:
        q2_score += 40.0
    if all_fields_present:
        q2_score += 40.0
    elif positive_fields:
        present_ratio = (len(positive_fields) - len(missing_fields_in_event)) / len(positive_fields)
        q2_score += round(40.0 * present_ratio, 1)
    if mitre_linked:
        q2_score += 20.0
    q2_score = max(0.0, q2_score - 10.0 * len(q2_overfit_warnings))
    q2_valid = ls_matched_any and all_fields_present and len(q2_errors) == 0

    # =========================================================================
    # QUESTION 3: BEHAVIORAL DETECTION & REPLAY VÒNG A + VÒNG B (Weight: 50%)
    # =========================================================================
    q3_errors: list[str] = []
    replay_details: list[dict[str, Any]] = []

    target_primary_evs = [
        pev for pev in primary_evs if check_logsource_compatible(logsource, pev)[0]
    ] or primary_evs

    tp = 0
    fn = 0
    for pev in target_primary_evs:
        res = evaluate_sigma_rule_on_event(parsed, pev)
        replay_details.append(res)
        if res["matched"]:
            tp += 1
        else:
            fn += 1

    if tp == 0:
        q3_errors.append(
            f"Rule FAILED to match any primary target event (TP=0, FN={fn}). "
            f"Diagnostics on primary event: {'; '.join(replay_details[0]['diagnostics'] if replay_details else ['no events'])}"
        )

    gen_hits = 0
    gen_total = len(bundle.generalized_variants)
    for gev in bundle.generalized_variants:
        gres = evaluate_sigma_rule_on_event(parsed, gev)
        if gres["matched"]:
            gen_hits += 1
    gen_rate = (gen_hits / gen_total) if gen_total > 0 else 0.0
    if tp > 0 and gen_rate < 0.67:
        q3_errors.append(
            f"Rule overfits specific event values: matched primary event but only matched "
            f"{gen_hits}/{gen_total} generalized variants (Generalization Rate = {gen_rate:.0%}). "
            f"Avoid hardcoding usernames or random temp filenames."
        )

    fp = 0
    tn = 0
    for bev in benign_corpus:
        bres = evaluate_sigma_rule_on_event(parsed, bev)
        if bres["matched"]:
            fp += 1
            replay_details.append(bres)
        else:
            tn += 1

    if fp > 0:
        q3_errors.append(
            f"Rule triggered {fp} False Positive(s) on the benign background corpus (FP={fp}, TN={tn}). "
            f"Add more specific selection criteria or a filter block."
        )

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    if tp == 0:
        q3_score = 0.0
        q3_valid = False
    else:
        q3_score = round(100.0 * (0.50 * f1_score + 0.30 * gen_rate + 0.20 * (1.0 - fpr)), 1)
        q3_valid = (tp > 0) and (fp == 0) and (gen_rate >= 0.67)

    raw_weighted = round(0.20 * q1_score + 0.30 * q2_score + 0.50 * q3_score, 1)

    all_repair_issues = (
        [f"[Q1-Syntax] {e}" for e in q1_errors]
        + [f"[Q2-DataLinkage] {e}" for e in q2_errors]
        + [f"[Q2-Overfitting] {w}" for w in q2_overfit_warnings]
        + [f"[Q3-Behavior] {e}" for e in q3_errors]
    )

    if not q1_valid or tp == 0 or not q2_valid:
        confidence_score = min(raw_weighted, 45.0)
        quality_gate = "FAIL - REJECT"
        reason = (
            "Rule trượt cổng kiểm chứng bắt buộc (Hard Gate): "
            + ("; ".join(all_repair_issues[:3]) or "Không khớp sự kiện cảnh báo gốc.")
        )
    elif confidence_score_val := raw_weighted:
        confidence_score = confidence_score_val
        if confidence_score >= 80.0 and fp == 0 and gen_rate >= 0.67:
            quality_gate = "PASS - RECOMMEND_ADD"
            reason = (
                f"Đạt chuẩn triển khai Wazuh (Confidence={confidence_score:.1f}%, F1={f1_score:.2f}, "
                f"Generalization={gen_rate:.0%}, FP={fp})."
            )
        elif confidence_score >= 60.0:
            quality_gate = "WARN - NEEDS_TUNING"
            reason = (
                f"Bắt được sự kiện gốc nhưng cần tinh chỉnh (Confidence={confidence_score:.1f}%, "
                f"Generalization={gen_rate:.0%}, FP={fp}). Xem chi tiết cảnh báo."
            )
        else:
            quality_gate = "FAIL - REJECT"
            reason = f"Điểm tin cậy thấp ({confidence_score:.1f}% < 60%)."

    return VerificationReport(
        alert_id=bundle.alert_id,
        rule_title=title,
        rule_id=rule_id,
        q1_syntax_valid=q1_valid,
        q1_syntax_score=round(q1_score, 1),
        q1_errors=q1_errors,
        q1_warnings=q1_warnings,
        q2_data_match_valid=q2_valid,
        q2_data_linkage_score=round(q2_score, 1),
        q2_logsource_matched=ls_matched_any,
        q2_all_fields_present_in_event=all_fields_present,
        q2_mitre_linked=mitre_linked,
        q2_overfit_warnings=q2_overfit_warnings,
        q2_errors=q2_errors,
        q3_behavior_valid=q3_valid,
        q3_behavior_score=round(q3_score, 1),
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1_score, 4),
        generalization_hits=gen_hits,
        generalization_total=gen_total,
        generalization_rate=round(gen_rate, 4),
        false_positive_rate=round(fpr, 4),
        q3_errors=q3_errors,
        replay_details=replay_details,
        confidence_score=confidence_score,
        quality_gate=quality_gate,
        recommendation_reason=reason,
        all_repair_issues=all_repair_issues,
    )