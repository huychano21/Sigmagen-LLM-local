"""Prompt templates for Sigma rule generation and automated verification repair."""
from __future__ import annotations

from sigmagen.retrieval.retriever import RetrievalResult

SYSTEM_PROMPT = """\
You are an expert detection engineer specializing in Sigma detection rules for \
Active Directory / Windows / Sysmon telemetry and the MITRE ATT&CK framework.

Your task is to generate a production-ready Sigma YAML detection rule that \
passes automated 3-stage verification (Syntax, Telemetry Field Grounding, and \
Behavioral Event Replay) and compiles cleanly into a Wazuh Sysmon XML rule.

Every rule you produce MUST include ALL of the following fields:

  title        — concise, descriptive, starts with a verb or noun
  id           — a freshly generated UUID v4
  status       — experimental
  description  — 2-4 sentences explaining what the rule detects and why it matters
  references   — list with at least one URL (e.g. https://attack.mitre.org/techniques/TXXXX/)
  author       — "SigmaGen"
  date         — today's date in YYYY-MM-DD format
  tags         — list including ONLY canonical MITRE ATT&CK technique tags
                 supported by the input context (e.g. attack.t1105, attack.t1059.001).
                 NEVER include tactic names (like attack.execution or attack.discovery).
  logsource    — MUST match the exact telemetry event type in the user request:
                   Sysmon EventID 1  -> product: windows, category: process_creation
                   Sysmon EventID 3  -> product: windows, category: network_connection
                   Sysmon EventID 11 -> product: windows, category: file_event
                   Sysmon EventID 13 -> product: windows, category: registry_set
  detection    — MUST contain:
                   - Named selection block(s) (`selection`) using ONLY non-null Sigma fields
                     explicitly present in the supplied telemetry (`Image`, `ParentImage`,
                     `CommandLine`, `TargetFilename`, `TargetObject`, `Details`).
                   - NEVER use a field that is NULL or absent in the supplied telemetry!
                     (For example, if the event is Sysmon EventID 11 `file_event` and
                     `CommandLine` is NULL, NEVER use `CommandLine` in `detection`—use
                     `Image` and `TargetFilename` instead.)
                   - ALWAYS use Sigma modifiers (`|endswith` or `|contains`) on string fields:
                     * Match executables with `Image|endswith: '\\powershell.exe'` (and `ParentImage|endswith` if present)
                     * Match file paths with `TargetFilename|contains: '\\AppData\\Local\\Temp\\__PSScriptPolicyTest_'` and `TargetFilename|endswith: '.ps1'`
                     * Match registry paths with `TargetObject|contains: 'DisableRealtimeMonitoring'` and `Details|contains: '0x00000001'`
                     * Match command lines with `CommandLine|contains|all:` using individual invariant tokens (e.g. `['query', 'Services\\Disk\\Enum']`), NOT full raw strings with multiple spaces.
                   - YAML QUOTING RULE FOR WINDOWS PATHS:
                     Always wrap Windows paths in SINGLE QUOTES (`'\\powershell.exe'`, `'\\AppData\\Local\\Temp\\'`)
                     or leave them unquoted. NEVER use double quotes (`"..."`) around single backslashes
                     like `"C:\\Users\\..."` because `\\U` and `\\T` are invalid YAML escape sequences!
                   - A `condition` key referencing the selection(s).
  falsepositives — list with at least one entry (e.g. "Legitimate administrative script execution")
  level        — one of: informational, low, medium, high, critical

OUTPUT FORMAT:
- Output ONLY valid Sigma YAML — no markdown code fences, no explanations before or after.
- Ensure proper YAML indentation (2 spaces).\
"""


def build_generation_prompt(retrieval_result: RetrievalResult, user_input: str) -> str:
    """Build the user-turn prompt from retrieval context and user input."""
    sections: list[str] = []

    sections.append(f"## User / Alert Telemetry Request\n{user_input}")

    if retrieval_result.techniques:
        sections.append("## ATT&CK Technique Context")
        for rt in retrieval_result.techniques[:3]:
            t = rt.technique
            block = [f"**{t.technique_id} — {t.name}** (relevance: {rt.score:.2f})"]
            if t.tactics:
                block.append(f"  Tactics: {', '.join(t.tactics)}")
            if t.platforms:
                block.append(f"  Platforms: {', '.join(t.platforms)}")
            if t.data_sources:
                block.append(f"  Data Sources: {', '.join(t.data_sources)}")
            if t.detection:
                det_text = t.detection[:800]
                block.append(f"  Detection Guidance:\n    {det_text}")
            sections.append("\n".join(block))

    if retrieval_result.sigma_rules:
        sections.append("## Existing Sigma Rule Examples (for style and structure reference)")
        for rr in retrieval_result.sigma_rules[:3]:
            r = rr.rule
            example_parts = [f"### {r.title} (relevance: {rr.score:.2f})"]
            if r.raw_yaml:
                yaml_preview = r.raw_yaml[:1500]
                example_parts.append(yaml_preview)
            else:
                example_parts.append(f"  Level: {r.level}")
                example_parts.append(f"  Logsource: {r.logsource}")
                if r.technique_ids:
                    example_parts.append(f"  Techniques: {', '.join(r.technique_ids)}")
            sections.append("\n".join(example_parts))

    sections.append(
        "## Instructions\n"
        "Generate exactly ONE Sigma detection rule for the request above.\n"
        "- The generated rule must directly detect the primary suspicious behavior in the telemetry.\n"
        "- Use ONLY fields listed in PRIMARY_TELEMETRY_FIELDS (never invent fields that are NULL).\n"
        "- Always use single quotes `'...'` for Windows paths with backslashes so YAML parsing succeeds.\n"
        "- Always use `|endswith` or `|contains` modifiers on `Image`, `ParentImage`, `CommandLine`, `TargetFilename`, `TargetObject`, and `Details`.\n"
        "- Generalize paths/arguments so the rule catches mutated variants without triggering false positives.\n"
        "- Output ONLY valid Sigma YAML."
    )

    return "\n\n".join(sections)


def build_repair_prompt(
    original_user_prompt: str,
    previous_yaml: str,
    repair_issues: list[str],
) -> str:
    """Build a repair prompt when the verification engine rejects or flags a candidate Sigma rule."""
    issues_bullet = "\n".join(f"- {iss}" for iss in repair_issues)
    return (
        f"## REPAIR MODE — PREVIOUS SIGMA RULE FAILED AUTOMATED VERIFICATION\n"
        f"Your previous candidate Sigma rule failed the verification pipeline with the following errors:\n"
        f"{issues_bullet}\n\n"
        f"### Previous Candidate Sigma YAML:\n"
        f"{previous_yaml}\n\n"
        f"### Original Alert Telemetry & Context:\n"
        f"{original_user_prompt}\n\n"
        f"### Repair Instructions:\n"
        f"1. Fix ALL listed verification errors above.\n"
        f"2. If YAML parsing failed due to backslash escape (`\\U`, `\\T`, etc.), wrap all Windows paths in SINGLE QUOTES `'...'` instead of double quotes `\"...\"`.\n"
        f"3. Remove any field from `detection` that is NULL/absent in `PRIMARY_TELEMETRY_FIELDS`.\n"
        f"4. Ensure `logsource` matches the exact `Required Sigma logsource` specified in the telemetry.\n"
        f"5. Use `|endswith` or `|contains` on string fields, and replace any hardcoded username or random filename suffix with invariant substrings.\n"
        f"6. Output ONLY the corrected Sigma YAML mapping (no markdown fences, no prose)."
    )
