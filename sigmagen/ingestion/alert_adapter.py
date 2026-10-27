"""Alert & Telemetry Adapter for SigmaGen.

Unifies ALL alert/telemetry schemas and cardinalities (Single-Alert AND Multi-Alert):
1. LogDeep Batch Schema v1 (`ai_alerts_test.json` + `ai_alert_evidence_test.json` with `{"alerts": [...]}`)
2. LogDeep Nested Schema v2 (`ALERT-001..122.json` + `ALERT-001..122_evidence.json`, either single object `{...}`
   or JSON array `[{...}, {...}]` or `{"alerts": [...]}`)
3. Wazuh/ML Archive Schema (`LLM_API` `ALERT-001..005.json` + `*_evidence.json`, either single object or array)

Strict Alert <-> Evidence Correspondence Verification:
- Validates `alert_id` and `evidence_id` at the top of each Alert and Evidence file.
- Rejects mismatched Alert and Evidence files immediately with a detailed error message so rules are never
  synthesized from mismatched telemetry.
"""
from __future__ import annotations

import copy
import html
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Mapping from Sysmon / Windows event family + EventID to Sigma logsource and Wazuh group
SYSMON_EVENT_MAP: dict[int, dict[str, str]] = {
    1: {
        "sigma_category": "process_creation",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event1",
        "description": "Sysmon EventID 1 (Process Creation)",
    },
    3: {
        "sigma_category": "network_connection",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event3",
        "description": "Sysmon EventID 3 (Network Connection)",
    },
    7: {
        "sigma_category": "image_load",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event7",
        "description": "Sysmon EventID 7 (Image Loaded)",
    },
    8: {
        "sigma_category": "create_remote_thread",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event8",
        "description": "Sysmon EventID 8 (CreateRemoteThread)",
    },
    10: {
        "sigma_category": "process_access",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event10",
        "description": "Sysmon EventID 10 (ProcessAccess)",
    },
    11: {
        "sigma_category": "file_event",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event_11",
        "description": "Sysmon EventID 11 (FileCreate)",
    },
    12: {
        "sigma_category": "registry_event",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event_12",
        "description": "Sysmon EventID 12 (RegistryEvent Create/Delete)",
    },
    13: {
        "sigma_category": "registry_set",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event_13",
        "description": "Sysmon EventID 13 (RegistryEvent Value Set)",
    },
    15: {
        "sigma_category": "file_event",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event_15",
        "description": "Sysmon EventID 15 (FileCreateStreamHash)",
    },
    22: {
        "sigma_category": "dns_query",
        "sigma_product": "windows",
        "wazuh_group": "sysmon_event_22",
        "description": "Sysmon EventID 22 (DNSEvent)",
    },
}

WINDOWS_EVENT_MAP: dict[int, dict[str, str]] = {
    4624: {
        "sigma_service": "security",
        "sigma_product": "windows",
        "wazuh_group": "authentication_success",
        "description": "Windows Security EventID 4624 (Logon Success)",
    },
    4688: {
        "sigma_category": "process_creation",
        "sigma_product": "windows",
        "sigma_service": "security",
        "wazuh_group": "windows_security",
        "description": "Windows Security EventID 4688 (Process Creation)",
    },
    7031: {
        "sigma_service": "system",
        "sigma_product": "windows",
        "wazuh_group": "windows",
        "description": "Windows System Service Control Manager EventID 7031 (Service Crashed)",
    },
    7036: {
        "sigma_service": "system",
        "sigma_product": "windows",
        "wazuh_group": "windows",
        "description": "Windows System Service Control Manager EventID 7036 (Service State Change)",
    },
    7040: {
        "sigma_service": "system",
        "sigma_product": "windows",
        "wazuh_group": "windows",
        "description": "Windows System Service Control Manager EventID 7040 (Start Type Changed)",
    },
}

# Mapping between snake_case (LogDeep), camelCase (Wazuh eventdata), and PascalCase (Sigma standard)
FIELD_ALIASES: dict[str, tuple[str, str]] = {
    "image": ("Image", "win.eventdata.image"),
    "parent_image": ("ParentImage", "win.eventdata.parentImage"),
    "parentimage": ("ParentImage", "win.eventdata.parentImage"),
    "command_line": ("CommandLine", "win.eventdata.commandLine"),
    "commandline": ("CommandLine", "win.eventdata.commandLine"),
    "processcommandline": ("CommandLine", "win.eventdata.commandLine"),
    "parent_command_line": ("ParentCommandLine", "win.eventdata.parentCommandLine"),
    "parentcommandline": ("ParentCommandLine", "win.eventdata.parentCommandLine"),
    "target_filename": ("TargetFilename", "win.eventdata.targetFilename"),
    "targetfilename": ("TargetFilename", "win.eventdata.targetFilename"),
    "target_object": ("TargetObject", "win.eventdata.targetObject"),
    "targetobject": ("TargetObject", "win.eventdata.targetObject"),
    "details": ("Details", "win.eventdata.details"),
    "original_file_name": ("OriginalFileName", "win.eventdata.originalFileName"),
    "originalfilename": ("OriginalFileName", "win.eventdata.originalFileName"),
    "current_directory": ("CurrentDirectory", "win.eventdata.currentDirectory"),
    "currentdirectory": ("CurrentDirectory", "win.eventdata.currentDirectory"),
    "integrity_level": ("IntegrityLevel", "win.eventdata.integrityLevel"),
    "integritylevel": ("IntegrityLevel", "win.eventdata.integrityLevel"),
    "user": ("User", "win.eventdata.user"),
    "parent_user": ("ParentUser", "win.eventdata.parentUser"),
    "parentuser": ("ParentUser", "win.eventdata.parentUser"),
    "destination_ip": ("DestinationIp", "win.eventdata.destinationIp"),
    "destinationip": ("DestinationIp", "win.eventdata.destinationIp"),
    "destination_port": ("DestinationPort", "win.eventdata.destinationPort"),
    "destinationport": ("DestinationPort", "win.eventdata.destinationPort"),
    "source_ip": ("SourceIp", "win.eventdata.sourceIp"),
    "sourceip": ("SourceIp", "win.eventdata.sourceIp"),
    "source_port": ("SourcePort", "win.eventdata.sourcePort"),
    "sourceport": ("SourcePort", "win.eventdata.sourcePort"),
    "event_type": ("EventType", "win.eventdata.eventType"),
    "eventtype": ("EventType", "win.eventdata.eventType"),
    "rule_name": ("RuleName", "win.eventdata.ruleName"),
    "rulename": ("RuleName", "win.eventdata.ruleName"),
    "hashes": ("Hashes", "win.eventdata.hashes"),
    "company": ("Company", "win.eventdata.company"),
    "description": ("Description", "win.eventdata.description"),
    "product": ("Product", "win.eventdata.product"),
    "query_name": ("QueryName", "win.eventdata.queryName"),
    "queryname": ("QueryName", "win.eventdata.queryName"),
    "query_status": ("QueryStatus", "win.eventdata.queryStatus"),
    "querystatus": ("QueryStatus", "win.eventdata.queryStatus"),
    "query_results": ("QueryResults", "win.eventdata.queryResults"),
    "queryresults": ("QueryResults", "win.eventdata.queryResults"),
}


def clean_windows_string(value: Any) -> str:
    """Normalize double-escaped backslashes and HTML entities from Wazuh/LogDeep JSON."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    s = html.unescape(str(value).strip())
    s = re.sub(r"\\{2,}", r"\\", s)
    if s.startswith('\\"') and s.endswith('\\"'):
        s = '"' + s[2:-2] + '"'
    return s


def parse_json_list_str(raw: Any) -> list[str]:
    """Parse fields like '[\"T1105\"]' or ['T1105'] into a clean list of strings."""
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                pass
        return [s] if s else []
    return []


def infer_mitre_from_telemetry(
    event_code: int | None,
    sigma_fields: dict[str, str],
    token: str = "",
) -> tuple[list[str], list[str]]:
    """Infer canonical MITRE ATT&CK Technique IDs and Tactics when Wazuh context has no MITRE tags.

    Ensures LogDeep sequence anomaly alerts (such as in `backfill.zip`) always carry valid
    ATT&CK technique tags (`attack.tXXXX`) grounded in their actual Sysmon telemetry.
    """
    techs: list[str] = []
    tactics: list[str] = []

    # 1. Check if RuleName, CommandLine, TargetFilename, or TargetObject explicitly mentions a Technique ID
    combined_text = " ".join(
        str(sigma_fields.get(k, ""))
        for k in ("RuleName", "CommandLine", "ParentCommandLine", "TargetFilename", "TargetObject")
    )
    for m in re.finditer(r"\b(T\d{4}(?:\.\d{3})?)\b", combined_text, flags=re.I):
        tid = m.group(1).upper()
        # Map deprecated T1089 (Disabling Security Tools) to modern T1562.001
        if tid == "T1089":
            tid = "T1562.001"
        if tid not in techs:
            techs.append(tid)

    img = sigma_fields.get("Image", "").lower()
    pimg = sigma_fields.get("ParentImage", "").lower()
    cmd = sigma_fields.get("CommandLine", "").lower()
    tf = sigma_fields.get("TargetFilename", "").lower()
    tobj = sigma_fields.get("TargetObject", "").lower()

    if event_code == 11:
        if ".ps1" in tf or "powershell" in img:
            for t in ("T1059.001", "T1105"):
                if t not in techs:
                    techs.append(t)
            tactics.extend(["Execution", "Command and Control"])
        else:
            if "T1105" not in techs:
                techs.append("T1105")
            tactics.append("Command and Control")
    elif event_code in (12, 13):
        if "disablerealtimemonitoring" in tobj or "windows defender" in tobj:
            for t in ("T1562.001", "T1112"):
                if t not in techs:
                    techs.append(t)
            tactics.append("Defense Evasion")
        elif "\\currentversion\\run" in tobj:
            for t in ("T1547.001", "T1112"):
                if t not in techs:
                    techs.append(t)
            tactics.extend(["Persistence", "Defense Evasion"])
        else:
            if "T1112" not in techs:
                techs.append("T1112")
            tactics.append("Defense Evasion")
    elif event_code == 22:
        if "T1071.004" not in techs:
            techs.append("T1071.004")
        tactics.append("Command and Control")
    elif event_code == 3:
        if "T1071" not in techs:
            techs.append("T1071")
        tactics.append("Command and Control")
    elif event_code in (7031, 7036, 7040):
        if "T1489" not in techs:
            techs.append("T1489")
        tactics.append("Impact")
    else:
        # EventID 1 (Process Creation) and general Windows events
        if img.endswith("\\whoami.exe"):
            techs.append("T1033")
            tactics.append("Discovery")
        elif img.endswith(("\\hostname.exe", "\\systeminfo.exe", "\\trustedinstaller.exe", "\\lpremove.exe")):
            techs.append("T1082")
            tactics.append("Discovery")
        elif img.endswith("\\reg.exe"):
            if "query" in cmd:
                techs.append("T1012")
                tactics.append("Discovery")
            else:
                techs.append("T1112")
                tactics.append("Defense Evasion")
        elif img.endswith(("\\netsh.exe", "\\ipconfig.exe", "\\arp.exe", "\\nbtstat.exe")):
            techs.append("T1016")
            tactics.append("Discovery")
        elif img.endswith("\\netstat.exe"):
            techs.append("T1049")
            tactics.append("Discovery")
        elif img.endswith("\\tasklist.exe"):
            techs.append("T1057")
            tactics.append("Discovery")
        elif img.endswith("\\sc.exe"):
            techs.append("T1007")
            tactics.append("Discovery")
        elif img.endswith("\\tree.com"):
            techs.append("T1083")
            tactics.append("Discovery")
        elif img.endswith("\\w32tm.exe"):
            techs.append("T1124")
            tactics.append("Discovery")
        elif img.endswith("\\rundll32.exe"):
            techs.append("T1218.011")
            tactics.append("Defense Evasion")
        elif img.endswith("\\mpcmdrun.exe"):
            techs.append("T1562.001")
            tactics.append("Defense Evasion")
        elif img.endswith(("\\net.exe", "\\net1.exe")):
            if "view" in cmd:
                techs.append("T1135")
            elif "time" in cmd:
                techs.append("T1124")
            elif "use" in cmd or "session" in cmd:
                techs.append("T1049")
            else:
                techs.append("T1082")
            tactics.append("Discovery")
        elif img.endswith("\\powershell.exe"):
            techs.append("T1059.001")
            tactics.append("Execution")
        elif img.endswith("\\cmd.exe"):
            techs.append("T1059.003")
            tactics.append("Execution")
        elif img.endswith(("\\logonui.exe", "\\taskhostw.exe")):
            techs.append("T1082")
            tactics.append("Discovery")

        if pimg.endswith("\\powershell.exe") and "T1059.001" not in techs:
            techs.append("T1059.001")
            if "Execution" not in tactics:
                tactics.append("Execution")
        elif pimg.endswith("\\cmd.exe") and "T1059.003" not in techs:
            techs.append("T1059.003")
            if "Execution" not in tactics:
                tactics.append("Execution")

    if not techs:
        techs = ["T1059"]
    if not tactics:
        tactics = ["Execution"]

    # Deduplicate preserving order
    dedup_techs = list(dict.fromkeys(techs))
    dedup_tactics = list(dict.fromkeys(tactics))
    return dedup_techs, dedup_tactics


def extract_nested_logdeep_fields(raw_ev: dict[str, Any]) -> dict[str, str]:
    """Extract flat snake_case fields from LogDeep v2 nested objects (`process`, `parent_process`, `file`, `network`, `event_data`)."""
    extracted: dict[str, str] = {}

    ed = raw_ev.get("event_data")
    if isinstance(ed, dict):
        for k, v in ed.items():
            if v is not None and v != "" and not isinstance(v, (dict, list)):
                extracted[k] = str(v)

    proc = raw_ev.get("process")
    if isinstance(proc, dict):
        for k in ("image", "command_line", "current_directory", "integrity_level", "original_file_name", "description", "product", "company"):
            if proc.get(k):
                extracted[k] = str(proc[k])
        hashes = proc.get("hashes")
        if isinstance(hashes, dict) and hashes:
            h_parts = [f"{hk.upper()}={hv}" for hk, hv in hashes.items() if hv]
            if h_parts:
                extracted["hashes"] = ",".join(h_parts)

    pproc = raw_ev.get("parent_process")
    if isinstance(pproc, dict):
        if pproc.get("image"):
            extracted["parent_image"] = str(pproc["image"])
        if pproc.get("command_line"):
            extracted["parent_command_line"] = str(pproc["command_line"])
        if pproc.get("user"):
            extracted["parent_user"] = str(pproc["user"])

    fobj = raw_ev.get("file")
    if isinstance(fobj, dict):
        for k in ("target_filename", "target_object", "details"):
            if fobj.get(k):
                extracted[k] = str(fobj[k])

    nobj = raw_ev.get("network")
    if isinstance(nobj, dict):
        for k in ("source_ip", "source_port", "destination_ip", "destination_port", "protocol", "query_name", "query_status", "query_results"):
            if nobj.get(k) not in (None, ""):
                extracted[k] = str(nobj[k])

    for k, v in raw_ev.items():
        if k in ("process", "parent_process", "file", "network", "event_data", "system_data", "source_metadata", "raw_event", "top_predictions", "wazuh_context", "mitre_context"):
            continue
        if k == "event_type" and str(v) in ("process_create", "file_create", "network_connect", "dns_query", "registry_object", "registry_value"):
            continue
        if v is not None and v != "" and not isinstance(v, (dict, list)):
            extracted.setdefault(k, str(v))

    return extracted


@dataclass
class NormalizedEvent:
    """A single normalized telemetry event ready for Sigma evaluation and prompt building."""

    event_id_uid: str
    role: str  # "primary" | "context" | "benign"
    event_family: str  # "sysmon" | "windows_security" | "service_control" | "ossec"
    event_code: int | None
    channel: str = ""
    provider: str = ""
    timestamp: str = ""
    host: str = ""
    sigma_fields: dict[str, str] = field(default_factory=dict)  # PascalCase -> clean string
    wazuh_fields: dict[str, str] = field(default_factory=dict)  # win.eventdata.* -> clean string
    wazuh_rule_id: str | None = None
    wazuh_rule_desc: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)

    @property
    def expected_sigma_logsource(self) -> dict[str, str]:
        """Return the expected Sigma logsource for this event."""
        if self.event_family == "sysmon" and self.event_code in SYSMON_EVENT_MAP:
            info = SYSMON_EVENT_MAP[self.event_code]
            return {"product": info["sigma_product"], "category": info["sigma_category"]}
        if self.event_code in WINDOWS_EVENT_MAP:
            info = WINDOWS_EVENT_MAP[self.event_code]
            out = {"product": info["sigma_product"]}
            if "sigma_category" in info:
                out["category"] = info["sigma_category"]
            if "sigma_service" in info:
                out["service"] = info["sigma_service"]
            return out
        return {"product": "windows"}

    @property
    def expected_wazuh_group(self) -> str:
        """Return the expected Wazuh parent <if_group> for this event."""
        if self.event_family == "sysmon" and self.event_code in SYSMON_EVENT_MAP:
            return SYSMON_EVENT_MAP[self.event_code]["wazuh_group"]
        if self.event_code in WINDOWS_EVENT_MAP:
            return WINDOWS_EVENT_MAP[self.event_code]["wazuh_group"]
        return "windows"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["expected_sigma_logsource"] = self.expected_sigma_logsource
        d["expected_wazuh_group"] = self.expected_wazuh_group
        return d


@dataclass
class NormalizedAlertBundle:
    """Complete normalized alert + evidence bundle from either LogDeep (v1/v2) or Wazuh ML."""

    alert_id: str
    source_format: str  # "logdeep" | "logdeep_v2" | "wazuh_ml"
    title: str
    description: str
    severity: str
    anomaly_score: float | None
    host: str
    timestamp: str
    evidence_id: str = ""
    observed_token: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    wazuh_rule_id: str | None = None
    wazuh_rule_description: str | None = None
    primary_events: list[NormalizedEvent] = field(default_factory=list)
    context_events: list[NormalizedEvent] = field(default_factory=list)
    generalized_variants: list[NormalizedEvent] = field(default_factory=list)
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "evidence_id": self.evidence_id,
            "source_format": self.source_format,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "host": self.host,
            "timestamp": self.timestamp,
            "observed_token": self.observed_token,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "wazuh_rule_id": self.wazuh_rule_id,
            "wazuh_rule_description": self.wazuh_rule_description,
            "primary_events": [e.to_dict() for e in self.primary_events],
            "context_events": [e.to_dict() for e in self.context_events],
            "generalized_variants_count": len(self.generalized_variants),
        }

    def build_llm_prompt_input(self) -> str:
        """Build a clean, structured telemetry text input for SigmaGenGenerator."""
        lines: list[str] = []
        primary = self.primary_events[0] if self.primary_events else None

        lines.append(f"ALERT_ID: {self.alert_id}")
        if self.evidence_id:
            lines.append(f"EVIDENCE_ID: {self.evidence_id}")
        lines.append(f"BEHAVIOR_SUMMARY: {self.title} - {self.description}")
        if self.mitre_techniques:
            lines.append(f"SUPPORTED_MITRE_TECHNIQUES: {', '.join(self.mitre_techniques)}")
        if primary:
            ls = primary.expected_sigma_logsource
            ls_str = ", ".join(f"{k}: {v}" for k, v in ls.items())
            lines.append(
                f"PRIMARY_EVENT_TYPE: {primary.event_family} EventID {primary.event_code} "
                f"-> Required Sigma logsource: {{{ls_str}}} | Wazuh group: {primary.expected_wazuh_group}"
            )
            lines.append("PRIMARY_TELEMETRY_FIELDS (Sigma PascalCase -> Wazuh field):")
            for s_key, s_val in primary.sigma_fields.items():
                w_key = next(
                    (wk for _, (sk, wk) in FIELD_ALIASES.items() if sk == s_key),
                    f"win.eventdata.{s_key[0].lower() + s_key[1:]}",
                )
                lines.append(f"  - {s_key} ({w_key}): {s_val}")

        if len(self.primary_events) > 1:
            lines.append(f"\nADDITIONAL_PRIMARY_EVENTS ({len(self.primary_events)} total primary events):")
            seen_sigs: set[str] = set()
            for ev in self.primary_events[:6]:
                sig = f"EID={ev.event_code} " + " ".join(f"{k}={v}" for k, v in ev.sigma_fields.items())
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    lines.append(f"  * [{ev.event_id_uid}] {sig}")

        lines.append("\nSTRICT DETECTION & GENERALIZATION RULES:")
        if primary:
            avail_keys = [k for k in primary.sigma_fields.keys() if k not in ("Channel", "EventID", "Company", "Product", "Description")]
            lines.append(
                f"1. ONLY use fields from this list: {avail_keys}. "
                f"All other fields (such as {', '.join(k for k in ('CommandLine', 'ParentImage', 'ParentCommandLine', 'TargetFilename', 'TargetObject', 'QueryName') if k not in avail_keys)}) "
                f"are NULL in this event and MUST NOT be used in `detection`!"
            )
            ls = primary.expected_sigma_logsource
            lines.append(f"2. Set `logsource:` to exactly: {json.dumps(ls)}")

            tf = primary.sigma_fields.get("TargetFilename", "")
            cmd = primary.sigma_fields.get("CommandLine", "")
            pcmd = primary.sigma_fields.get("ParentCommandLine", "")
            tobj = primary.sigma_fields.get("TargetObject", "")
            qname = primary.sigma_fields.get("QueryName", "")

            if "__PSScriptPolicyTest_" in tf:
                lines.append(
                    "3. GENERALIZATION HINT: The filename contains a random suffix after `__PSScriptPolicyTest_` "
                    "and a specific username. Do NOT hardcode the random suffix or username. "
                    "Use `Image|endswith: '\\powershell.exe'` and `TargetFilename|contains: '\\AppData\\Local\\Temp\\__PSScriptPolicyTest_'` "
                    "and `TargetFilename|endswith: '.ps1'`."
                )
            elif tf:
                lines.append(
                    "3. GENERALIZATION HINT: Match process `Image|endswith` on the executable basename "
                    "and `TargetFilename|endswith` or `TargetFilename|contains` on the invariant folder/filename."
                )
            elif cmd or pcmd:
                lines.append(
                    "3. GENERALIZATION HINT: Match `Image|endswith` (and `ParentImage|endswith` if present) "
                    "using the executable basename (e.g. `'\\systeminfo.exe'`, `'\\cmd.exe'`, `'\\powershell.exe'`, `'\\reg.exe'`, `'\\netsh.exe'`), "
                    "and match key invariant arguments in `CommandLine|contains` or `ParentCommandLine|contains`."
                )
            elif tobj:
                lines.append(
                    "3. GENERALIZATION HINT: For Registry events (Sysmon EventID 12/13), match `TargetObject|contains` "
                    "on the meaningful registry key path and `Details|contains` or `Image|endswith`."
                )
            elif qname:
                lines.append(
                    "3. GENERALIZATION HINT: For DNS Query events (Sysmon EventID 22), match `Image|endswith` "
                    "and `QueryName|contains` on the queried domain/hostname."
                )

        if self.context_events:
            lines.append(f"\nSLIDING_WINDOW_CONTEXT_EVENTS ({len(self.context_events)} surrounding events, DO NOT match benign context):")
            for cev in self.context_events[:5]:
                c_summary = ", ".join(f"{k}={v}" for k, v in list(cev.sigma_fields.items())[:3])
                lines.append(
                    f"  - [{cev.event_id_uid}] {cev.event_family} EventID={cev.event_code} ({c_summary})"
                )

        return "\n".join(lines)


def normalize_logdeep_event(raw_ev: dict[str, Any], role: str = "primary") -> NormalizedEvent:
    """Normalize a LogDeep event (supports both flat v1 and nested v2 `process`/`parent_process`/`event_data` schemas)."""
    uid = str(raw_ev.get("event_uid") or raw_ev.get("event_id") or "ev-unknown")
    sys_d = raw_ev.get("system_data") if isinstance(raw_ev.get("system_data"), dict) else {}
    src_meta = raw_ev.get("source_metadata") if isinstance(raw_ev.get("source_metadata"), dict) else {}

    channel = str(raw_ev.get("channel") or sys_d.get("channel") or "")
    provider = str(raw_ev.get("provider") or sys_d.get("provider_name") or "")
    ts = str(raw_ev.get("timestamp") or sys_d.get("system_time") or "")
    host = str(raw_ev.get("host") or sys_d.get("computer") or "")

    ecode_raw = raw_ev.get("event_code") if raw_ev.get("event_code") is not None else (
        raw_ev.get("event_id") if isinstance(raw_ev.get("event_id"), int) or str(raw_ev.get("event_id", "")).isdigit()
        else sys_d.get("event_id")
    )
    ecode = int(ecode_raw) if ecode_raw is not None and str(ecode_raw).isdigit() else None

    efam = str(raw_ev.get("event_family") or "")
    if not efam:
        if "sysmon" in provider.lower() or "sysmon" in channel.lower() or str(uid).startswith("sysmon:"):
            efam = "sysmon"
        elif channel.lower() == "security" or (ecode and ecode in (4624, 4625, 4688)):
            efam = "windows_security"
        elif channel.lower() == "system" or (ecode and ecode in (7031, 7036, 7040)):
            efam = "service_control"
        else:
            efam = "sysmon"

    sigma_fields: dict[str, str] = {}
    wazuh_fields: dict[str, str] = {}

    flat_candidates = extract_nested_logdeep_fields(raw_ev)
    for k_raw, v_raw in flat_candidates.items():
        k_low = k_raw.lower()
        if k_low in FIELD_ALIASES:
            s_key, w_key = FIELD_ALIASES[k_low]
            cleaned = clean_windows_string(v_raw)
            if cleaned:
                sigma_fields[s_key] = cleaned
                wazuh_fields[w_key] = cleaned

    raw_json_str = raw_ev.get("raw_event")
    if isinstance(raw_json_str, str) and raw_json_str.strip().startswith("{"):
        try:
            parsed_raw = json.loads(raw_json_str)
            win_obj = parsed_raw.get("win") if isinstance(parsed_raw, dict) else None
            if not win_obj and isinstance(parsed_raw, dict) and "data" in parsed_raw:
                win_obj = parsed_raw["data"].get("win")
            if isinstance(win_obj, dict):
                ev_data = win_obj.get("eventdata") or {}
                if isinstance(ev_data, dict):
                    for ek, ev_val in ev_data.items():
                        cleaned = clean_windows_string(ev_val)
                        if not cleaned:
                            continue
                        ek_low = ek.lower()
                        if ek_low in FIELD_ALIASES:
                            s_key, w_key = FIELD_ALIASES[ek_low]
                        else:
                            s_key = ek[0].upper() + ek[1:]
                            w_key = f"win.eventdata.{ek}"
                        sigma_fields.setdefault(s_key, cleaned)
                        wazuh_fields.setdefault(w_key, cleaned)
        except Exception:
            pass

    if ecode is not None:
        sigma_fields["EventID"] = str(ecode)
        wazuh_fields["win.system.eventID"] = str(ecode)
    if channel:
        sigma_fields["Channel"] = channel
        wazuh_fields["win.system.channel"] = channel

    w_rule = src_meta.get("wazuh_rule") if isinstance(src_meta.get("wazuh_rule"), dict) else {}
    w_mitre = w_rule.get("mitre") if isinstance(w_rule.get("mitre"), dict) else {}

    w_rule_id = str(raw_ev.get("wazuh_rule_id") or w_rule.get("id") or "") or None
    w_rule_desc = str(raw_ev.get("wazuh_rule_desc") or w_rule.get("description") or "") or None
    mitre_techs = parse_json_list_str(raw_ev.get("mitre_techniques") or w_mitre.get("id") or w_mitre.get("technique"))
    mitre_tacs = parse_json_list_str(raw_ev.get("mitre_tactics") or w_mitre.get("tactic"))

    return NormalizedEvent(
        event_id_uid=uid,
        role=role,
        event_family=efam,
        event_code=ecode,
        channel=channel,
        provider=provider,
        timestamp=ts,
        host=host,
        sigma_fields=sigma_fields,
        wazuh_fields=wazuh_fields,
        wazuh_rule_id=w_rule_id,
        wazuh_rule_desc=w_rule_desc,
        mitre_techniques=mitre_techs,
        mitre_tactics=mitre_tacs,
    )


def normalize_wazuh_archive_event(raw_ev: dict[str, Any], default_role: str = "primary", idx: int = 0) -> NormalizedEvent:
    """Normalize a full Wazuh archive/alert JSON record (from `ALERT-xxx_evidence.json` or `ossec-alerts-29.json`)."""
    ev_meta = raw_ev.get("_evidence", {}) if isinstance(raw_ev.get("_evidence"), dict) else {}
    role = str(ev_meta.get("role") or default_role)

    agent = raw_ev.get("agent", {}) if isinstance(raw_ev.get("agent"), dict) else {}
    rule = raw_ev.get("rule", {}) if isinstance(raw_ev.get("rule"), dict) else {}
    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    data = raw_ev.get("data", {}) if isinstance(raw_ev.get("data"), dict) else {}
    win = data.get("win", {}) if isinstance(data.get("win"), dict) else {}
    system = win.get("system", {}) if isinstance(win.get("system"), dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win.get("eventdata"), dict) else {}

    uid = str(raw_ev.get("id") or f"wazuh-ev-{idx}")
    ts = str(raw_ev.get("timestamp") or system.get("systemTime") or "")
    host = str(system.get("computer") or agent.get("name") or "")
    channel = str(system.get("channel") or raw_ev.get("location") or "")
    provider = str(system.get("providerName") or "")

    ecode_str = str(system.get("eventID") or "")
    ecode = int(ecode_str) if ecode_str.isdigit() else None

    if "sysmon" in provider.lower() or "sysmon" in channel.lower():
        efam = "sysmon"
    elif channel.lower() == "security":
        efam = "windows_security"
    elif channel.lower() == "system":
        efam = "service_control"
    else:
        efam = "ossec"

    sigma_fields: dict[str, str] = {}
    wazuh_fields: dict[str, str] = {}

    for k, v in eventdata.items():
        cleaned = clean_windows_string(v)
        if not cleaned:
            continue
        k_low = k.lower()
        if k_low in FIELD_ALIASES:
            s_key, w_key = FIELD_ALIASES[k_low]
        else:
            s_key = k[0].upper() + k[1:]
            w_key = f"win.eventdata.{k}"
        sigma_fields[s_key] = cleaned
        wazuh_fields[w_key] = cleaned

    if ecode is not None:
        sigma_fields["EventID"] = str(ecode)
        wazuh_fields["win.system.eventID"] = str(ecode)
    if channel:
        sigma_fields["Channel"] = channel
        wazuh_fields["win.system.channel"] = channel

    return NormalizedEvent(
        event_id_uid=uid,
        role=role,
        event_family=efam,
        event_code=ecode,
        channel=channel,
        provider=provider,
        timestamp=ts,
        host=host,
        sigma_fields=sigma_fields,
        wazuh_fields=wazuh_fields,
        wazuh_rule_id=str(rule.get("id") or "") or None,
        wazuh_rule_desc=str(rule.get("description") or "") or None,
        mitre_techniques=parse_json_list_str(mitre.get("id") or mitre.get("technique")),
        mitre_tactics=parse_json_list_str(mitre.get("tactic")),
    )


def synthesize_generalized_variants(primary_events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Generate synthetic generalized attack variants (mutated random temp names, usernames, and path casing)
    to verify in Vòng A that the generated Sigma rule is NOT overfitted to one random token.
    """
    variants: list[NormalizedEvent] = []
    if not primary_events:
        return variants

    base = primary_events[0]

    v1 = copy.deepcopy(base)
    v1.event_id_uid = f"{base.event_id_uid}_var_user"
    for d in (v1.sigma_fields, v1.wazuh_fields):
        for k, val in list(d.items()):
            new_val = re.sub(r"\\Users\\[^\\]+\\", r"\\Users\\soc_test_user\\", val, flags=re.IGNORECASE)
            if k in ("User", "win.eventdata.user") and "\\" in val:
                domain = val.split("\\")[0]
                new_val = f"{domain}\\soc_test_user"
            d[k] = new_val
    variants.append(v1)

    v2 = copy.deepcopy(base)
    v2.event_id_uid = f"{base.event_id_uid}_var_randtoken"
    for d in (v2.sigma_fields, v2.wazuh_fields):
        for k, val in list(d.items()):
            new_val = re.sub(
                r"__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1",
                "__PSScriptPolicyTest_xyz98765.tmp.ps1",
                val,
                flags=re.IGNORECASE,
            )
            d[k] = new_val
    variants.append(v2)

    v3 = copy.deepcopy(base)
    v3.event_id_uid = f"{base.event_id_uid}_var_casing"
    for d in (v3.sigma_fields, v3.wazuh_fields):
        for k, val in list(d.items()):
            new_val = val.replace("C:\\WINDOWS\\", "C:\\Windows\\").replace("system32", "System32")
            d[k] = new_val
    variants.append(v3)

    return variants


def _extract_alert_list(raw_alert_data: Any) -> list[dict[str, Any]]:
    """Extract normalized list of alert dicts from raw_alert_data and reject swapped Evidence files."""
    if isinstance(raw_alert_data, dict):
        # Detect if user accidentally uploaded an Evidence file into the Alert slot
        if (
            ("target_event" in raw_alert_data and "window_size" in raw_alert_data and "anomaly_score" not in raw_alert_data)
            or ("evidence" in raw_alert_data and "alerts" not in raw_alert_data and "alert" not in raw_alert_data)
        ):
            raise ValueError(
                "File tải lên ở ô Alert thực chất là file Evidence (chứa window_size/context_events nhưng không có dữ liệu Alert). "
                "Vui lòng chọn đúng file Alert JSON ở ô số 1!"
            )
        if "alerts" in raw_alert_data and isinstance(raw_alert_data["alerts"], list):
            return [a for a in raw_alert_data["alerts"] if isinstance(a, dict)]
        if "alert" in raw_alert_data and isinstance(raw_alert_data["alert"], dict):
            return [raw_alert_data["alert"]]
        if "alert_id" in raw_alert_data or "target_event" in raw_alert_data or "process" in raw_alert_data:
            return [raw_alert_data]
    elif isinstance(raw_alert_data, list):
        if raw_alert_data and isinstance(raw_alert_data[0], dict):
            first = raw_alert_data[0]
            if ("window_size" in first and "anomaly_score" not in first) or ("_evidence" in first and "alert_id" not in first):
                raise ValueError(
                    "File tải lên ở ô Alert thực chất là file Evidence. Vui lòng chọn đúng file Alert JSON ở ô số 1!"
                )
        return [a for a in raw_alert_data if isinstance(a, dict)]

    raise ValueError("Cấu trúc file Alert JSON không hợp lệ: cần chứa đối tượng Alert (có alert_id / evidence_id).")


def _index_evidence_records(raw_ev_data: Any) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    """Build lookup dictionaries mapping `evidence_id` and `alert_id` to their evidence records,
    plus a summary list of `[{"alert_id": ..., "evidence_id": ...}]` found in the evidence file.
    """
    by_evidence_id: dict[str, Any] = {}
    by_alert_id: dict[str, Any] = {}
    summary_pairs: list[dict[str, str]] = []

    if not raw_ev_data:
        return by_evidence_id, by_alert_id, summary_pairs

    # Detect if user accidentally uploaded an Alert file into the Evidence slot
    if isinstance(raw_ev_data, dict):
        if (
            ("anomaly_score" in raw_ev_data or "scored_token" in raw_ev_data or "alerts" in raw_ev_data)
            and "target_event" not in raw_ev_data
            and "context_events" not in raw_ev_data
            and "evidence" not in raw_ev_data
        ):
            raise ValueError(
                "File tải lên ở ô Evidence thực chất là file Alert (chứa anomaly_score nhưng không có target_event/context_events). "
                "Vui lòng chọn đúng file *_evidence.json ở ô số 2!"
            )

    ev_items: list[Any] = []
    if isinstance(raw_ev_data, dict):
        if "evidence" in raw_ev_data and isinstance(raw_ev_data["evidence"], list):
            ev_items = raw_ev_data["evidence"]
        elif "evidence_id" in raw_ev_data or "alert_id" in raw_ev_data or "target_event" in raw_ev_data or "context_events" in raw_ev_data:
            ev_items = [raw_ev_data]
    elif isinstance(raw_ev_data, list):
        ev_items = raw_ev_data

    for item in ev_items:
        if isinstance(item, dict):
            ev_id = str(item.get("evidence_id") or "").strip()
            al_id = str(item.get("alert_id") or "").strip()
            ev_meta = item.get("_evidence")
            if isinstance(ev_meta, dict) and ev_meta.get("alert_id") and not al_id:
                al_id = str(ev_meta["alert_id"]).strip()

            if ev_id or al_id:
                pair = {"alert_id": al_id, "evidence_id": ev_id}
                if pair not in summary_pairs:
                    summary_pairs.append(pair)

            if ev_id:
                by_evidence_id[ev_id] = item
            if al_id:
                if isinstance(ev_meta, dict) and "_evidence" in item:
                    by_alert_id.setdefault(al_id, [])
                    if isinstance(by_alert_id[al_id], list):
                        by_alert_id[al_id].append(item)
                else:
                    by_alert_id[al_id] = item

    return by_evidence_id, by_alert_id, summary_pairs


def validate_alert_evidence_correspondence(raw_alert_data: Any, raw_ev_data: Any) -> dict[str, Any]:
    """Strictly verify that `alert_id` and `evidence_id` in `raw_alert_data` match `raw_ev_data`.

    Returns a dictionary summarizing matched pairs, or raises ValueError if mismatched.
    """
    alert_list = _extract_alert_list(raw_alert_data)
    if raw_ev_data is None:
        return {
            "valid": True,
            "has_evidence": False,
            "alert_count": len(alert_list),
            "matched_pairs": [
                {"alert_id": str(a.get("alert_id") or ""), "evidence_id": str(a.get("evidence_id") or "")}
                for a in alert_list
            ],
        }

    by_ev_id, by_al_id, ev_summary = _index_evidence_records(raw_ev_data)
    matched_pairs: list[dict[str, str]] = []
    mismatches: list[str] = []

    for idx, a_obj in enumerate(alert_list):
        aid = str(a_obj.get("alert_id") or f"AI-ALERT-{idx + 1:03d}").strip()
        evid = str(a_obj.get("evidence_id") or "").strip()

        matched_ev = None
        if evid and evid in by_ev_id:
            matched_ev = by_ev_id[evid]
            # Also verify alert_id matches if present on the evidence object
            ev_aid = str(matched_ev.get("alert_id") or "").strip() if isinstance(matched_ev, dict) else ""
            if aid and ev_aid and aid != ev_aid:
                mismatches.append(
                    f"Alert có [alert_id='{aid}', evidence_id='{evid}'] nhưng Evidence cùng evidence_id lại có [alert_id='{ev_aid}']"
                )
                continue
        elif aid and aid in by_al_id:
            matched_ev = by_al_id[aid]
            ev_evid = str(matched_ev.get("evidence_id") or "").strip() if isinstance(matched_ev, dict) else ""
            if evid and ev_evid and evid != ev_evid:
                mismatches.append(
                    f"Alert có [alert_id='{aid}', evidence_id='{evid}'] nhưng Evidence cùng alert_id lại có [evidence_id='{ev_evid}']"
                )
                continue

        if matched_ev is None:
            sample_ev_str = (
                ", ".join(f"[alert_id='{p['alert_id']}', evidence_id='{p['evidence_id']}']" for p in ev_summary[:3])
                if ev_summary
                else "không tìm thấy trường alert_id / evidence_id hợp lệ"
            )
            mismatches.append(
                f"File Alert có [alert_id='{aid}', evidence_id='{evid or 'N/A'}'] KHÔNG KHỚP với file Evidence ({sample_ev_str})"
            )
        else:
            matched_pairs.append({"alert_id": aid, "evidence_id": evid})

    if mismatches:
        raise ValueError(
            "Không khớp cặp dữ liệu Alert ↔ Evidence: " + "; ".join(mismatches[:3])
            + ". Vui lòng chọn đúng file Evidence tương ứng với file Alert!"
        )

    return {
        "valid": True,
        "has_evidence": True,
        "alert_count": len(alert_list),
        "matched_pairs": matched_pairs,
    }


def load_alert_bundles_from_raw(
    raw_alert_data: Any,
    raw_ev_data: Any = None,
    deduplicate_tokens: bool = False,
) -> list[NormalizedAlertBundle]:
    """Parse 1 or N NormalizedAlertBundles directly from parsed JSON objects/lists in memory.

    Enforces strict correspondence between `alert_id` and `evidence_id` when `raw_ev_data` is provided.
    """
    # Case A: Combined MLInput (`{"alert": {...}, "evidence": [...]}`)
    if isinstance(raw_alert_data, dict) and "alert" in raw_alert_data and "evidence" in raw_alert_data and raw_ev_data is None:
        raw_ev_data = raw_alert_data["evidence"]
        raw_alert_data = raw_alert_data["alert"]

    # Validate Alert <-> Evidence correspondence first
    validate_alert_evidence_correspondence(raw_alert_data, raw_ev_data)

    alert_list = _extract_alert_list(raw_alert_data)
    by_ev_id, by_al_id, _ = _index_evidence_records(raw_ev_data)

    bundles: list[NormalizedAlertBundle] = []
    seen_patterns: set[str] = set()

    for idx, alert_obj in enumerate(alert_list):
        aid = str(alert_obj.get("alert_id") or f"AI-ALERT-{idx + 1:03d}").strip()
        ev_id = str(alert_obj.get("evidence_id") or "").strip()

        matched_ev: Any = None
        if ev_id and ev_id in by_ev_id:
            matched_ev = by_ev_id[ev_id]
        elif aid and aid in by_al_id:
            matched_ev = by_al_id[aid]

        bundle = _build_single_alert_bundle(alert_obj, matched_ev)

        if deduplicate_tokens and bundle.primary_events:
            p_ev = bundle.primary_events[0]
            tf_raw = p_ev.sigma_fields.get("TargetFilename", "")
            tf_pattern = re.sub(r"__PSScriptPolicyTest_[a-z0-9.]+", "__PSScriptPolicyTest_*", tf_raw)
            pattern_key = (
                f"{bundle.observed_token}|{p_ev.event_code}|"
                f"{p_ev.sigma_fields.get('Image')}|{p_ev.sigma_fields.get('ParentImage')}|"
                f"{p_ev.sigma_fields.get('CommandLine')}|{tf_pattern}|"
                f"{p_ev.sigma_fields.get('TargetObject')}|{p_ev.sigma_fields.get('QueryName')}"
            )
            if pattern_key in seen_patterns:
                continue
            seen_patterns.add(pattern_key)

        bundles.append(bundle)

    return bundles


def load_alert_bundles(
    alert_path: Path,
    evidence_path: Path | None = None,
    deduplicate_tokens: bool = False,
) -> list[NormalizedAlertBundle]:
    """Load one or more NormalizedAlertBundles from LogDeep v1, LogDeep v2 (nested), or Wazuh ML JSON files."""
    text = alert_path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("{") and "\n{" in text:
        raw_alert_data = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        raw_alert_data = json.loads(text)

    # Auto-discover companion evidence file if not explicitly passed
    if evidence_path is None:
        stem = alert_path.stem
        candidates = [
            alert_path.parent / f"{stem}_evidence.json",
            alert_path.parent / "ai_alert_evidence_test.json",
            alert_path.parent / "evidence.json",
        ]
        if isinstance(raw_alert_data, dict) and raw_alert_data.get("evidence_file"):
            ev_rel = Path(str(raw_alert_data["evidence_file"]))
            candidates.insert(0, alert_path.parent / ev_rel)
            candidates.insert(1, alert_path.parent / ev_rel.name)
        for c in candidates:
            if c.exists() and c.is_file() and c.resolve() != alert_path.resolve():
                # Only auto-pair if the candidate evidence actually matches this alert!
                try:
                    ev_txt = c.read_text(encoding="utf-8-sig").strip()
                    ev_cand = [json.loads(line) for line in ev_txt.splitlines() if line.strip()] if (ev_txt.startswith("{") and "\n{" in ev_txt) else json.loads(ev_txt)
                    validate_alert_evidence_correspondence(raw_alert_data, ev_cand)
                    evidence_path = c
                    break
                except Exception:
                    continue

    raw_ev_data: Any = None
    if evidence_path and evidence_path.exists():
        ev_text = evidence_path.read_text(encoding="utf-8-sig").strip()
        if ev_text.startswith("{") and "\n{" in ev_text:
            raw_ev_data = [json.loads(line) for line in ev_text.splitlines() if line.strip()]
        elif ev_text:
            raw_ev_data = json.loads(ev_text)

    return load_alert_bundles_from_raw(
        raw_alert_data=raw_alert_data,
        raw_ev_data=raw_ev_data,
        deduplicate_tokens=deduplicate_tokens,
    )


def _build_single_alert_bundle(alert_obj: dict[str, Any], ev_data: Any) -> NormalizedAlertBundle:
    """Construct a NormalizedAlertBundle from LogDeep v1, LogDeep v2 (nested), or Wazuh ML alert."""
    aid = str(alert_obj.get("alert_id") or "ALERT-UNKNOWN").strip()
    ev_id = str(alert_obj.get("evidence_id") or "").strip()
    token = str(alert_obj.get("event_token") or alert_obj.get("observed_token") or "")

    is_logdeep = (
        isinstance(alert_obj.get("process"), dict)
        or isinstance(alert_obj.get("target_event"), dict)
        or "event_token" in alert_obj
        or "observed_token" in alert_obj
        or (isinstance(ev_data, list) and len(ev_data) > 0 and isinstance(ev_data[0], dict) and ("target_event" in ev_data[0] or "context_events" in ev_data[0]))
        or (isinstance(ev_data, dict) and ("target_event" in ev_data or "context_events" in ev_data))
    )

    if is_logdeep:
        w_ctx = alert_obj.get("wazuh_context") if isinstance(alert_obj.get("wazuh_context"), dict) else {}
        m_ctx = alert_obj.get("mitre_context") if isinstance(alert_obj.get("mitre_context"), dict) else {}
        w_mitre = w_ctx.get("mitre") if isinstance(w_ctx.get("mitre"), dict) else m_ctx
        w_desc = str(w_ctx.get("rule_description") or "").strip()

        ev_envelope: dict[str, Any] = {}
        if isinstance(ev_data, list) and len(ev_data) > 0 and isinstance(ev_data[0], dict):
            matched = next(
                (item for item in ev_data if item.get("evidence_id") == ev_id or item.get("alert_id") == aid),
                None,
            )
            if matched is None:
                raise ValueError(f"Không tìm thấy bản ghi Evidence khớp với alert_id='{aid}', evidence_id='{ev_id}'.")
            ev_envelope = matched
        elif isinstance(ev_data, dict):
            if "evidence" in ev_data and isinstance(ev_data["evidence"], list):
                matched = next(
                    (item for item in ev_data["evidence"] if isinstance(item, dict) and (item.get("evidence_id") == ev_id or item.get("alert_id") == aid)),
                    None,
                )
                if matched is None:
                    raise ValueError(f"Không tìm thấy bản ghi Evidence khớp với alert_id='{aid}', evidence_id='{ev_id}'.")
                ev_envelope = matched
            else:
                ev_envelope = ev_data

        if not ev_id and ev_envelope.get("evidence_id"):
            ev_id = str(ev_envelope["evidence_id"]).strip()

        te_raw = ev_envelope.get("target_event") or alert_obj.get("target_event") or alert_obj
        primary_ev = normalize_logdeep_event(te_raw, role="primary")

        alert_ev = normalize_logdeep_event(alert_obj.get("target_event") or alert_obj, role="primary")
        for k, v in alert_ev.sigma_fields.items():
            primary_ev.sigma_fields.setdefault(k, v)
        for k, v in alert_ev.wazuh_fields.items():
            primary_ev.wazuh_fields.setdefault(k, v)

        context_evs: list[NormalizedEvent] = []
        for c_raw in ev_envelope.get("context_events", []):
            if isinstance(c_raw, dict):
                context_evs.append(normalize_logdeep_event(c_raw, role="context"))

        mitre_techs = (
            parse_json_list_str(alert_obj.get("mitre_attack"))
            or parse_json_list_str(w_mitre.get("id") if isinstance(w_mitre, dict) else None)
            or parse_json_list_str(w_mitre.get("technique") if isinstance(w_mitre, dict) else None)
            or primary_ev.mitre_techniques
        )
        mitre_tacs = (
            parse_json_list_str(alert_obj.get("tactic"))
            or parse_json_list_str(w_mitre.get("tactic") if isinstance(w_mitre, dict) else None)
            or primary_ev.mitre_tactics
        )

        # Automatically infer MITRE ATT&CK technique & tactic when Wazuh context has no MITRE tags
        if not mitre_techs:
            inferred_techs, inferred_tacs = infer_mitre_from_telemetry(
                primary_ev.event_code,
                primary_ev.sigma_fields,
                token=token,
            )
            mitre_techs = inferred_techs
            if not mitre_tacs:
                mitre_tacs = inferred_tacs

        img_base = primary_ev.sigma_fields.get("Image", "").rsplit("\\", 1)[-1]
        pimg_base = primary_ev.sigma_fields.get("ParentImage", "").rsplit("\\", 1)[-1]
        pcmd = primary_ev.sigma_fields.get("ParentCommandLine", "")
        cmd = primary_ev.sigma_fields.get("CommandLine", "")
        tobj = primary_ev.sigma_fields.get("TargetObject", "")
        qname = primary_ev.sigma_fields.get("QueryName", "")

        if w_desc:
            if pimg_base and img_base:
                default_title = f"Suspicious {pimg_base} Spawning {img_base} ({w_desc})"
            else:
                default_title = f"LogDeep Anomaly: {w_desc}"
        else:
            if primary_ev.event_code in (12, 13) and tobj:
                key_tail = tobj.rsplit("\\", 1)[-1]
                default_title = f"Suspicious Registry Activity by {img_base or 'Process'} on {key_tail}"
            elif primary_ev.event_code == 22 and qname:
                default_title = f"Suspicious DNS Query by {img_base or 'Process'} for {qname}"
            elif pimg_base and img_base:
                default_title = f"Suspicious Process Creation: {pimg_base} Spawning {img_base}"
            elif img_base:
                default_title = f"Suspicious Activity by {img_base} ({mitre_techs[0]})"
            else:
                default_title = f"LogDeep Sequence Anomaly ({token or aid})"

        title = str(alert_obj.get("title") or default_title)
        desc = str(
            alert_obj.get("description")
            or f"Host {alert_obj.get('host')} triggered sequence anomaly (token='{token}', score={float(alert_obj.get('anomaly_score') or 0.0):.4f}): "
            f"Image={img_base}, ParentImage={pimg_base}, CommandLine={cmd}, MITRE={','.join(mitre_techs)}."
        )

        src_fmt = "logdeep_v2" if isinstance(alert_obj.get("process"), dict) else "logdeep"
        return NormalizedAlertBundle(
            alert_id=aid,
            evidence_id=ev_id,
            source_format=src_fmt,
            title=title,
            description=desc,
            severity=str(alert_obj.get("severity") or "high").lower(),
            anomaly_score=float(alert_obj["anomaly_score"]) if alert_obj.get("anomaly_score") is not None else None,
            host=str(alert_obj.get("host") or ""),
            timestamp=str(alert_obj.get("timestamp") or ""),
            observed_token=token,
            mitre_techniques=mitre_techs,
            mitre_tactics=mitre_tacs,
            wazuh_rule_id=str(w_ctx.get("rule_id")) if w_ctx.get("rule_id") else None,
            wazuh_rule_description=w_desc or default_title,
            primary_events=[primary_ev],
            context_events=context_evs,
            generalized_variants=synthesize_generalized_variants([primary_ev]),
        )

    # Otherwise: Wazuh ML format (`ALERT-001..005` from `LLM_API`)
    title = str(alert_obj.get("title") or alert_obj.get("description") or aid)
    desc = str(alert_obj.get("description") or title)
    sev = str(alert_obj.get("severity") or "medium").lower()
    score = float(alert_obj["anomaly_score"]) if alert_obj.get("anomaly_score") is not None else None
    host = str(alert_obj.get("host") or alert_obj.get("agent_name") or "")
    ts = str(alert_obj.get("first_seen_utc") or alert_obj.get("timestamp") or "")

    mitre_techs = parse_json_list_str(alert_obj.get("mitre_attack"))
    mitre_tacs = parse_json_list_str(alert_obj.get("tactic"))

    ground_truth = {}
    for gt_key in ("detection_hints_for_rule", "why_wazuh_missed"):
        if gt_key in alert_obj:
            ground_truth[gt_key] = alert_obj[gt_key]

    primary_evs: list[NormalizedEvent] = []
    context_evs: list[NormalizedEvent] = []

    ev_list = ev_data if isinstance(ev_data, list) else []
    for idx, raw_ev in enumerate(ev_list, 1):
        norm_ev = normalize_wazuh_archive_event(raw_ev, default_role="primary", idx=idx)
        if norm_ev.role == "primary":
            primary_evs.append(norm_ev)
        else:
            context_evs.append(norm_ev)

    sysmon_primary = [e for e in primary_evs if e.event_family == "sysmon" and len(e.sigma_fields) > 2]
    if sysmon_primary:
        non_sysmon = [e for e in primary_evs if e not in sysmon_primary]
        primary_evs = sysmon_primary
        context_evs.extend(non_sysmon)

    if not mitre_techs and primary_evs:
        mitre_techs, mitre_tacs = infer_mitre_from_telemetry(
            primary_evs[0].event_code,
            primary_evs[0].sigma_fields,
        )

    return NormalizedAlertBundle(
        alert_id=aid,
        evidence_id=ev_id or f"EVID-{aid}",
        source_format="wazuh_ml",
        title=title,
        description=desc,
        severity=sev,
        anomaly_score=score,
        host=host,
        timestamp=ts,
        mitre_techniques=mitre_techs,
        mitre_tactics=mitre_tacs,
        primary_events=primary_evs,
        context_events=context_evs,
        generalized_variants=synthesize_generalized_variants(primary_evs),
        ground_truth=ground_truth,
    )


def load_benign_background_events(paths: list[Path] | None = None) -> list[NormalizedEvent]:
    """Load benign/background telemetry events for False Positive (FP/TN) evaluation in Vòng B."""
    benign_events: list[NormalizedEvent] = []

    if paths:
        for p in paths:
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8-sig").strip()
            if not text:
                continue
            if text.startswith("{") and "\n{" in text:
                for idx, line in enumerate(text.splitlines(), 1):
                    if line.strip():
                        raw = json.loads(line)
                        ev = normalize_wazuh_archive_event(raw, default_role="benign", idx=idx)
                        ev.role = "benign"
                        benign_events.append(ev)
            else:
                data = json.loads(text)
                ev_records = []
                if isinstance(data, dict) and "evidence" in data and isinstance(data["evidence"], list):
                    ev_records = data["evidence"]
                elif isinstance(data, list):
                    ev_records = data

                for idx, raw in enumerate(ev_records, 1):
                    if isinstance(raw, dict) and ("target_event" in raw or "context_events" in raw):
                        for c_raw in raw.get("context_events", []):
                            cev = normalize_logdeep_event(c_raw, role="benign")
                            if cev.event_code in (4624, 7036, 7040) or (
                                cev.sigma_fields.get("Image", "").lower().endswith(
                                    ("werfault.exe", "taskhostw.exe", "svchost.exe", "mscorsvw.exe", "tiworker.exe")
                                )
                            ):
                                benign_events.append(cev)
                    elif isinstance(raw, dict):
                        ev = normalize_wazuh_archive_event(raw, default_role="benign", idx=idx)
                        if ev.event_code in (4624, 7036, 7040) or ev.event_family == "ossec" or (
                            ev.sigma_fields.get("Image", "").lower().endswith(
                                ("werfault.exe", "taskhostw.exe", "svchost.exe", "mscorsvw.exe", "tiworker.exe")
                            )
                        ):
                            ev.role = "benign"
                            benign_events.append(ev)

    builtin_benign_specs = [
        {
            "uid": "benign-sysmon-1-svchost",
            "family": "sysmon",
            "code": 1,
            "fields": {
                "EventID": "1",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "CommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sysmon-1-werfault",
            "family": "sysmon",
            "code": 1,
            "fields": {
                "EventID": "1",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\WerFault.exe",
                "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                "CommandLine": "C:\\WINDOWS\\system32\\WerFault.exe -pss -s 576 -p 1836 -ip 1836",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sysmon-1-taskhostw",
            "family": "sysmon",
            "code": 1,
            "fields": {
                "EventID": "1",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\taskhostw.exe",
                "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                "CommandLine": "taskhostw.exe",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sysmon-1-powershell-admin-normal",
            "family": "sysmon",
            "code": 1,
            "fields": {
                "EventID": "1",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "CommandLine": "powershell.exe Get-Service",
                "User": "CORP\\admin",
            },
        },
        {
            "uid": "benign-sysmon-11-normal-log",
            "family": "sysmon",
            "code": 11,
            "fields": {
                "EventID": "11",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorsvw.exe",
                "TargetFilename": "C:\\Windows\\Temp\\ngen_service.log",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sysmon-11-powershell-profile",
            "family": "sysmon",
            "code": 11,
            "fields": {
                "EventID": "11",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\admin\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
                "User": "CORP\\admin",
            },
        },
        {
            "uid": "benign-sysmon-13-defender-normal",
            "family": "sysmon",
            "code": 13,
            "fields": {
                "EventID": "13",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventType": "SetValue",
                "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.24020.7-0\\MsMpEng.exe",
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\AVSignatureVersion",
                "Details": "1.407.521.0",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sysmon-1-reg-normal",
            "family": "sysmon",
            "code": 1,
            "fields": {
                "EventID": "1",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "ParentImage": "C:\\Windows\\System32\\gpscript.exe",
                "CommandLine": "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        {
            "uid": "benign-sec-4624-normal",
            "family": "windows_security",
            "code": 4624,
            "fields": {
                "EventID": "4624",
                "Channel": "Security",
                "User": "DESKTOP-QGB4EQH$",
            },
        },
        {
            "uid": "benign-scm-7036-normal",
            "family": "service_control",
            "code": 7036,
            "fields": {
                "EventID": "7036",
                "Channel": "System",
            },
        },
    ]

    existing_uids = {e.event_id_uid for e in benign_events}
    for spec in builtin_benign_specs:
        if spec["uid"] not in existing_uids:
            w_fields = {}
            for sk, sv in spec["fields"].items():
                wk = next((w for _, (s, w) in FIELD_ALIASES.items() if s == sk), f"win.eventdata.{sk[0].lower() + sk[1:]}")
                w_fields[wk] = sv
            benign_events.append(
                NormalizedEvent(
                    event_id_uid=spec["uid"],
                    role="benign",
                    event_family=spec["family"],
                    event_code=spec["code"],
                    channel=spec["fields"].get("Channel", ""),
                    sigma_fields=dict(spec["fields"]),
                    wazuh_fields=w_fields,
                )
            )

    return benign_events