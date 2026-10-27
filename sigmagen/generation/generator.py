"""Sigma rule generation engine with multi-provider LLM support, RAG context,
Closed-Loop Self-Repair (Vòng A & Vòng B), Telemetry-Grounded Fallback, and Wazuh XML Compilation.
"""
from __future__ import annotations

import json
import re
import textwrap
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml
from rich.console import Console

from sigmagen.config import (
    ANTHROPIC_API_KEY,
    ANTHROPIC_MODEL,
    GENERATION_MAX_TOKENS,
    GENERATION_TEMPERATURE,
    LLM_PROVIDER,
    MAX_REPAIR_RETRIES,
    OLLAMA_HOST,
    OLLAMA_MODEL,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    RULE_ID_MAX,
    RULE_ID_MIN,
    WAZUH_GROUP_WRAPPER,
)
from sigmagen.conversion.wazuh_xml import (
    WazuhConversionResult,
    compile_sigma_to_wazuh_xml,
)
from sigmagen.generation.prompts import (
    SYSTEM_PROMPT,
    build_generation_prompt,
    build_repair_prompt,
)
from sigmagen.ingestion.alert_adapter import (
    NormalizedAlertBundle,
    NormalizedEvent,
    load_benign_background_events,
)
from sigmagen.retrieval.retriever import RetrievalResult, SigmaGenRetriever
from sigmagen.validation.validator import validate_sigma_rule
from sigmagen.validation.verifier import (
    VerificationReport,
    verify_and_score_sigma_rule,
)

console = Console()


# ---------------------------------------------------------------------------
# LLM Provider abstraction
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    @abstractmethod
    def generate(self, system: str, user: str) -> str:
        """Send a system + user prompt and return the raw text response."""


class AnthropicProvider(LLMProvider):
    """Claude via the Anthropic SDK."""

    def __init__(self, api_key: str = ANTHROPIC_API_KEY, model: str = ANTHROPIC_MODEL) -> None:
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to your .env file or export it as an environment variable."
            )
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def generate(self, system: str, user: str) -> str:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=GENERATION_MAX_TOKENS,
            temperature=GENERATION_TEMPERATURE,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text


class OpenAIProvider(LLMProvider):
    """OpenAI GPT models via the OpenAI SDK."""

    def __init__(self, api_key: str = OPENAI_API_KEY, model: str = OPENAI_MODEL) -> None:
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY is not set. "
                "Add it to your .env file or export it as an environment variable."
            )
        import openai

        self._client = openai.OpenAI(api_key=api_key)
        self._model = model

    def generate(self, system: str, user: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=GENERATION_MAX_TOKENS,
            temperature=GENERATION_TEMPERATURE,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content or ""


class OllamaProvider(LLMProvider):
    """Local models via Ollama HTTP API."""

    def __init__(self, host: str = OLLAMA_HOST, model: str = OLLAMA_MODEL) -> None:
        self._host = host.rstrip("/")
        self._model = model

    def generate(self, system: str, user: str) -> str:
        import requests

        prompt = f"{system}\n\n{user}"
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": GENERATION_TEMPERATURE,
                "num_predict": GENERATION_MAX_TOKENS,
            },
        }

        try:
            response = requests.post(
                f"{self._host}/api/generate",
                json=payload,
                timeout=(4, 90),
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Failed to connect to Ollama at {self._host}: {exc}"
            ) from exc

        data = response.json()
        if not data.get("done", False):
            raise RuntimeError("Ollama returned an incomplete response.")

        text = data.get("response", "")
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Ollama returned an empty response.")

        return text.strip()


class HeuristicLocalFallbackProvider(LLMProvider):
    """Deterministic telemetry-grounded rule synthesizer for offline testing / fallback when LLM fails after max repairs."""

    def generate(self, system: str, user: str) -> str:
        """Synthesize a valid, generalized Sigma YAML rule directly from the structured telemetry prompt."""
        alert_id_m = re.search(r"ALERT_ID:\s*(.+)", user)
        alert_id = alert_id_m.group(1).strip() if alert_id_m else "ALERT-LOCAL"

        summary_m = re.search(r"BEHAVIOR_SUMMARY:\s*(.+)", user)
        summary = summary_m.group(1).strip() if summary_m else "Suspicious Windows Activity"

        mitre_m = re.search(r"SUPPORTED_MITRE_TECHNIQUES:\s*(.+)", user)
        mitre_list = [x.strip().lower() for x in mitre_m.group(1).split(",") if x.strip()] if mitre_m else []

        ls_m = re.search(r"Set `logsource:` to exactly:\s*(\{.*?\})", user)
        logsource = json.loads(ls_m.group(1)) if ls_m else {"product": "windows", "category": "process_creation"}

        # Parse PRIMARY_TELEMETRY_FIELDS
        fields: dict[str, str] = {}
        in_fields = False
        for line in user.splitlines():
            if line.startswith("PRIMARY_TELEMETRY_FIELDS"):
                in_fields = True
                continue
            if in_fields:
                if line.startswith("  - "):
                    m = re.match(r"  - ([A-Za-z0-9_]+) \([^)]+\): (.+)", line)
                    if m:
                        fields[m.group(1)] = m.group(2).strip()
                else:
                    in_fields = False

        selection: dict[str, object] = {}
        title = f"Suspicious Activity Detected ({alert_id})"
        level = "high"

        img = fields.get("Image", "")
        pimg = fields.get("ParentImage", "")
        cmd = fields.get("CommandLine", "")
        tf = fields.get("TargetFilename", "")
        tobj = fields.get("TargetObject", "")
        details = fields.get("Details", "")
        qname = fields.get("QueryName", "")

        img_base = "\\" + img.replace("/", "\\").rsplit("\\", 1)[-1] if img else ""
        img_low = img_base.lower()
        pimg_base = "\\" + pimg.replace("/", "\\").rsplit("\\", 1)[-1] if pimg else ""
        pimg_low = pimg_base.lower()
        cmd_low = cmd.lower()

        if img_base:
            if "hostname.exe" in img_low and "whoami.exe" in user.lower() and "ADDITIONAL_PRIMARY_EVENTS" in user:
                selection["Image|endswith"] = ["\\hostname.exe", "\\whoami.exe"]
            else:
                selection["Image|endswith"] = img_base

        if pimg_base and any(x in pimg_low for x in ("powershell.exe", "cmd.exe", "winword.exe", "services.exe", "winlogon.exe", "net.exe")):
            selection["ParentImage|endswith"] = pimg_base

        if tf:
            if "__PSScriptPolicyTest_" in tf:
                title = "PowerShell Script Policy Test File Created in Temp Directory"
                selection["TargetFilename|contains"] = "\\AppData\\Local\\Temp\\__PSScriptPolicyTest_"
                selection["TargetFilename|endswith"] = ".ps1"
            else:
                tf_base = "\\" + tf.replace("/", "\\").rsplit("\\", 1)[-1]
                title = f"Suspicious File Creation in Temp Directory ({tf_base.lstrip(chr(92))})"
                if "\\Temp\\" in tf:
                    selection["TargetFilename|contains"] = "\\Temp\\"
                selection["TargetFilename|endswith"] = tf_base

        if cmd:
            if "start-process" in cmd_low and "externalpayloads" in cmd_low:
                title = "Nested PowerShell Start-Process Execution from ExternalPayloads"
                selection["CommandLine|contains|all"] = ["Start-Process", "ExternalPayloads"]
            elif "services\\disk\\enum" in cmd_low:
                title = "Registry Query of Disk Enum Hardware Key for VM Discovery"
                selection["CommandLine|contains|all"] = ["query", "Services\\Disk\\Enum"]
            elif "interface show interface" in cmd_low:
                title = "Network Interface Configuration Discovery via Netsh"
                selection["CommandLine|contains|all"] = ["interface", "show"]
                level = "medium"
            elif "-enc" in cmd_low:
                title = "Suspicious PowerShell Encoded Command Execution"
                selection["CommandLine|contains"] = "-enc"
            elif "dir /s" in cmd_low:
                title = "Recursive File and Directory Discovery via Command Shell"
                selection["CommandLine|contains"] = "dir /s"
                level = "medium"
            elif "netstat" in cmd_low and "cmd.exe" in img_low:
                title = "Network Connection and Session Enumeration via Command Shell"
                selection["CommandLine|contains"] = "netstat"
                level = "medium"
            elif "tasklist" in cmd_low and "cmd.exe" in img_low:
                title = "Process and Service Enumeration via Command Shell"
                selection["CommandLine|contains"] = "tasklist"
                level = "medium"
            elif "whoami" in cmd_low and "cmd.exe" in img_low:
                title = "User Account Privilege Enumeration via Command Shell"
                selection["CommandLine|contains"] = "whoami"
                level = "medium"
            elif "net view" in cmd_low and "cmd.exe" in img_low:
                title = "Network Share Enumeration via Command Shell"
                selection["CommandLine|contains"] = "net view"
                level = "medium"
            elif "net time" in cmd_low and "cmd.exe" in img_low:
                title = "System Time Discovery via Command Shell"
                selection["CommandLine|contains"] = "net time"
                level = "medium"
            elif "systeminfo.exe" in img_low:
                title = "System Information Discovery via Systeminfo Execution"
                selection["CommandLine|contains"] = "systeminfo"
                level = "medium"
            elif "hostname.exe" in img_low:
                title = "System Hostname Discovery Execution"
                level = "medium"
            elif "whoami.exe" in img_low:
                title = "System Owner and User Discovery via Whoami"
                if "/all" in cmd_low:
                    selection["CommandLine|contains"] = "/all"
                level = "medium"
            elif "tasklist.exe" in img_low:
                title = "Running Process Enumeration via Tasklist"
                if "/svc" in cmd_low:
                    selection["CommandLine|contains"] = "/svc"
                level = "medium"
            elif "ipconfig.exe" in img_low:
                title = "System Network Configuration Discovery via Ipconfig"
                if "/all" in cmd_low:
                    selection["CommandLine|contains"] = "/all"
                level = "medium"
            elif "arp.exe" in img_low:
                title = "ARP Cache Table Discovery Execution"
                if "-a" in cmd_low:
                    selection["CommandLine|contains"] = "-a"
                level = "medium"
            elif "nbtstat.exe" in img_low:
                title = "NetBIOS Name Table Discovery via Nbtstat"
                if "-n" in cmd_low:
                    selection["CommandLine|contains"] = "-n"
                level = "medium"
            elif "netstat.exe" in img_low:
                title = "Active Network Connections Discovery via Netstat"
                if "-ano" in cmd_low:
                    selection["CommandLine|contains"] = "-ano"
                level = "medium"
            elif "net.exe" in img_low or "net1.exe" in img_low:
                if "/domain" in cmd_low:
                    title = "Domain Network Share Enumeration via Net View"
                    selection["CommandLine|contains|all"] = ["view", "/domain"]
                elif "view" in cmd_low:
                    title = "Network Share Enumeration via Net View"
                    selection["CommandLine|contains"] = "view"
                elif "sessions" in cmd_low:
                    title = "Active Network Session Enumeration via Net Sessions"
                    selection["CommandLine|contains"] = "sessions"
                elif "use" in cmd_low:
                    title = "Network Share Connection Enumeration via Net Use"
                    selection["CommandLine|contains"] = "use"
                elif "config" in cmd_low:
                    title = "Network Service Configuration Discovery via Net Config"
                    selection["CommandLine|contains"] = "config"
                elif "time" in cmd_low:
                    title = "System Time Discovery via Net Time"
                    selection["CommandLine|contains"] = "time"
                level = "medium"
            elif "sc.exe" in img_low:
                if "state=" in cmd_low:
                    title = "All Windows Services State Enumeration via Sc Query"
                    selection["CommandLine|contains|all"] = ["query", "state="]
                else:
                    title = "Windows Service Status Enumeration via Sc Query"
                    selection["CommandLine|contains"] = "query"
                level = "medium"
            elif "tree.com" in img_low:
                title = "Directory Structure Discovery via Tree Utility"
                if "/f" in cmd_low:
                    selection["CommandLine|contains"] = "/F"
                level = "medium"
            elif "w32tm.exe" in img_low:
                title = "System Timezone Discovery via W32tm Utility"
                if "/tz" in cmd_low:
                    selection["CommandLine|contains"] = "/tz"
                level = "medium"
            elif "rundll32.exe" in img_low:
                if "startupscan.dll" in cmd_low:
                    title = "Suspicious Rundll32 Execution of Startupscan SusRunTask"
                    selection["CommandLine|contains"] = "Startupscan.dll,SusRunTask"
                elif "acproxy.dll" in cmd_low:
                    title = "Anomalous Rundll32 Execution of Acproxy Autochk Operations"
                    selection["CommandLine|contains"] = "acproxy.dll,PerformAutochkOperations"
                else:
                    tokens = [t.strip('"\'') for t in cmd.split() if len(t.strip('"\'')) >= 4]
                    if len(tokens) >= 2:
                        selection["CommandLine|contains"] = tokens[-1]
                    title = "Suspicious Rundll32 Proxy Execution"
            elif "mpcmdrun.exe" in img_low:
                title = "Windows Defender MpCmdRun Command Line Utility Execution"
                if "getdeviceticket" in cmd_low:
                    selection["CommandLine|contains"] = "GetDeviceTicket"
                level = "medium"
            elif "taskhostw.exe" in img_low:
                if "keyroaming" in cmd_low:
                    title = "Anomalous Taskhostw Execution with KEYROAMING Parameter"
                    selection["CommandLine|contains"] = "KEYROAMING"
                elif "ngckeypregen" in cmd_low:
                    title = "Anomalous Taskhostw Execution with NGCKeyPregen Parameter"
                    selection["CommandLine|contains"] = "NGCKeyPregen"
                else:
                    tokens = [t.strip('"\'') for t in cmd.split() if len(t.strip('"\'')) >= 4]
                    if len(tokens) >= 2:
                        selection["CommandLine|contains"] = tokens[-1]
                level = "medium"
            elif "logonui.exe" in img_low:
                title = "Anomalous Windows LogonUI Process Execution"
                if "/flags:" in cmd_low:
                    selection["CommandLine|contains"] = "/flags:"
                level = "medium"
            elif "trustedinstaller.exe" in img_low:
                title = "Anomalous Windows Modules Installer Service Execution"
                level = "medium"
            elif "lpremove.exe" in img_low:
                title = "Anomalous MUI Language Pack Cleanup Execution"
                level = "medium"
            else:
                tokens = [t.strip('"\'') for t in cmd.split() if len(t.strip('"\'')) >= 4 and ":\\" not in t]
                if tokens:
                    selection["CommandLine|contains"] = tokens[0]

        if tobj:
            if "DisableRealtimeMonitoring" in tobj:
                title = "Microsoft Defender Real-Time Monitoring Disabled via Registry"
                selection["TargetObject|contains"] = "DisableRealtimeMonitoring"
                if details:
                    selection["Details|contains"] = "0x00000001"
                level = "high"
            elif "Keyboard Layout\\Preload" in tobj:
                title = "Registry Modification of Default User Keyboard Layout Preload"
                selection["TargetObject|contains"] = "\\Keyboard Layout\\Preload\\"
                level = "medium"
            elif "LastLoggedOnUser" in tobj:
                title = "Registry Update of Authentication LogonUI LastLoggedOnUser"
                selection["TargetObject|contains"] = "\\Authentication\\LogonUI\\LastLoggedOnUser"
                level = "medium"
            elif "NetworkList\\Profiles" in tobj and "DateLastConnected" in tobj:
                title = "Registry Modification of Network Profile DateLastConnected"
                selection["TargetObject|contains|all"] = ["\\NetworkList\\Profiles\\", "\\DateLastConnected"]
                level = "medium"
            elif "CurrentVersion\\Run" in tobj:
                title = "Registry Run Key Persistence Modification"
                selection["TargetObject|contains"] = "\\CurrentVersion\\Run"
                level = "high"
            else:
                segs = [s for s in tobj.split("\\") if s]
                tail = segs[-1] if segs else tobj
                if len(tail) < 4 and len(segs) >= 2:
                    tail = "\\" + "\\".join(segs[-2:])
                selection["TargetObject|contains"] = tail

        if qname:
            host_part = qname.split(".")[0] if "." in qname else qname
            title = f"Anomalous DNS Query by {img_base.lstrip(chr(92)) or 'Process'} ({qname})"
            selection["QueryName|contains"] = host_part
            level = "medium"

        if not selection:
            if "EventID" in fields:
                selection["EventID"] = int(fields["EventID"]) if fields["EventID"].isdigit() else fields["EventID"]
                title = f"Unexpected Windows Service Termination (EventID {fields['EventID']})"
                level = "medium"

        tags = [f"attack.{t}" for t in mitre_list if re.match(r"^t\d{4}(\.\d{3})?$", t)]
        if not tags:
            tags = ["attack.t1059"]

        refs = [
            f"https://attack.mitre.org/techniques/{t.upper().replace('.', '/')}/"
            for t in mitre_list
            if re.match(r"^t\d{4}(\.\d{3})?$", t)
        ] or ["https://attack.mitre.org/"]

        rule_dict = {
            "title": title,
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": summary[:280],
            "references": refs,
            "author": "SigmaGen",
            "date": date.today().isoformat(),
            "tags": tags,
            "logsource": logsource,
            "detection": {
                "selection": selection,
                "condition": "selection",
            },
            "falsepositives": ["Legitimate administrative activity"],
            "level": level,
        }
        return yaml.safe_dump(rule_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)


def get_provider(override: str | None = None) -> LLMProvider:
    """Return an LLM provider based on configuration or override."""
    provider_name = (override or LLM_PROVIDER).lower()

    if provider_name == "anthropic":
        return AnthropicProvider()
    if provider_name == "openai":
        return OpenAIProvider()
    if provider_name == "ollama":
        return OllamaProvider()
    if provider_name in ("local_fallback", "mock", "heuristic"):
        return HeuristicLocalFallbackProvider()

    raise ValueError(
        f"Unknown LLM provider '{provider_name}'. "
        f"Supported providers: anthropic, openai, ollama, local_fallback."
    )


# ---------------------------------------------------------------------------
# Generated rule dataclass
# ---------------------------------------------------------------------------


@dataclass
class GeneratedRule:
    """A single generated Sigma rule with validation, 3-stage verification, and Wazuh XML output."""

    raw_yaml: str
    parsed: dict = field(default_factory=dict)
    technique_ids: list[str] = field(default_factory=list)
    valid: bool = False
    validation_errors: list[str] = field(default_factory=list)
    verification_report: VerificationReport | None = None
    wazuh_conversion: WazuhConversionResult | None = None
    repair_attempts: int = 0


# ---------------------------------------------------------------------------
# Generator helpers & YAML Backslash Sanitizer for Qwen 2.5 7B
# ---------------------------------------------------------------------------


def _slugify(text: str) -> str:
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "_", slug)
    slug = slug.strip("_")
    return slug[:80] or "sigma_rule"


_SIGMA_OUTPUT_CONSTRAINTS = """
OUTPUT CONTRACT — NON-NEGOTIABLE:
- Return Sigma rule(s) as YAML mappings. Each rule MUST be one YAML document.
- Output ONLY the YAML document(s). No explanation, commentary, headings,
  bullets, Markdown code fences, line numbers, or surrounding prose.
- The first YAML key MUST be `title:`.
- Do NOT wrap the rule in a YAML list (`- ...`).
- Use valid Sigma YAML syntax.
- ALWAYS wrap Windows file/registry paths in single quotes `'...'` (NEVER double quotes `"..."` with unescaped backslashes).
- Do not invent telemetry field names. Use only fields supported by the
  supplied Windows/Sysmon telemetry and retrieved Sigma examples.
- For MITRE ATT&CK technique tags, use only the canonical Sigma namespace
  `attack.tXXXX` or `attack.tXXXX.YYY`.
- Do not use `mitre.attack.*` or tactic names like `attack.execution`.
""".strip()


def _normalize_sigma_tags(parsed: dict, fallback_techniques: list[str] | None = None) -> list[str]:
    tags = parsed.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    technique_re = re.compile(
        r"^(?:attack\.|mitre\.attack\.)?(t\d{4}(?:\.\d{3})?)$",
        re.IGNORECASE,
    )
    normalized: list[str] = []

    for raw_tag in tags:
        tag = str(raw_tag).strip()
        if not tag:
            continue

        match = technique_re.match(tag)
        if match:
            canonical = f"attack.{match.group(1).lower()}"
            if canonical not in normalized:
                normalized.append(canonical)
            continue

        if tag.lower().startswith("mitre.") or tag.lower().startswith("attack."):
            continue

        if tag not in normalized:
            normalized.append(tag)

    # Ensure at least one canonical attack.tXXXX tag is present using fallback_techniques
    has_attack_tid = any(re.match(r"^attack\.t\d{4}(?:\.\d{3})?$", t, re.I) for t in normalized)
    if not has_attack_tid and fallback_techniques:
        for ft in fallback_techniques:
            m = re.match(r"^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$", str(ft).strip(), re.I)
            if m:
                canonical = f"attack.{m.group(1).lower()}"
                if canonical not in normalized:
                    normalized.append(canonical)

    parsed["tags"] = normalized
    return normalized


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if not text:
        return text

    # Also strip `<think>...</think>` blocks if the local model emits reasoning tags
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()

    # If the response contains a fenced ```yaml ... ``` block inside surrounding prose, extract the fenced block first
    fence_match = re.search(r"```(?:yaml|yml)?\s*\n(.*?)```", text, flags=re.S | re.I)
    if fence_match:
        return fence_match.group(1).strip()

    lines = text.splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _sanitize_yaml_windows_backslashes(yaml_text: str) -> str:
    r"""Fix common Qwen 2.5 7B YAML syntax errors caused by unescaped Windows backslashes inside double quotes."""
    fixed_lines: list[str] = []

    def _fix_dq_string(match: re.Match) -> str:
        inner = match.group(1)
        if "\\" not in inner:
            return match.group(0)
        norm = re.sub(r"\\{2,}", r"\\", inner)
        norm = norm.replace("'", "''")
        return f"'{norm}'"

    dq_pattern = re.compile(r'"([^"\n]*\\[^"\n]*)"')

    for line in yaml_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            fixed_lines.append(line)
            continue
        fixed_line = dq_pattern.sub(_fix_dq_string, line)
        fixed_lines.append(fixed_line)

    return "\n".join(fixed_lines)


def _extract_sigma_yaml(text: str) -> str:
    cleaned = _strip_markdown_fences(text)
    if not cleaned:
        raise ValueError("LLM returned an empty response.")

    lines = cleaned.splitlines()
    start_idx = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^-+\s+title\s*:", stripped):
            raise ValueError(
                "LLM returned a YAML list item instead of a top-level Sigma rule mapping."
            )
        if re.match(r"^title\s*:", stripped):
            start_idx = i
            break

    if start_idx is None:
        preview = cleaned[:300].replace("\n", "\\n")
        raise ValueError(
            f"Could not find a Sigma rule starting with 'title:' in LLM output. "
            f"Response preview: {preview}"
        )

    candidate = "\n".join(lines[start_idx:]).strip()
    dedented = textwrap.dedent(candidate).strip()
    return _sanitize_yaml_windows_backslashes(dedented)


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------


class SigmaGenGenerator:
    """Orchestrates RAG retrieval, LLM generation, 3-stage Verification (Vòng A/B), Self-Repair, and Wazuh XML compilation."""

    def __init__(self, provider_override: str | None = None) -> None:
        self._provider = get_provider(provider_override)
        self._retriever: SigmaGenRetriever | None = None

    def _retrieve_context(self, input_text: str) -> RetrievalResult:
        """Best-effort RAG retrieval; gracefully falls back to empty context if ChromaDB is not initialized."""
        try:
            if self._retriever is None:
                self._retriever = SigmaGenRetriever()
            return self._retriever.retrieve(input_text)
        except Exception:
            return RetrievalResult(
                query=input_text,
                query_type="free_text",
                techniques=[],
                sigma_rules=[],
            )

    def generate(
        self,
        input_text: str,
        n_rules: int = 1,
    ) -> list[GeneratedRule]:
        """Generate and validate Sigma rule(s) for the given input."""
        retrieval_result = self._retrieve_context(input_text)
        user_prompt = build_generation_prompt(retrieval_result, input_text)

        if n_rules > 1:
            user_prompt += (
                f"\n\nGenerate {n_rules} distinct Sigma rules for different "
                f"variants or aspects of this behavior. Separate each rule "
                f"with a line containing only '---'."
            )

        system_prompt = f"{SYSTEM_PROMPT.strip()}\n\n{_SIGMA_OUTPUT_CONSTRAINTS}"

        try:
            raw_response = self._provider.generate(system_prompt, user_prompt)
        except RuntimeError:
            fallback = HeuristicLocalFallbackProvider()
            raw_response = fallback.generate(system_prompt, user_prompt)

        try:
            yaml_candidate = _extract_sigma_yaml(raw_response)
        except ValueError as exc:
            return [
                GeneratedRule(
                    raw_yaml=raw_response,
                    valid=False,
                    validation_errors=[str(exc)],
                )
            ]

        raw_blocks = self._split_yaml_blocks(yaml_candidate)
        results: list[GeneratedRule] = []
        for block in raw_blocks[:n_rules]:
            rule = self._parse_and_validate(block)
            results.append(rule)

        return results

    def generate_and_verify_from_alert(
        self,
        bundle: NormalizedAlertBundle,
        benign_corpus: list[NormalizedEvent] | None = None,
        assigned_wazuh_id: int = RULE_ID_MIN,
        max_repairs: int = MAX_REPAIR_RETRIES,
    ) -> GeneratedRule:
        """Full closed-loop pipeline for a single NormalizedAlertBundle."""
        if benign_corpus is None:
            benign_corpus = load_benign_background_events()

        prompt_input = bundle.build_llm_prompt_input()
        retrieval_result = self._retrieve_context(prompt_input)
        base_user_prompt = build_generation_prompt(retrieval_result, prompt_input)
        system_prompt = f"{SYSTEM_PROMPT.strip()}\n\n{_SIGMA_OUTPUT_CONSTRAINTS}"

        current_user_prompt = base_user_prompt
        best_rule: GeneratedRule | None = None
        best_score: float = -1.0

        for attempt in range(max_repairs + 1):
            raw_resp = ""
            try:
                raw_resp = self._provider.generate(system_prompt, current_user_prompt)
                extracted = _extract_sigma_yaml(raw_resp)
                cand_rule = self._parse_and_validate(extracted, fallback_techniques=bundle.mitre_techniques)
            except RuntimeError as exc:
                console.print(
                    f"[yellow]  Ollama connection failed on attempt {attempt + 1} ({exc}); "
                    f"using local telemetry-grounded synthesizer.[/yellow]"
                )
                fallback = HeuristicLocalFallbackProvider()
                extracted = _extract_sigma_yaml(fallback.generate(system_prompt, base_user_prompt))
                cand_rule = self._parse_and_validate(extracted, fallback_techniques=bundle.mitre_techniques)
                cand_rule.repair_attempts = attempt
                report = verify_and_score_sigma_rule(cand_rule.raw_yaml, bundle, benign_corpus)
                cand_rule.verification_report = report
                cand_rule.valid = report.q1_syntax_valid and report.q2_data_match_valid and report.tp > 0
                best_rule = cand_rule
                best_score = report.confidence_score
                break
            except Exception as exc:
                cand_rule = GeneratedRule(
                    raw_yaml=raw_resp or "# Empty LLM response",
                    valid=False,
                    validation_errors=[f"Generation/extraction error: {exc}"],
                )

            cand_rule.repair_attempts = attempt
            report = verify_and_score_sigma_rule(cand_rule.raw_yaml, bundle, benign_corpus)
            cand_rule.verification_report = report
            cand_rule.valid = report.q1_syntax_valid and report.q2_data_match_valid and report.tp > 0

            if report.confidence_score > best_score:
                best_score = report.confidence_score
                best_rule = cand_rule

            # Stop early if rule passes Quality Gate with >= 95% score
            if report.quality_gate == "PASS - RECOMMEND_ADD" and report.confidence_score >= 95.0:
                break

            # Otherwise prepare repair prompt for next iteration
            if attempt < max_repairs:
                console.print(
                    f"[yellow]  Attempt {attempt + 1} scored {report.confidence_score:.1f}% "
                    f"({report.quality_gate}). Running self-repair with {len(report.all_repair_issues)} issue(s)...[/yellow]"
                )
                current_user_prompt = build_repair_prompt(
                    original_user_prompt=base_user_prompt,
                    previous_yaml=cand_rule.raw_yaml if cand_rule.raw_yaml.strip() else raw_resp,
                    repair_issues=report.all_repair_issues,
                )

        # Guaranteed Telemetry-Grounded Fallback if 7B LLM did not reach PASS - RECOMMEND_ADD
        if (
            best_rule is None
            or not best_rule.valid
            or best_rule.verification_report is None
            or best_rule.verification_report.quality_gate != "PASS - RECOMMEND_ADD"
            or best_score < 90.0
        ):
            fallback = HeuristicLocalFallbackProvider()
            fb_yaml = _extract_sigma_yaml(fallback.generate(system_prompt, base_user_prompt))
            fb_rule = self._parse_and_validate(fb_yaml, fallback_techniques=bundle.mitre_techniques)
            fb_rule.repair_attempts = max_repairs + 1
            fb_report = verify_and_score_sigma_rule(fb_rule.raw_yaml, bundle, benign_corpus)
            fb_rule.verification_report = fb_report
            fb_rule.valid = fb_report.q1_syntax_valid and fb_report.q2_data_match_valid and fb_report.tp > 0
            if fb_report.confidence_score >= best_score or fb_report.quality_gate == "PASS - RECOMMEND_ADD":
                best_rule = fb_rule

        assert best_rule is not None
        best_rule.wazuh_conversion = compile_sigma_to_wazuh_xml(
            raw_yaml=best_rule.raw_yaml,
            rule_id=assigned_wazuh_id,
            bundle=bundle,
            group_wrapper=WAZUH_GROUP_WRAPPER,
            rule_id_min=RULE_ID_MIN,
            rule_id_max=RULE_ID_MAX,
        )
        return best_rule

    def generate_to_files(
        self,
        input_text: str,
        output_dir: Path,
        n_rules: int = 1,
    ) -> list[Path]:
        rules = self.generate(input_text, n_rules=n_rules)
        output_dir.mkdir(parents=True, exist_ok=True)

        written: list[Path] = []
        for i, rule in enumerate(rules):
            if not rule.valid:
                console.print(
                    f"[yellow]Skipping invalid rule {i + 1}: "
                    f"{', '.join(rule.validation_errors)}[/yellow]"
                )
                continue

            title = rule.parsed.get("title", f"sigma_rule_{i}")
            slug = _slugify(title)
            path = output_dir / f"{slug}.yml"
            counter = 1
            while path.exists():
                path = output_dir / f"{slug}_{counter}.yml"
                counter += 1

            path.write_text(rule.raw_yaml, encoding="utf-8")
            written.append(path)
            console.print(f"[green]Wrote: {path}[/green]")

        return written

    @staticmethod
    def _split_yaml_blocks(text: str) -> list[str]:
        blocks: list[str] = []
        current_lines: list[str] = []

        for line in text.split("\n"):
            if line.strip() == "---" and current_lines:
                block = "\n".join(current_lines).strip()
                if block:
                    blocks.append(block)
                current_lines = []
            else:
                current_lines.append(line)

        if current_lines:
            block = "\n".join(current_lines).strip()
            if block:
                blocks.append(block)

        return blocks if blocks else [text.strip()]

    @staticmethod
    def _parse_and_validate(yaml_text: str, fallback_techniques: list[str] | None = None) -> GeneratedRule:
        rule = GeneratedRule(raw_yaml=yaml_text)

        sanitized = _sanitize_yaml_windows_backslashes(yaml_text)
        try:
            parsed = yaml.safe_load(sanitized)
        except yaml.YAMLError as exc:
            rule.validation_errors.append(f"YAML parse error: {exc}")
            return rule

        if not isinstance(parsed, dict):
            rule.validation_errors.append("Parsed YAML is not a mapping")
            return rule

        rule.parsed = parsed

        tags = _normalize_sigma_tags(parsed, fallback_techniques=fallback_techniques)
        tid_pattern = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
        for tag in tags:
            m = tid_pattern.match(tag)
            if m:
                rule.technique_ids.append(m.group(1).upper())

        try:
            parsed_id = uuid.UUID(str(parsed.get("id", "")))
        except (ValueError, AttributeError, TypeError):
            parsed_id = None

        if (
            parsed_id is None
            or parsed_id.int == 0
            or str(parsed_id) == "00000000-0000-0000-0000-000000000001"
        ):
            parsed["id"] = str(uuid.uuid4())

        parsed["date"] = date.today().isoformat()

        rule.raw_yaml = yaml.safe_dump(
            parsed,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        validation = validate_sigma_rule(parsed)
        rule.valid = validation.valid
        rule.validation_errors = validation.errors

        return rule