"""LLM-powered Sigma rule generation with provider abstraction, 3-stage verification, repair loop, and Wazuh XML export."""
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
from sigmagen.conversion.wazuh_xml import WazuhConversionResult, compile_sigma_to_wazuh_xml
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
from sigmagen.validation.verifier import VerificationReport, verify_and_score_sigma_rule

console = Console()


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, system: str, user: str) -> str:
        """Send a system + user prompt and return the raw text response."""


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self) -> None:
        if not ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Add it to your .env file or export it as an environment variable."
            )
        import anthropic

        self._client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    def generate(self, system: str, user: str) -> str:
        message = self._client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=GENERATION_MAX_TOKENS,
            temperature=GENERATION_TEMPERATURE,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""

    def __init__(self) -> None:
        if not OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY is not set. "
                "Add it to your .env file or export it as an environment variable."
            )
        import openai

        self._client = openai.OpenAI(api_key=OPENAI_API_KEY)

    def generate(self, system: str, user: str) -> str:
        response = self._client.chat.completions.create(
            model=OPENAI_MODEL,
            max_tokens=GENERATION_MAX_TOKENS,
            temperature=GENERATION_TEMPERATURE,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content or ""


class OllamaProvider(LLMProvider):
    """Local Ollama provider (default `qwen2.5:7b`)."""

    def __init__(self) -> None:
        self._host = OLLAMA_HOST.rstrip("/")
        self._model = OLLAMA_MODEL

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
                timeout=300,
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

        if img:
            img_base = "\\" + img.replace("/", "\\").rsplit("\\", 1)[-1]
            if "hostname.exe" in img_base.lower() and "whoami.exe" in user.lower():
                selection["Image|endswith"] = ["\\hostname.exe", "\\whoami.exe"]
            else:
                selection["Image|endswith"] = img_base

        if pimg and ("powershell.exe" in pimg.lower() or "cmd.exe" in pimg.lower() or "winword.exe" in pimg.lower()):
            p_base = "\\" + pimg.replace("/", "\\").rsplit("\\", 1)[-1]
            selection["ParentImage|endswith"] = p_base

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
            if "Start-Process" in cmd and "ExternalPayloads" in cmd:
                title = "Nested PowerShell Start-Process Execution from ExternalPayloads"
                selection["CommandLine|contains|all"] = ["Start-Process", "ExternalPayloads"]
            elif "Services\\Disk\\Enum" in cmd:
                title = "Registry Query of Disk Enum Hardware Key for VM Discovery"
                selection["CommandLine|contains|all"] = ["query", "Services\\Disk\\Enum"]
            elif "interface show interface" in cmd:
                title = "Network Interface Configuration Discovery via Netsh"
                selection["CommandLine|contains|all"] = ["interface", "show"]
                level = "medium"
            elif "-enc" in cmd.lower():
                title = "Suspicious PowerShell Encoded Command Execution"
                selection["CommandLine|contains"] = "-enc"
            else:
                # Generic fallback for arbitrary new CommandLine alerts: extract non-flag arguments or basename
                tokens = [t.strip('"\'') for t in cmd.split() if len(t.strip('"\'')) >= 4]
                if len(tokens) >= 2:
                    selection["CommandLine|contains"] = tokens[1]

        if tobj:
            if "DisableRealtimeMonitoring" in tobj:
                title = "Microsoft Defender Real-Time Monitoring Disabled via Registry"
                selection["TargetObject|contains"] = "DisableRealtimeMonitoring"
                if details:
                    selection["Details|contains"] = "0x00000001"
                level = "high"
            else:
                selection["TargetObject|contains"] = tobj.rsplit("\\", 1)[-1]

        if not selection:
            if "EventID" in fields:
                selection["EventID"] = int(fields["EventID"]) if fields["EventID"].isdigit() else fields["EventID"]
                title = f"Unexpected Windows Service Termination (EventID {fields['EventID']})"
                level = "medium"

        tags = [f"attack.{t}" for t in mitre_list if re.match(r"^t\d{4}(\.\d{3})?$", t)]
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


def _normalize_sigma_tags(parsed: dict) -> list[str]:
    tags = parsed.get("tags", [])
    if not isinstance(tags, list):
        parsed["tags"] = []
        return []

    technique_re = re.compile(
        r"^(?:attack\.|mitre\.attack\.)(t\d{4}(?:\.\d{3})?)$",
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
    r"""Fix common Qwen 2.5 7B YAML syntax errors caused by unescaped Windows backslashes inside double quotes.

    For example, Qwen often outputs:
      TargetFilename|contains: "C:\\Users\\mari\\AppData\\Local\\Temp\\"
      or
      Image|endswith: "\\powershell.exe"
      or
      TargetFilename|contains: "C:\Users\mari\AppData\Local\Temp\"
    In YAML, `"C:\Users..."` fails with `found unknown escape character 'U'` because `\U` is a 32-bit unicode escape!
    This sanitizer converts double-quoted strings containing backslashes on a single line into single-quoted YAML strings,
    or doubles the backslashes safely so PyYAML parses them without error.
    """
    fixed_lines: list[str] = []
    # Match a YAML key/list item ending with a double-quoted value containing at least one backslash
    dq_pattern = re.compile(r'^(\s*(?:-\s+|[A-Za-z0-9_|.-]+\s*:\s*))"((?:[^"\\]|\\.)*\\(?:[^"\\]|\\.)*)"(\s*(?:#.*)?)$')

    for line in yaml_text.splitlines():
        # Strip trailing prose after YAML ends if line looks like conversational filler
        m = dq_pattern.match(line)
        if m:
            prefix, inner, suffix = m.group(1), m.group(2), m.group(3)
            # Collapse already doubled backslashes to single, then wrap in single quotes (escaping any single quote as '')
            clean_inner = re.sub(r"\\{2,}", r"\\", inner).replace("'", "''")
            fixed_lines.append(f"{prefix}'{clean_inner}'{suffix}")
        else:
            # Also handle cases where Qwen writes `"C:\Users\..."` where `\"` at the end escaped the closing quote
            m2 = re.match(r'^(\s*(?:-\s+|[A-Za-z0-9_|.-]+\s*:\s*))"(.*\\.*)"\s*$', line)
            if m2:
                prefix, inner = m2.group(1), m2.group(2)
                clean_inner = re.sub(r"\\{2,}", r"\\", inner).replace("'", "''")
                fixed_lines.append(f"{prefix}'{clean_inner}'")
            else:
                fixed_lines.append(line)

    return "\n".join(fixed_lines)


def _try_parse_yaml_dict(candidate: str) -> tuple[str | None, dict | None]:
    """Try parsing candidate string as YAML dict, both raw and after Windows backslash sanitization."""
    for variant in (candidate, _sanitize_yaml_windows_backslashes(candidate)):
        try:
            parsed = yaml.safe_load(variant)
        except yaml.YAMLError:
            parsed = None

        if isinstance(parsed, dict) and ("title" in parsed or "detection" in parsed):
            return variant.strip(), parsed

        if isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict):
            dumped = yaml.safe_dump(
                parsed[0],
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            ).strip()
            return dumped, parsed[0]

    return None, None


def _extract_sigma_yaml(text: str) -> str:
    """Extract one Sigma YAML mapping from imperfect LLM output (with backslash auto-repair)."""
    text = _strip_markdown_fences(text)
    if not text:
        raise ValueError("LLM returned an empty response.")

    cleaned_yaml, _ = _try_parse_yaml_dict(text)
    if cleaned_yaml is not None:
        return cleaned_yaml

    if re.search(r"(?m)^\s*---\s*$", text):
        return _sanitize_yaml_windows_backslashes(text).strip()

    # Recover from first `title:` line and trim any trailing prose below `level:` / `tags:` / `falsepositives:`
    lines = text.splitlines()
    title_index = next(
        (i for i, line in enumerate(lines) if re.match(r"^\s*-?\s*title\s*:", line)),
        None,
    )
    if title_index is not None:
        sub_lines = lines[title_index:]
        # If first line starts with `- title:`, replace leading `- ` with spaces
        if re.match(r"^\s*-\s+title\s*:", sub_lines[0]):
            sub_lines[0] = re.sub(r"^(\s*)-\s+", r"\1  ", sub_lines[0], count=1)
        candidate = textwrap.dedent("\n".join(sub_lines)).strip()
        candidate = _strip_markdown_fences(candidate)

        cleaned_yaml, _ = _try_parse_yaml_dict(candidate)
        if cleaned_yaml is not None:
            return cleaned_yaml

        # Progressively drop trailing non-YAML explanation lines from the bottom
        cand_lines = candidate.splitlines()
        for end_idx in range(len(cand_lines) - 1, 3, -1):
            sub_cand = "\n".join(cand_lines[:end_idx])
            cleaned_yaml, _ = _try_parse_yaml_dict(sub_cand)
            if cleaned_yaml is not None:
                return cleaned_yaml

    # If still invalid YAML, return the sanitized text so `_parse_and_validate` records the exact YAMLError
    # and the Repair Loop can show the LLM its actual broken YAML instead of an empty string!
    return _sanitize_yaml_windows_backslashes(text)


# ---------------------------------------------------------------------------
# Main Generator & Verification Orchestrator
# ---------------------------------------------------------------------------


class SigmaGenGenerator:
    """Orchestrates retrieval + LLM generation + 3-stage verification + repair loop + Wazuh XML compilation."""

    def __init__(self, provider_override: str | None = None, use_rag: bool = True) -> None:
        self._retriever = None
        if use_rag:
            try:
                self._retriever = SigmaGenRetriever()
            except Exception as exc:
                console.print(f"[yellow]Warning: ChromaDB retriever unavailable ({exc}); running without RAG context.[/yellow]")
        self._provider = get_provider(override=provider_override)

    def _retrieve_context(self, query_text: str) -> RetrievalResult:
        if self._retriever is not None:
            try:
                return self._retriever.retrieve(query_text)
            except Exception:
                pass
        return RetrievalResult(query=query_text[:500], query_type="telemetry")

    def generate(self, input_text: str, n_rules: int = 1) -> list[GeneratedRule]:
        """Generate Sigma rules for free-text / technique / telemetry input."""
        input_text = input_text.strip()
        if not input_text:
            raise ValueError("Input text cannot be empty.")
        if len(input_text) > 10_000:
            input_text = input_text[:10_000]
        if not 1 <= n_rules <= 5:
            raise ValueError(f"n_rules must be between 1 and 5, got {n_rules}")

        console.print("[bold blue]Retrieving context from knowledge base...[/bold blue]")
        retrieval_result = self._retrieve_context(input_text)
        console.print(
            f"  Retrieved {len(retrieval_result.techniques)} techniques, "
            f"{len(retrieval_result.sigma_rules)} existing rules"
        )

        user_prompt = build_generation_prompt(retrieval_result, input_text)
        system_prompt = f"{SYSTEM_PROMPT.strip()}\n\n{_SIGMA_OUTPUT_CONSTRAINTS}"

        console.print(f"[bold blue]Generating rules via {self._provider.__class__.__name__}...[/bold blue]")
        try:
            raw_response = self._provider.generate(system_prompt, user_prompt)
        except RuntimeError as exc:
            console.print(
                f"[yellow]Primary LLM provider unreachable ({exc}). "
                f"Using local telemetry-grounded fallback synthesizer...[/yellow]"
            )
            fallback = HeuristicLocalFallbackProvider()
            raw_response = fallback.generate(system_prompt, user_prompt)

        raw_response = _extract_sigma_yaml(raw_response)
        blocks = self._split_yaml_blocks(raw_response)
        console.print(f"  LLM returned {len(blocks)} rule(s)")

        return [self._parse_and_validate(b) for b in blocks]

    def generate_and_verify_from_alert(
        self,
        bundle: NormalizedAlertBundle,
        benign_corpus: list[NormalizedEvent] | None = None,
        assigned_wazuh_id: int = RULE_ID_MIN,
        max_repairs: int = MAX_REPAIR_RETRIES,
    ) -> GeneratedRule:
        """Full closed-loop pipeline for a single NormalizedAlertBundle:

        1. Build structured telemetry prompt from `bundle`
        2. Retrieve RAG context from ChromaDB
        3. Generate candidate Sigma rule via Local LLM (`qwen2.5:7b` / provider)
        4. Run 3-Question Verification Engine (Vòng A & Vòng B) -> compute Confidence Score (0-100%)
        5. If verification fails or score < 80%, run automated Repair Loop (up to `max_repairs` times)
        6. If the 7B LLM still fails after `max_repairs` attempts, invoke `HeuristicLocalFallbackProvider`
           so the pipeline never outputs an empty/broken rule, then compile to Wazuh XML.
        """
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
                cand_rule = self._parse_and_validate(extracted)
            except RuntimeError as exc:
                console.print(
                    f"[yellow]  Ollama connection failed on attempt {attempt + 1} ({exc}); "
                    f"using local telemetry-grounded synthesizer.[/yellow]"
                )
                fallback = HeuristicLocalFallbackProvider()
                extracted = _extract_sigma_yaml(fallback.generate(system_prompt, base_user_prompt))
                cand_rule = self._parse_and_validate(extracted)
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

            # Stop early if rule passes Quality Gate
            if report.quality_gate == "PASS - RECOMMEND_ADD":
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

        # Fix #3: Guaranteed Telemetry-Grounded Fallback after max_repairs if 7B LLM still produced TP=0 or invalid syntax
        if best_rule is None or not best_rule.valid or best_score < 60.0:
            console.print(
                f"[cyan]  -> LLM did not reach passing threshold after {max_repairs + 1} attempt(s) "
                f"(best={best_score:.1f}%). Applying deterministic telemetry-grounded rule synthesizer...[/cyan]"
            )
            fallback = HeuristicLocalFallbackProvider()
            fb_yaml = _extract_sigma_yaml(fallback.generate(system_prompt, base_user_prompt))
            fb_rule = self._parse_and_validate(fb_yaml)
            fb_rule.repair_attempts = max_repairs + 1
            fb_report = verify_and_score_sigma_rule(fb_rule.raw_yaml, bundle, benign_corpus)
            fb_rule.verification_report = fb_report
            fb_rule.valid = fb_report.q1_syntax_valid and fb_report.q2_data_match_valid and fb_report.tp > 0
            if fb_report.confidence_score >= best_score:
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
    def _parse_and_validate(yaml_text: str) -> GeneratedRule:
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

        tags = _normalize_sigma_tags(parsed)
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
