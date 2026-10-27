"""Click CLI for SigmaGen — supports Technique, Description, Telemetry, Alert JSON (`-a`), Auto-ID Allocation, Auto-Watch (`watch`), and Web Dashboard (`serve`)."""
from __future__ import annotations

import json
import re as _re
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()

_technique_id_cache: list[str] | None = None


def _load_technique_ids() -> list[str]:
    global _technique_id_cache
    if _technique_id_cache is not None:
        return _technique_id_cache

    try:
        from sigmagen.config import ATTACK_COLLECTION
        from sigmagen.embeddings.pipeline import get_collection

        col = get_collection(ATTACK_COLLECTION)
        result = col.get(include=["metadatas"])
        ids = sorted({m["technique_id"] for m in result["metadatas"] if "technique_id" in m})
        _technique_id_cache = ids
    except Exception:
        _technique_id_cache = []
    return _technique_id_cache


class TechniqueType(click.ParamType):
    name = "technique_id"

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ) -> list[click.shell_completion.CompletionItem]:
        from click.shell_completion import CompletionItem

        prefix = incomplete.upper()
        return [
            CompletionItem(tid)
            for tid in _load_technique_ids()
            if tid.startswith(prefix)
        ]


TECHNIQUE = TechniqueType()


def _slugify(text: str) -> str:
    slug = _re.sub(r"[^\w\s-]", "", text.lower())
    slug = _re.sub(r"[\s_]+", "_", slug).strip("_")
    return slug[:80] or "sigma_rule"


def _check_api_key(provider_override: str | None = None) -> tuple[bool, str, str]:
    from sigmagen.config import (
        ANTHROPIC_API_KEY,
        LLM_PROVIDER,
        OLLAMA_HOST,
        OPENAI_API_KEY,
    )

    provider = (provider_override or LLM_PROVIDER).lower()
    if provider in ("ollama", "local_fallback", "mock", "heuristic"):
        return bool(OLLAMA_HOST), provider, "OLLAMA_HOST"
    if provider == "openai":
        return bool(OPENAI_API_KEY), "openai", "OPENAI_API_KEY"
    if provider == "anthropic":
        return bool(ANTHROPIC_API_KEY), "anthropic", "ANTHROPIC_API_KEY"
    return False, provider, "LLM_PROVIDER"


def _read_telemetry_file(path_str: str) -> str:
    p = Path(path_str)
    if not p.exists():
        console.print(f"[bold red]x File not found:[/bold red] {path_str}")
        sys.exit(1)
    if not p.is_file():
        console.print(f"[bold red]x Not a file:[/bold red] {path_str}")
        sys.exit(1)
    try:
        raw_text = p.read_text(encoding="utf-8-sig")
    except Exception as exc:
        console.print(f"[bold red]x[/bold red] Cannot read file: {exc}")
        sys.exit(1)

    if not raw_text.strip():
        console.print(f"[bold red]x[/bold red] File is empty: {path_str}")
        sys.exit(1)

    if p.suffix.lower() == ".json":
        try:
            from sigmagen.ingestion.alert_adapter import load_alert_bundles

            bundles = load_alert_bundles(p, deduplicate_tokens=True)
            if bundles:
                console.print(
                    f"[cyan]i Auto-detected structured AI Alert JSON in -T ({len(bundles)} unique alert pattern(s)). "
                    f"Using normalized telemetry adapter.[/cyan]"
                )
                return bundles[0].build_llm_prompt_input()
        except Exception:
            pass

    return raw_text[:8000]


def _print_verification_table(report) -> None:
    """Render a Rich summary table of the 3-Stage Verification Report + Vòng A/B Metrics."""
    table = Table(title=f"Kết quả Kiểm chứng Sigma Rule — Alert: {report.alert_id}", show_lines=True)
    table.add_column("Tiêu chí / Câu hỏi kiểm chứng", style="bold white", width=38)
    table.add_column("Trạng thái", justify="center", width=14)
    table.add_column("Điểm / Chỉ số", justify="right", style="cyan", width=18)
    table.add_column("Chi tiết đánh giá", style="white")

    q1_badge = "[green]PASS[/green]" if report.q1_syntax_valid else "[red]FAIL[/red]"
    q1_detail = "; ".join(report.q1_errors or report.q1_warnings) or "Đạt chuẩn schema Sigma YAML, UUID, condition & MITRE tags"
    table.add_row("1) Cú pháp & Schema (Trọng số 20%)", q1_badge, f"{report.q1_syntax_score:.1f} / 100", q1_detail)

    q2_badge = "[green]PASS[/green]" if report.q2_data_match_valid else "[red]FAIL[/red]"
    q2_items = [
        f"Logsource={report.q2_logsource_matched}",
        f"Non-null Fields={report.q2_all_fields_present_in_event}",
        f"MITRE Linked={report.q2_mitre_linked}",
    ]
    if report.q2_errors:
        q2_items.extend(report.q2_errors)
    if report.q2_overfit_warnings:
        q2_items.extend(report.q2_overfit_warnings)
    table.add_row("2) Khớp dữ liệu & Liên kết Alert (30%)", q2_badge, f"{report.q2_data_linkage_score:.1f} / 100", "; ".join(q2_items))

    q3_badge = "[green]PASS[/green]" if report.q3_behavior_valid else ("[yellow]WARN[/yellow]" if report.tp > 0 else "[red]FAIL[/red]")
    q3_metrics = (
        f"TP={report.tp} | FP={report.fp} | FN={report.fn} | TN={report.tn}\n"
        f"Precision={report.precision:.2f} | Recall={report.recall:.2f} | F1={report.f1_score:.2f}\n"
        f"Generalization={report.generalization_hits}/{report.generalization_total} ({report.generalization_rate:.0%}) | FPR={report.false_positive_rate:.2%}"
    )
    if report.q3_errors:
        q3_metrics += "\nLỗi: " + "; ".join(report.q3_errors)
    table.add_row("3) Phát hiện hành vi Vòng A & B (50%)", q3_badge, f"{report.q3_behavior_score:.1f} / 100", q3_metrics)

    gate_color = "green" if "PASS" in report.quality_gate else ("yellow" if "WARN" in report.quality_gate else "red")
    table.add_row(
        "[bold]TỔNG ĐIỂM TIN CẬY (CONFIDENCE SCORE)[/bold]",
        f"[bold {gate_color}]{report.quality_gate}[/bold {gate_color}]",
        f"[bold {gate_color}]{report.confidence_score:.1f}%[/bold {gate_color}]",
        report.recommendation_reason,
    )
    console.print(table)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="sigmagen")
def cli() -> None:
    """SigmaGen — AI-powered Sigma rule generator, verifier & SOC Web Dashboard."""


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

_TECHNIQUE_ID_RE = _re.compile(r"^T\d{4}(\.\d{3})?$", _re.IGNORECASE)


def _validate_technique_id(value: str) -> str:
    tid = value.strip().upper()
    if not _TECHNIQUE_ID_RE.match(tid):
        console.print(
            f"[bold red]x[/bold red] '{value}' is not a valid ATT&CK technique ID.\n"
            f"  Expected format: T1059 or T1059.001"
        )
        sys.exit(1)
    return tid


@cli.command()
@click.option("--technique", "-t", default=None, type=TECHNIQUE, help="ATT&CK technique ID (e.g. T1059.001).")
@click.option("--telemetry", "-T", default=None, help="Path to a log/telemetry file (or AI alert JSON).")
@click.option("--description", "-d", default=None, help="Free-text attack description.")
@click.option(
    "--alert-json",
    "-a",
    default=None,
    type=click.Path(exists=True),
    help="Path to AI Alert JSON (1 alert or multi-alert JSON) for automatic rule generation, verification & Wazuh XML export.",
)
@click.option(
    "--evidence-json",
    "-e",
    default=None,
    type=click.Path(exists=True),
    help="Optional path to accompanying evidence JSON (auto-discovered if omitted).",
)
@click.option(
    "--background-json",
    "-b",
    multiple=True,
    type=click.Path(exists=True),
    help="Optional path(s) to benign/background Wazuh logs for False Positive evaluation in Vòng B.",
)
@click.option(
    "--deduplicate-alerts/--all-alerts",
    default=True,
    help="When processing a multi-alert file, group identical token patterns to avoid redundant LLM calls.",
)
@click.option(
    "--rule-id-start",
    type=int,
    default=None,
    help="Optional starting Wazuh XML rule ID. If omitted, SigmaGen automatically allocates the next available ID in 100100-109999!",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./output/new_rules",
    help="Directory to write generated Sigma (.yml), Wazuh (.xml), and verification report (.eval.json) files.",
)
@click.option("--n-rules", "-n", type=int, default=1, help="Number of rules to generate (1-5).")
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["anthropic", "openai", "ollama", "local_fallback"], case_sensitive=False),
    default=None,
    help="Override the LLM provider for this run.",
)
def generate(
    technique: str | None,
    telemetry: str | None,
    description: str | None,
    alert_json: str | None,
    evidence_json: str | None,
    background_json: tuple[str, ...],
    deduplicate_alerts: bool,
    rule_id_start: int | None,
    output: str,
    n_rules: int,
    provider: str | None,
) -> None:
    """Generate Sigma detection rules, run 3-stage verification (Vòng A & B), and compile to Wazuh XML with automatic Rule ID allocation."""
    from sigmagen.conversion.wazuh_xml import (
        allocate_next_wazuh_rule_id,
        register_generated_rule_metadata,
    )
    from sigmagen.generation.generator import SigmaGenGenerator
    from sigmagen.ingestion.alert_adapter import (
        load_alert_bundles,
        load_benign_background_events,
    )

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Path 1: Full Alert JSON closed-loop pipeline (`-a / --alert-json`)
    if alert_json is not None:
        alert_p = Path(alert_json)
        ev_p = Path(evidence_json) if evidence_json else None
        bg_paths = [Path(x) for x in background_json]
        if ev_p and ev_p.exists() and ev_p not in bg_paths:
            bg_paths.append(ev_p)

        bundles = load_alert_bundles(alert_p, ev_p, deduplicate_tokens=deduplicate_alerts)
        benign_corpus = load_benign_background_events(bg_paths)

        console.rule("[bold blue]SigmaGen Closed-Loop Alert -> Sigma (.yml) -> Verify (Vòng A/B) -> Wazuh (.xml)[/bold blue]")
        console.print(
            f"  Loaded [cyan]{len(bundles)}[/cyan] alert bundle(s) from [white]{alert_p.name}[/white] "
            f"| Benign background corpus: [cyan]{len(benign_corpus)}[/cyan] events"
        )

        generator = SigmaGenGenerator(provider_override=provider)
        summary_rows = []

        for idx, bundle in enumerate(bundles):
            if rule_id_start is not None:
                assigned_id = rule_id_start + idx
            else:
                assigned_id = allocate_next_wazuh_rule_id(output_dir, alert_id=bundle.alert_id)

            console.rule(f"[bold]Alert {idx + 1}/{len(bundles)}: {bundle.alert_id} (Auto Wazuh Rule ID: {assigned_id})[/bold]")
            rule = generator.generate_and_verify_from_alert(
                bundle=bundle,
                benign_corpus=benign_corpus,
                assigned_wazuh_id=assigned_id,
            )

            console.print(Syntax(rule.raw_yaml, "yaml", theme="monokai", line_numbers=True))

            if rule.verification_report:
                _print_verification_table(rule.verification_report)

            if rule.wazuh_conversion and rule.wazuh_conversion.wazuh_xml:
                console.print("\n[bold cyan]Compiled Wazuh XML Rule:[/bold cyan]")
                console.print(Syntax(rule.wazuh_conversion.wazuh_xml, "xml", theme="monokai", line_numbers=True))

            slug = _slugify(f"{bundle.alert_id}_{rule.parsed.get('title', 'rule')}")
            yml_path = output_dir / f"{slug}.yml"
            xml_path = output_dir / f"ml_generated_{assigned_id}.xml"
            eval_path = output_dir / f"{slug}.eval.json"

            yml_path.write_text(rule.raw_yaml, encoding="utf-8")
            if rule.wazuh_conversion:
                xml_path.write_text(rule.wazuh_conversion.wazuh_xml, encoding="utf-8")
            if rule.verification_report:
                payload = {
                    "verification_report": rule.verification_report.to_dict(),
                    "wazuh_xml_valid": rule.wazuh_conversion.xml_valid if rule.wazuh_conversion else False,
                    "wazuh_rule_id": assigned_id,
                    "wazuh_xml_file": xml_path.name,
                    "sigma_yaml_file": yml_path.name,
                    "repair_attempts": rule.repair_attempts,
                }
                eval_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                row = payload["verification_report"] | {
                    "wazuh_rule_id": assigned_id,
                    "sigma_yaml_file": yml_path.name,
                    "wazuh_xml_file": xml_path.name,
                }
                summary_rows.append(row)
                register_generated_rule_metadata(output_dir, row)

        batch_report_path = output_dir / "batch_verification_summary.json"
        batch_report_path.write_text(json.dumps(summary_rows, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"\n[bold green]v Saved all Sigma (.yml), Wazuh (.xml), and Evaluation (.eval.json) files to:[/bold green] {output_dir}")
        return

    # Path 2: Legacy CLI flags (`-t`, `-T`, `-d`)
    inputs = [x for x in (technique, telemetry, description) if x is not None]
    if len(inputs) != 1:
        console.print(
            "[bold red]x[/bold red] Provide either --alert-json (-a) OR exactly one of "
            "--technique (-t), --telemetry (-T), or --description (-d)."
        )
        sys.exit(1)

    if technique:
        input_text = _validate_technique_id(technique)
    elif telemetry:
        input_text = _read_telemetry_file(telemetry)
    else:
        input_text = description or ""

    generator = SigmaGenGenerator(provider_override=provider)
    rules = generator.generate(input_text, n_rules=n_rules)

    for i, rule in enumerate(rules, 1):
        console.rule(f"[bold]Rule {i}[/bold]")
        console.print(Syntax(rule.raw_yaml, "yaml", theme="monokai", line_numbers=True))
        title = rule.parsed.get("title", f"sigma_rule_{i}")
        slug = _slugify(title)
        filepath = output_dir / f"{slug}.yml"
        filepath.write_text(rule.raw_yaml, encoding="utf-8")
        console.print(f"[green]Saved: {filepath}[/green]")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _auto_resolve_bundle_for_yaml(yaml_path: Path, yaml_text: str, bundles: list, alert_index: int | None):
    if alert_index is not None:
        idx = max(0, min(alert_index, len(bundles) - 1))
        return bundles[idx]

    stem_norm = _re.sub(r"[^a-z0-9]", "", yaml_path.stem.lower())
    text_norm = _re.sub(r"[^a-z0-9]", "", yaml_text.lower())

    for b in bundles:
        aid_norm = _re.sub(r"[^a-z0-9]", "", b.alert_id.lower())
        if aid_norm and (aid_norm in stem_norm or stem_norm.startswith(aid_norm) or aid_norm in text_norm):
            console.print(f"[cyan]i Auto-matched YAML file '{yaml_path.name}' to Alert ID '{b.alert_id}'[/cyan]")
            return b

    return bundles[0]


@cli.command("verify")
@click.argument("yaml_path", type=click.Path(exists=True))
@click.option("--alert-json", "-a", required=True, type=click.Path(exists=True), help="Path to the AI Alert JSON to verify against.")
@click.option("--evidence-json", "-e", default=None, type=click.Path(exists=True), help="Optional path to evidence JSON.")
@click.option("--alert-index", type=int, default=None, help="Optional index of the alert in multi-alert JSON.")
@click.option("--rule-id", type=int, default=None, help="Wazuh Rule ID (auto-allocated in 100100-109999 if omitted).")
@click.option("--output-xml", "-x", default=None, type=click.Path(), help="Optional path to save the compiled Wazuh XML rule.")
def verify_cmd(
    yaml_path: str,
    alert_json: str,
    evidence_json: str | None,
    alert_index: int | None,
    rule_id: int | None,
    output_xml: str | None,
) -> None:
    """Verify an existing Sigma YAML rule against an Alert JSON (3 Questions + Vòng A/B Score + Wazuh XML)."""
    from sigmagen.conversion.wazuh_xml import (
        allocate_next_wazuh_rule_id,
        compile_sigma_to_wazuh_xml,
    )
    from sigmagen.ingestion.alert_adapter import (
        load_alert_bundles,
        load_benign_background_events,
    )
    from sigmagen.validation.verifier import verify_and_score_sigma_rule

    yml_p = Path(yaml_path)
    yml_text = yml_p.read_text(encoding="utf-8-sig")
    ev_p = Path(evidence_json) if evidence_json else None
    bundles = load_alert_bundles(Path(alert_json), ev_p, deduplicate_tokens=False)
    if not bundles:
        console.print("[bold red]x No alerts found in alert JSON.[/bold red]")
        sys.exit(1)

    bundle = _auto_resolve_bundle_for_yaml(yml_p, yml_text, bundles, alert_index)
    bg_paths = [ev_p] if (ev_p and ev_p.exists()) else []
    benign_corpus = load_benign_background_events(bg_paths)

    report = verify_and_score_sigma_rule(yml_text, bundle, benign_corpus)
    _print_verification_table(report)

    assigned_id = rule_id if rule_id is not None else allocate_next_wazuh_rule_id(yml_p.parent, alert_id=bundle.alert_id)
    conv = compile_sigma_to_wazuh_xml(yml_text, rule_id=assigned_id, bundle=bundle)
    if conv.wazuh_xml:
        console.print(f"\n[bold cyan]Compiled Wazuh XML Rule (Auto ID: {assigned_id}):[/bold cyan]")
        console.print(Syntax(conv.wazuh_xml, "xml", theme="monokai", line_numbers=True))
        if output_xml:
            Path(output_xml).write_text(conv.wazuh_xml, encoding="utf-8")
            console.print(f"[green]Saved Wazuh XML to {output_xml}[/green]")


# ---------------------------------------------------------------------------
# watch (Full Auto-Watch Daemon for ./alert directory)
# ---------------------------------------------------------------------------


@cli.command("watch")
@click.option("--alert-dir", default="./alert", type=click.Path(), help="Directory to watch for incoming alert JSON files.")
@click.option("--output", "-o", default="./output/new_rules", type=click.Path(), help="Directory to write generated rules.")
@click.option("--interval", default=5, type=int, help="Polling interval in seconds (set 0 for single pass).")
@click.option("--deduplicate/--all-alerts", default=True, help="Deduplicate identical behavior tokens in multi-alert files.")
def watch_cmd(alert_dir: str, output: str, interval: int, deduplicate: bool) -> None:
    """Automatically watch `--alert-dir` for new alert/evidence files, allocate Rule IDs, generate, verify & save rules."""
    from sigmagen.api.app import _process_bundle_to_dashboard_item
    from sigmagen.generation.generator import SigmaGenGenerator
    from sigmagen.ingestion.alert_adapter import (
        load_alert_bundles,
        load_benign_background_events,
    )

    a_dir = Path(alert_dir)
    out_dir = Path(output)
    a_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    processed_mtimes: dict[str, float] = {}
    generator = SigmaGenGenerator()
    benign_corpus = load_benign_background_events()

    console.print(
        Panel(
            f"[bold green]SigmaGen Auto-Watch Daemon Active[/bold green]\n"
            f"  Watching folder : [cyan]{a_dir.resolve()}[/cyan]\n"
            f"  Output folder   : [cyan]{out_dir.resolve()}[/cyan]\n"
            f"  Auto Rule IDs   : [amber]100100 - 109999[/amber]",
            expand=False,
        )
    )

    while True:
        alert_files = sorted(
            p for p in a_dir.glob("*.json")
            if not p.name.endswith("_evidence.json")
            and p.name not in ("ai_alert_evidence_test.json", "evidence.json")
        )
        for af in alert_files:
            mtime = af.stat().st_mtime
            key = str(af.resolve())
            if processed_mtimes.get(key) == mtime:
                continue
            processed_mtimes[key] = mtime
            try:
                bundles = load_alert_bundles(af, evidence_path=None, deduplicate_tokens=deduplicate)
                console.print(f"[cyan]-> Auto-detected '{af.name}' ({len(bundles)} alert bundle(s))[/cyan]")
                for b in bundles:
                    item = _process_bundle_to_dashboard_item(b, generator, benign_corpus, out_dir)
                    console.print(
                        f"   [green]v[/green] Alert [bold]{b.alert_id}[/bold] -> Wazuh ID [bold yellow]#{item['wazuh_rule_id']}[/bold yellow] "
                        f"| Score: [bold]{item['report']['confidence_score']}%[/bold] ({item['report']['quality_gate']})"
                    )
            except Exception as exc:
                console.print(f"[yellow]! Skipped {af.name}: {exc}[/yellow]")

        if interval <= 0:
            break
        time.sleep(interval)


# ---------------------------------------------------------------------------
# serve (Web Dashboard + REST API)
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
@click.option("--port", default=8000, type=int, help="Port to listen on (default: 8000).")
def serve(host: str, port: int) -> None:
    """Start the SigmaGen SOC Web Dashboard & REST API server."""
    import uvicorn

    console.print(
        Panel(
            f"[bold green]SigmaGen SOC Web Dashboard & Auto-Rule Server[/bold green]\n\n"
            f"  Mở trình duyệt tại : [bold cyan]http://localhost:{port}[/bold cyan]\n"
            f"  Swagger API Docs   : [dim]http://localhost:{port}/docs[/dim]",
            expand=False,
        )
    )
    uvicorn.run("sigmagen.api.app:app", host=host, port=port, reload=False)


# ---------------------------------------------------------------------------
# validate (Static schema check)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("yaml_path", type=click.Path(exists=True))
def validate(yaml_path: str) -> None:
    """Validate a Sigma YAML rule file (static schema check)."""
    from sigmagen.validation.validator import validate_sigma_yaml, validate_with_sigma_cli

    path = Path(yaml_path)
    text = path.read_text(encoding="utf-8-sig")
    console.rule(f"[bold blue]Validating {path.name}[/bold blue]")

    result = validate_sigma_yaml(text)
    cli_result = validate_with_sigma_cli(path)
    result.merge(cli_result)

    if result.errors:
        console.print("[bold red]ERRORS:[/bold red]")
        for err in result.errors:
            console.print(f"  [red]- {err}[/red]")

    if result.warnings:
        console.print("[bold yellow]WARNINGS:[/bold yellow]")
        for warn in result.warnings:
            console.print(f"  [yellow]- {warn}[/yellow]")

    if result.valid and not result.errors:
        console.print("[bold green]Validation PASSED[/bold green]")
    else:
        console.print("[bold red]Validation FAILED[/bold red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@cli.command()
def status() -> None:
    """Show knowledge base status and configuration at a glance."""
    from sigmagen import __version__
    from sigmagen.config import ANTHROPIC_MODEL, EMBEDDING_MODEL, LLM_PROVIDER, OLLAMA_MODEL, OPENAI_MODEL
    from sigmagen.embeddings.pipeline import get_collection_stats

    console.print(f"\n[bold]SigmaGen[/bold] v{__version__}")
    console.rule()

    stats = get_collection_stats()
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Knowledge Base", style="white")
    table.add_column("Documents", justify="right", style="cyan")
    table.add_column("Status", style="bold")

    for name, count in stats.items():
        mark = "[green]v Ready[/green]" if count > 0 else "[red]x Empty[/red]"
        table.add_row(name, str(count), mark)

    console.print(table)
    console.print()

    key_set, provider, _ = _check_api_key()
    model = OLLAMA_MODEL if provider == "ollama" else (ANTHROPIC_MODEL if provider == "anthropic" else OPENAI_MODEL)
    key_mark = "[green]v Set[/green]" if key_set else "[red]x NOT SET[/red]"

    config_table = Table(show_header=False, box=None, pad_edge=False)
    config_table.add_column("Key", style="dim")
    config_table.add_column("Value")
    config_table.add_row("LLM Provider", f"[cyan]{provider}[/cyan]")
    config_table.add_row("API Key / Host", key_mark)
    config_table.add_row("Model", f"[cyan]{model}[/cyan]")
    config_table.add_row("Embedding Model", f"[cyan]{EMBEDDING_MODEL}[/cyan]")
    console.print(config_table)
    console.rule()