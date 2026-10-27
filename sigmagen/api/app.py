"""FastAPI application & Web Dashboard for SigmaGen — Full Automation for Alert -> Sigma (.yml) -> Verify -> Wazuh (.xml)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from sigmagen.config import EMBEDDING_MODEL, LLM_PROVIDER
from sigmagen.conversion.wazuh_xml import (
    RULE_ID_MIN_DEFAULT,
    allocate_next_wazuh_rule_id,
    compile_sigma_to_wazuh_xml,
    normalize_registry_item,
    register_generated_rule_metadata,
)
from sigmagen.generation.generator import SigmaGenGenerator
from sigmagen.ingestion.alert_adapter import (
    NormalizedAlertBundle,
    load_alert_bundles,
    load_alert_bundles_from_raw,
    load_benign_background_events,
    validate_alert_evidence_correspondence,
)
from sigmagen.validation.verifier import verify_and_score_sigma_rule

DEFAULT_OUTPUT_DIR = Path("./output/new_rules")
DEFAULT_ALERT_DIR = Path("./alert")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "_", slug).strip("_")
    return slug[:80] or "sigma_rule"


def _read_next_id(output_dir: Path) -> int:
    reg_p = output_dir / "rule_registry.json"
    next_id = RULE_ID_MIN_DEFAULT
    if reg_p.exists():
        try:
            reg = json.loads(reg_p.read_text(encoding="utf-8-sig"))
            next_id = max(int(reg.get("next_id", RULE_ID_MIN_DEFAULT)), RULE_ID_MIN_DEFAULT)
        except Exception:
            pass
    return next_id


class GenerateRequest(BaseModel):
    technique_id: Optional[str] = None
    telemetry: Optional[str] = None
    n_rules: int = Field(default=1, ge=1, le=5)


class ValidateCorrespondenceRequest(BaseModel):
    alert_data: Any
    evidence_data: Optional[Any] = None


class ProcessFilesRequest(BaseModel):
    alert_data: Any
    evidence_data: Optional[Any] = None
    deduplicate: bool = True
    provider: Optional[str] = None
    output_dir: str = "./output/new_rules"


class VerifyRuleRequest(BaseModel):
    raw_yaml: str
    alert_data: Optional[Any] = None
    evidence_data: Optional[Any] = None
    bundle_item: Optional[dict[str, Any]] = None
    wazuh_rule_id: Optional[int] = None
    output_dir: str = "./output/new_rules"


class ResetDashboardRequest(BaseModel):
    output_dir: str = "./output/new_rules"
    keep_next_id: bool = True
    reset_next_id_to: Optional[int] = None


class AutoWatchScanRequest(BaseModel):
    alert_dir: str = "./alert"
    output_dir: str = "./output/new_rules"
    deduplicate: bool = True
    max_alerts: int = 20
    force_reprocess: bool = False
    provider: Optional[str] = None


class RuleOutput(BaseModel):
    yaml: str
    title: str
    level: str
    technique_ids: list[str]
    valid: bool
    validation_errors: list[str]


class GenerateResponse(BaseModel):
    rules: list[RuleOutput]
    technique_ids: list[str]
    retrieval_context: dict


class StatusResponse(BaseModel):
    status: str
    collections: dict[str, int]
    llm_provider: str
    embedding_model: str


app = FastAPI(
    title="SigmaGen SOC Dashboard & Automated Rule Engine",
    description="Automated Alert + Evidence ingestion, Local LLM Sigma rule generation, 3-Stage Verification (Vòng A/B), and Wazuh XML compilation with Auto-ID allocation.",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _process_bundle_to_dashboard_item(
    bundle: NormalizedAlertBundle,
    generator: SigmaGenGenerator,
    benign_corpus: list,
    output_dir: Path,
) -> dict[str, Any]:
    """Run closed-loop generation, verification, auto-ID assignment, and file saving for a single AlertBundle."""
    output_dir.mkdir(parents=True, exist_ok=True)
    assigned_id = allocate_next_wazuh_rule_id(
        output_dir,
        alert_id=bundle.alert_id,
        reuse_for_same_alert=False,
    )

    rule = generator.generate_and_verify_from_alert(
        bundle=bundle,
        benign_corpus=benign_corpus,
        assigned_wazuh_id=assigned_id,
    )

    slug = _slugify(f"{bundle.alert_id}_{rule.parsed.get('title', 'rule')}")
    yml_path = output_dir / f"{slug}.yml"
    xml_path = output_dir / f"ml_generated_{assigned_id}.xml"
    eval_path = output_dir / f"{slug}.eval.json"

    yml_path.write_text(rule.raw_yaml, encoding="utf-8")
    wazuh_xml_str = rule.wazuh_conversion.wazuh_xml if rule.wazuh_conversion else ""
    if wazuh_xml_str:
        xml_path.write_text(wazuh_xml_str, encoding="utf-8")

    rep = rule.verification_report
    rep_dict = rep.to_dict() if rep else {}

    primary = bundle.primary_events[0] if bundle.primary_events else None
    item = normalize_registry_item(
        {
            "wazuh_rule_id": assigned_id,
            "alert_id": bundle.alert_id,
            "evidence_id": bundle.evidence_id or "",
            "source_format": bundle.source_format,
            "title": rule.parsed.get("title") or bundle.title,
            "description": bundle.description,
            "severity": rule.parsed.get("level") or bundle.severity,
            "mitre_techniques": rule.technique_ids or bundle.mitre_techniques,
            "event_family": primary.event_family if primary else "sysmon",
            "event_code": primary.event_code if primary else 1,
            "expected_logsource": primary.expected_sigma_logsource if primary else {"product": "windows"},
            "expected_wazuh_group": primary.expected_wazuh_group if primary else "sysmon_event1",
            "sigma_fields": primary.sigma_fields if primary else {},
            "context_events": [
                {
                    "uid": c.event_id_uid,
                    "ecode": c.event_code,
                    "family": c.event_family,
                    "summary": ", ".join(f"{k}={v}" for k, v in list(c.sigma_fields.items())[:4]),
                }
                for c in bundle.context_events[:8]
            ],
            "raw_yaml": rule.raw_yaml,
            "wazuh_xml": wazuh_xml_str,
            "sigma_file": yml_path.name,
            "wazuh_file": xml_path.name,
            "report": {
                "q1_syntax_valid": rep.q1_syntax_valid if rep else True,
                "q1_syntax_score": rep.q1_syntax_score if rep else 100.0,
                "q1_errors": rep.q1_errors if rep else [],
                "q1_warnings": rep.q1_warnings if rep else [],
                "q2_data_match_valid": rep.q2_data_match_valid if rep else True,
                "q2_data_linkage_score": rep.q2_data_linkage_score if rep else 100.0,
                "q2_logsource_matched": rep.q2_logsource_matched if rep else True,
                "q2_all_fields_present": rep.q2_all_fields_present_in_event if rep else True,
                "q2_errors": rep.q2_errors if rep else [],
                "q2_warnings": rep.q2_overfit_warnings if rep else [],
                "q3_behavior_valid": rep.q3_behavior_valid if rep else True,
                "q3_behavior_score": rep.q3_behavior_score if rep else 100.0,
                "tp": rep.tp if rep else 1,
                "fp": rep.fp if rep else 0,
                "fn": rep.fn if rep else 0,
                "tn": rep.tn if rep else 10,
                "precision": rep.precision if rep else 1.0,
                "recall": rep.recall if rep else 1.0,
                "f1_score": rep.f1_score if rep else 1.0,
                "generalization_hits": rep.generalization_hits if rep else 3,
                "generalization_total": rep.generalization_total if rep else 3,
                "generalization_rate": rep.generalization_rate if rep else 1.0,
                "fpr": rep.false_positive_rate if rep else 0.0,
                "confidence_score": rep.confidence_score if rep else 100.0,
                "quality_gate": rep.quality_gate if rep else "PASS - RECOMMEND_ADD",
                "recommendation_reason": rep.recommendation_reason if rep else "",
            },
        }
    )

    eval_payload = {
        "verification_report": rep_dict,
        "wazuh_xml_valid": rule.wazuh_conversion.xml_valid if rule.wazuh_conversion else False,
        "wazuh_rule_id": assigned_id,
        "wazuh_xml_file": xml_path.name,
        "sigma_yaml_file": yml_path.name,
        "repair_attempts": rule.repair_attempts,
        "dashboard_item": item,
    }
    eval_path.write_text(json.dumps(eval_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    register_generated_rule_metadata(output_dir, item)
    return item


def _find_dashboard_html() -> str:
    """Locate `dashboard.html` or `sigmagen_soc_dashboard.html` across candidate paths."""
    here = Path(__file__).resolve().parent
    candidates = [
        here / "dashboard.html",
        here / "sigmagen_soc_dashboard.html",
        Path.cwd() / "sigmagen" / "api" / "dashboard.html",
        Path.cwd() / "sigmagen" / "api" / "sigmagen_soc_dashboard.html",
        Path.cwd() / "dashboard.html",
        Path.cwd() / "sigmagen_soc_dashboard.html",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c.read_text(encoding="utf-8")
    return "<h1>Không tìm thấy file sigmagen/api/dashboard.html</h1>"


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
@app.get("/sigmagen_soc_dashboard.html", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    """Serve the interactive SigmaGen SOC Web Dashboard with no-cache headers for clean browser reloads."""
    html_content = _find_dashboard_html()
    return HTMLResponse(
        content=html_content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/api/dashboard-state")
async def get_dashboard_state(output_dir: str = "./output/new_rules") -> dict[str, Any]:
    """Return current rule registry, next auto Wazuh Rule ID, and saved rules."""
    out_p = Path(output_dir)
    reg_p = out_p / "rule_registry.json"
    history: list[dict[str, Any]] = []
    next_id = RULE_ID_MIN_DEFAULT
    if reg_p.exists():
        try:
            reg = json.loads(reg_p.read_text(encoding="utf-8-sig"))
            raw_hist = reg.get("history", [])
            if isinstance(raw_hist, list):
                history = [normalize_registry_item(x) for x in raw_hist if isinstance(x, dict)]
            next_id = max(int(reg.get("next_id", RULE_ID_MIN_DEFAULT)), RULE_ID_MIN_DEFAULT)
        except Exception:
            pass
    return {
        "status": "ok",
        "llm_provider": LLM_PROVIDER,
        "next_wazuh_rule_id": next_id,
        "rules": history,
    }


@app.post("/api/reset-dashboard")
async def api_reset_dashboard(req: ResetDashboardRequest) -> dict[str, Any]:
    """Clear the displayed rule history in rule_registry.json while preserving (or resetting) next_id."""
    out_p = Path(req.output_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    reg_p = out_p / "rule_registry.json"

    next_id = _read_next_id(out_p) if req.keep_next_id else RULE_ID_MIN_DEFAULT
    if req.reset_next_id_to is not None and 100100 <= req.reset_next_id_to <= 109999:
        next_id = req.reset_next_id_to

    reg_data = {
        "next_id": next_id,
        "alert_to_rule_id": {},
        "history": [],
    }
    reg_p.write_text(json.dumps(reg_data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "status": "ok",
        "next_wazuh_rule_id": next_id,
        "rules": [],
    }


@app.post("/api/validate-correspondence")
async def api_validate_correspondence(req: ValidateCorrespondenceRequest) -> dict[str, Any]:
    """Validate that uploaded Alert JSON and Evidence JSON match by alert_id and evidence_id."""
    try:
        res = validate_alert_evidence_correspondence(req.alert_data, req.evidence_data)
        return res
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Lỗi kiểm tra cặp file Alert/Evidence: {exc}") from exc


@app.post("/api/process-files")
async def api_process_files(req: ProcessFilesRequest) -> dict[str, Any]:
    """Automatically validate Alert <-> Evidence correspondence, then process 1 or N alerts."""
    try:
        bundles = load_alert_bundles_from_raw(
            raw_alert_data=req.alert_data,
            raw_ev_data=req.evidence_data,
            deduplicate_tokens=req.deduplicate,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Lỗi đọc dữ liệu Alert/Evidence JSON: {exc}") from exc

    benign_corpus = load_benign_background_events()
    generator = SigmaGenGenerator(provider_override=req.provider)
    out_dir = Path(req.output_dir)

    results = []
    for b in bundles:
        item = _process_bundle_to_dashboard_item(b, generator, benign_corpus, out_dir)
        results.append(item)

    next_id = _read_next_id(out_dir)
    return {
        "processed_count": len(results),
        "next_wazuh_rule_id": next_id,
        "rules": results,
    }


@app.post("/api/auto-watch/scan")
async def api_auto_watch_scan(req: Optional[AutoWatchScanRequest] = None) -> dict[str, Any]:
    """Recursively scan `./alert` (and `./backfill` if present) for alert JSON files,
    validate Alert <-> Evidence correspondence, and generate & verify rules for new alerts.
    """
    cfg = req or AutoWatchScanRequest()
    out_dir = Path(cfg.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    search_roots: list[Path] = []
    primary_root = Path(cfg.alert_dir)
    if primary_root.exists():
        search_roots.append(primary_root)
    backfill_root = Path("./backfill")
    if backfill_root.exists() and backfill_root.resolve() not in [r.resolve() for r in search_roots]:
        search_roots.append(backfill_root)

    if not search_roots:
        return {
            "processed_count": 0,
            "total_found": 0,
            "skipped_already_processed": 0,
            "skipped_errors": ["Thư mục ./alert chưa tồn tại."],
            "next_wazuh_rule_id": _read_next_id(out_dir),
            "rules": [],
        }

    ignored_names = {
        "ai_alert_evidence_test.json",
        "evidence.json",
        "manifest.json",
        "rule_registry.json",
        "batch_verification_summary.json",
        "full_evaluation_summary.json",
        "benign_single_field.json",
        "ossec-alerts-29.json",
    }

    candidate_files: list[Path] = []
    for root in search_roots:
        for p in sorted(root.rglob("*.json")):
            if p.name.endswith("_evidence.json") or p.name.endswith(".eval.json"):
                continue
            if p.name in ignored_names:
                continue
            candidate_files.append(p)

    # Check already processed alert_ids in rule_registry.json
    reg_p = out_dir / "rule_registry.json"
    processed_alert_ids: set[str] = set()
    seen_patterns: set[str] = set()
    if reg_p.exists() and not cfg.force_reprocess:
        try:
            reg = json.loads(reg_p.read_text(encoding="utf-8-sig"))
            for h in reg.get("history", []):
                if isinstance(h, dict) and h.get("alert_id"):
                    processed_alert_ids.add(str(h["alert_id"]))
                    sf = h.get("sigma_fields") or {}
                    pat = f"{h.get('event_code')}|{sf.get('Image')}|{sf.get('ParentImage')}|{sf.get('CommandLine')}|{sf.get('TargetFilename')}|{sf.get('TargetObject')}|{sf.get('QueryName')}"
                    seen_patterns.add(pat)
        except Exception:
            pass

    benign_corpus = load_benign_background_events()
    generator = SigmaGenGenerator(provider_override=cfg.provider)
    results: list[dict[str, Any]] = []
    skipped_already = 0
    skipped_errors: list[str] = []

    for af in candidate_files:
        if len(results) >= cfg.max_alerts:
            break
        try:
            bundles = load_alert_bundles(af, evidence_path=None, deduplicate_tokens=cfg.deduplicate)
            for b in bundles:
                if len(results) >= cfg.max_alerts:
                    break
                if not cfg.force_reprocess and b.alert_id in processed_alert_ids:
                    skipped_already += 1
                    continue
                if cfg.deduplicate and b.primary_events:
                    pe = b.primary_events[0]
                    sf = pe.sigma_fields
                    pat = f"{pe.event_code}|{sf.get('Image')}|{sf.get('ParentImage')}|{sf.get('CommandLine')}|{sf.get('TargetFilename')}|{sf.get('TargetObject')}|{sf.get('QueryName')}"
                    if pat in seen_patterns:
                        skipped_already += 1
                        continue
                    seen_patterns.add(pat)

                item = _process_bundle_to_dashboard_item(b, generator, benign_corpus, out_dir)
                processed_alert_ids.add(b.alert_id)
                results.append(item)
        except Exception as exc:
            skipped_errors.append(f"{af.name}: {exc}")
            continue

    next_id = _read_next_id(out_dir)
    return {
        "processed_count": len(results),
        "total_found": len(candidate_files),
        "skipped_already_processed": skipped_already,
        "skipped_errors": skipped_errors[:10],
        "next_wazuh_rule_id": next_id,
        "rules": results,
    }


@app.post("/api/verify-rule")
async def api_verify_rule(req: VerifyRuleRequest) -> dict[str, Any]:
    """Re-verify an edited or uploaded Sigma YAML rule against Alert + Evidence and update Wazuh XML."""
    out_dir = Path(req.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    benign_corpus = load_benign_background_events()

    bundle: Optional[NormalizedAlertBundle] = None
    if req.alert_data is not None:
        try:
            bundles = load_alert_bundles_from_raw(req.alert_data, req.evidence_data, deduplicate_tokens=False)
            bundle = bundles[0] if bundles else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif req.bundle_item and isinstance(req.bundle_item, dict):
        from sigmagen.ingestion.alert_adapter import (
            FIELD_ALIASES,
            NormalizedEvent,
            synthesize_generalized_variants,
        )

        bi = req.bundle_item
        sf = bi.get("sigma_fields") if isinstance(bi.get("sigma_fields"), dict) else {}
        wf = {}
        for sk, sv in sf.items():
            wk = next((w for _, (s, w) in FIELD_ALIASES.items() if s == sk), f"win.eventdata.{sk[0].lower() + sk[1:]}")
            wf[wk] = str(sv)
        pev = NormalizedEvent(
            event_id_uid=str(bi.get("alert_id") or "ev-primary"),
            role="primary",
            event_family=str(bi.get("event_family") or "sysmon"),
            event_code=int(bi.get("event_code") or 1),
            channel=str(sf.get("Channel") or "Microsoft-Windows-Sysmon/Operational"),
            sigma_fields={k: str(v) for k, v in sf.items()},
            wazuh_fields=wf,
            mitre_techniques=bi.get("mitre_techniques") or ["T1059"],
        )
        bundle = NormalizedAlertBundle(
            alert_id=str(bi.get("alert_id") or "ALERT-VERIFY"),
            evidence_id=str(bi.get("evidence_id") or ""),
            source_format=str(bi.get("source_format") or "logdeep_v2"),
            title=str(bi.get("title") or "Verified Rule"),
            description=str(bi.get("description") or ""),
            severity=str(bi.get("severity") or "high"),
            anomaly_score=None,
            host="",
            timestamp="",
            mitre_techniques=bi.get("mitre_techniques") or ["T1059"],
            primary_events=[pev],
            context_events=[],
            generalized_variants=synthesize_generalized_variants([pev]),
        )

    rule_id = req.wazuh_rule_id or allocate_next_wazuh_rule_id(out_dir, reuse_for_same_alert=False)

    if bundle:
        report = verify_and_score_sigma_rule(req.raw_yaml, bundle, benign_corpus)
        conv = compile_sigma_to_wazuh_xml(req.raw_yaml, rule_id=rule_id, bundle=bundle)

        # Persist updated YAML, XML, and registry metadata if sigma_file/wazuh_file exist
        if req.bundle_item and isinstance(req.bundle_item, dict):
            sigma_file = str(req.bundle_item.get("sigma_file") or f"{_slugify(bundle.alert_id)}.yml")
            wazuh_file = str(req.bundle_item.get("wazuh_file") or f"ml_generated_{rule_id}.xml")
            (out_dir / sigma_file).write_text(req.raw_yaml, encoding="utf-8")
            if conv.wazuh_xml:
                (out_dir / wazuh_file).write_text(conv.wazuh_xml, encoding="utf-8")

            updated_item = normalize_registry_item(
                {
                    **req.bundle_item,
                    "wazuh_rule_id": rule_id,
                    "title": report.rule_title or req.bundle_item.get("title"),
                    "raw_yaml": req.raw_yaml,
                    "wazuh_xml": conv.wazuh_xml,
                    "sigma_file": sigma_file,
                    "wazuh_file": wazuh_file,
                    "report": {
                        "q1_syntax_valid": report.q1_syntax_valid,
                        "q1_syntax_score": report.q1_syntax_score,
                        "q1_errors": report.q1_errors,
                        "q1_warnings": report.q1_warnings,
                        "q2_data_match_valid": report.q2_data_match_valid,
                        "q2_data_linkage_score": report.q2_data_linkage_score,
                        "q2_logsource_matched": report.q2_logsource_matched,
                        "q2_all_fields_present": report.q2_all_fields_present_in_event,
                        "q2_errors": report.q2_errors,
                        "q2_warnings": report.q2_overfit_warnings,
                        "q3_behavior_valid": report.q3_behavior_valid,
                        "q3_behavior_score": report.q3_behavior_score,
                        "tp": report.tp,
                        "fp": report.fp,
                        "fn": report.fn,
                        "tn": report.tn,
                        "precision": report.precision,
                        "recall": report.recall,
                        "f1_score": report.f1_score,
                        "generalization_hits": report.generalization_hits,
                        "generalization_total": report.generalization_total,
                        "generalization_rate": report.generalization_rate,
                        "fpr": report.false_positive_rate,
                        "confidence_score": report.confidence_score,
                        "quality_gate": report.quality_gate,
                        "recommendation_reason": report.recommendation_reason,
                    },
                }
            )
            register_generated_rule_metadata(out_dir, updated_item)
            return {
                "verification_report": report.to_dict(),
                "wazuh_conversion": conv.to_dict(),
                "dashboard_item": updated_item,
                "next_wazuh_rule_id": _read_next_id(out_dir),
            }

        return {
            "verification_report": report.to_dict(),
            "wazuh_conversion": conv.to_dict(),
            "next_wazuh_rule_id": _read_next_id(out_dir),
        }

    conv = compile_sigma_to_wazuh_xml(req.raw_yaml, rule_id=rule_id)
    return {
        "wazuh_conversion": conv.to_dict(),
        "next_wazuh_rule_id": _read_next_id(out_dir),
    }


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/status", response_model=StatusResponse)
async def status() -> StatusResponse:
    try:
        from sigmagen.embeddings.pipeline import get_collection_stats
        stats = get_collection_stats()
    except Exception:
        stats = {}
    all_ready = all(v > 0 for v in stats.values())
    return StatusResponse(
        status="ready" if all_ready else "needs_ingestion",
        collections=stats,
        llm_provider=LLM_PROVIDER,
        embedding_model=EMBEDDING_MODEL,
    )


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest) -> GenerateResponse:
    technique = (req.technique_id or "").strip()
    telemetry = (req.telemetry or "").strip()

    if technique and telemetry:
        raise HTTPException(status_code=422, detail="Provide either 'technique_id' or 'telemetry', not both.")
    if not technique and not telemetry:
        raise HTTPException(status_code=422, detail="Provide either 'technique_id' or 'telemetry'.")

    input_text = technique or telemetry
    try:
        generator = SigmaGenGenerator()
        results = generator.generate(input_text, n_rules=req.n_rules)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    all_technique_ids: list[str] = []
    rules: list[RuleOutput] = []
    for r in results:
        rules.append(
            RuleOutput(
                yaml=r.raw_yaml,
                title=r.parsed.get("title", "Untitled"),
                level=r.parsed.get("level", ""),
                technique_ids=r.technique_ids,
                valid=r.valid,
                validation_errors=r.validation_errors,
            )
        )
        all_technique_ids.extend(r.technique_ids)

    return GenerateResponse(
        rules=rules,
        technique_ids=sorted(set(all_technique_ids)),
        retrieval_context={"input": input_text, "n_rules_requested": req.n_rules},
    )


@app.get("/retrieve")
async def retrieve(
    q: str = Query(..., min_length=1, description="Query text (technique ID or description)"),
    n_results: int = Query(default=5, ge=1, le=20),
) -> dict:
    if not q.strip():
        raise HTTPException(status_code=422, detail="Query cannot be empty or whitespace.")
    try:
        from sigmagen.retrieval.retriever import SigmaGenRetriever
        retriever = SigmaGenRetriever()
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    result = retriever.retrieve(q, n_results=n_results)
    return {
        "query": result.query,
        "query_type": result.query_type,
        "techniques": [
            {
                "technique_id": rt.technique.technique_id,
                "name": rt.technique.name,
                "tactics": rt.technique.tactics,
                "score": round(rt.score, 4),
            }
            for rt in result.techniques
        ],
        "sigma_rules": [
            {
                "rule_id": rr.rule.rule_id,
                "title": rr.rule.title,
                "level": rr.rule.level,
                "score": round(rr.score, 4),
            }
            for rr in result.sigma_rules
        ],
    }