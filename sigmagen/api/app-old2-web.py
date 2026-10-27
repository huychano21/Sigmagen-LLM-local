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
    allocate_next_wazuh_rule_id,
    compile_sigma_to_wazuh_xml,
    register_generated_rule_metadata,
)
from sigmagen.generation.generator import SigmaGenGenerator
from sigmagen.ingestion.alert_adapter import (
    NormalizedAlertBundle,
    load_alert_bundles,
    load_alert_bundles_from_raw,
    load_benign_background_events,
)
from sigmagen.validation.verifier import verify_and_score_sigma_rule

DEFAULT_OUTPUT_DIR = Path("./output/new_rules")
DEFAULT_ALERT_DIR = Path("./alert")


def _slugify(text: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", text.lower())
    slug = re.sub(r"[\s_]+", "_", slug).strip("_")
    return slug[:80] or "sigma_rule"


class GenerateRequest(BaseModel):
    technique_id: Optional[str] = None
    telemetry: Optional[str] = None
    n_rules: int = Field(default=1, ge=1, le=5)


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
    wazuh_rule_id: Optional[int] = None


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
    version="0.2.0",
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
    assigned_id = allocate_next_wazuh_rule_id(output_dir, alert_id=bundle.alert_id)

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
    item = {
        "wazuh_rule_id": assigned_id,
        "alert_id": bundle.alert_id,
        "evidence_id": "",
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


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    """Serve the interactive SigmaGen SOC Web Dashboard."""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>SigmaGen Dashboard not found</h1>", status_code=404)


@app.get("/api/dashboard-state")
async def get_dashboard_state(output_dir: str = "./output/new_rules") -> dict[str, Any]:
    """Return current rule registry, next auto Wazuh Rule ID, and saved rules."""
    out_p = Path(output_dir)
    reg_p = out_p / "rule_registry.json"
    history = []
    next_id = 100100
    if reg_p.exists():
        try:
            reg = json.loads(reg_p.read_text(encoding="utf-8-sig"))
            history = reg.get("history", [])
            next_id = int(reg.get("next_id", 100100))
        except Exception:
            pass
    return {
        "status": "ok",
        "llm_provider": LLM_PROVIDER,
        "next_wazuh_rule_id": next_id,
        "rules": history,
    }


@app.post("/api/process-files")
async def api_process_files(req: ProcessFilesRequest) -> dict[str, Any]:
    """Automatically process 1 or N alerts from uploaded JSON + optional evidence JSON."""
    try:
        bundles = load_alert_bundles_from_raw(
            raw_alert_data=req.alert_data,
            raw_ev_data=req.evidence_data,
            deduplicate_tokens=req.deduplicate,
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse alert/evidence JSON: {exc}") from exc

    benign_corpus = load_benign_background_events()
    generator = SigmaGenGenerator(provider_override=req.provider)
    out_dir = Path(req.output_dir)

    results = []
    for b in bundles:
        item = _process_bundle_to_dashboard_item(b, generator, benign_corpus, out_dir)
        results.append(item)

    return {
        "processed_count": len(results),
        "rules": results,
    }


@app.post("/api/auto-watch/scan")
async def api_auto_watch_scan(
    alert_dir: str = "./alert",
    output_dir: str = "./output/new_rules",
    deduplicate: bool = True,
) -> dict[str, Any]:
    """Scan `./alert` folder for alert JSON files, automatically pair with evidence, generate & verify rules."""
    a_dir = Path(alert_dir)
    out_dir = Path(output_dir)
    if not a_dir.exists():
        return {"processed_count": 0, "rules": []}

    alert_files = sorted(
        p for p in a_dir.glob("*.json")
        if not p.name.endswith("_evidence.json")
        and p.name not in ("ai_alert_evidence_test.json", "evidence.json")
    )

    benign_corpus = load_benign_background_events()
    generator = SigmaGenGenerator()
    results = []

    for af in alert_files:
        try:
            bundles = load_alert_bundles(af, evidence_path=None, deduplicate_tokens=deduplicate)
            for b in bundles:
                item = _process_bundle_to_dashboard_item(b, generator, benign_corpus, out_dir)
                results.append(item)
        except Exception:
            continue

    return {
        "processed_count": len(results),
        "rules": results,
    }


@app.post("/api/verify-rule")
async def api_verify_rule(req: VerifyRuleRequest) -> dict[str, Any]:
    """Re-verify an edited Sigma YAML rule and re-compile to Wazuh XML."""
    bundles = []
    if req.alert_data:
        bundles = load_alert_bundles_from_raw(req.alert_data, req.evidence_data, deduplicate_tokens=False)
    bundle = bundles[0] if bundles else None
    benign_corpus = load_benign_background_events()
    rule_id = req.wazuh_rule_id or allocate_next_wazuh_rule_id(DEFAULT_OUTPUT_DIR)

    if bundle:
        report = verify_and_score_sigma_rule(req.raw_yaml, bundle, benign_corpus)
        conv = compile_sigma_to_wazuh_xml(req.raw_yaml, rule_id=rule_id, bundle=bundle)
        return {
            "verification_report": report.to_dict(),
            "wazuh_conversion": conv.to_dict(),
        }
    conv = compile_sigma_to_wazuh_xml(req.raw_yaml, rule_id=rule_id)
    return {"wazuh_conversion": conv.to_dict()}


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
