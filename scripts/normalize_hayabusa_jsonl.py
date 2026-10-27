import json
import sys
from collections import Counter
from pathlib import Path

source = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)

normalized_path = out_dir / "alerts.normalized.jsonl"
report_path = out_dir / "normalization_report.json"
sample_path = out_dir / "sample_alert.json"

severity_map = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}

total = 0
invalid = []
missing = Counter()
levels = Counter()
titles = Counter()
event_ids = Counter()
sample = None

with source.open("r", encoding="utf-8-sig") as fin, \
     normalized_path.open("w", encoding="utf-8", newline="\n") as fout:

    for line_no, line in enumerate(fin, 1):
        if not line.strip():
            continue

        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            invalid.append({
                "line": line_no,
                "error": str(exc),
            })
            continue

        if not isinstance(raw, dict):
            invalid.append({
                "line": line_no,
                "error": "JSON record is not an object",
            })
            continue

        total += 1

        title = raw.get("RuleTitle")
        level_raw = str(raw.get("Level") or "").strip().lower()
        event_id = raw.get("EventID")

        alert = {
            "schema_version": "1.0",
            "source": "hayabusa",
            "timestamp": raw.get("Timestamp"),
            "title": title,
            "severity": severity_map.get(level_raw, "unknown"),
            "host": raw.get("Computer"),
            "channel": raw.get("Channel"),
            "event_id": event_id,
            "record_id": raw.get("RecordID"),
            "details": raw.get("Details", {}),
            "extra_fields": raw.get("ExtraFieldInfo", {}),
            "source_rule_id": raw.get("RuleID"),
            "raw": raw,
        }

        for field in (
            "timestamp", "title", "host", "channel",
            "event_id", "record_id", "source_rule_id"
        ):
            if alert[field] is None or alert[field] == "":
                missing[field] += 1

        levels[alert["severity"]] += 1
        titles[str(title or "<missing>")] += 1
        event_ids[str(event_id or "<missing>")] += 1

        fout.write(json.dumps(
            alert, ensure_ascii=False, separators=(",", ":")
        ) + "\n")

        if sample is None:
            sample = alert

report = {
    "input_file": str(source),
    "output_file": str(normalized_path),
    "records_normalized": total,
    "invalid_records": len(invalid),
    "missing_fields": dict(missing),
    "severity_counts": dict(levels),
    "unique_titles": len(titles),
    "top_10_titles": titles.most_common(10),
    "top_10_event_ids": event_ids.most_common(10),
    "invalid_examples": invalid[:10],
}

report_path.write_text(
    json.dumps(report, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

if sample is not None:
    sample_path.write_text(
        json.dumps(sample, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

print(json.dumps(report, ensure_ascii=False, indent=2))
print(f"\nSample alert: {sample_path}")
print(f"Normalized JSONL: {normalized_path}")
