"""MITRE ATT&CK Enterprise technique ingestion from STIX bundle."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from sigmagen.config import ATTACK_JSON_PATH, ATTACK_JSON_URL

console = Console()


@dataclass
class AttackTechnique:
    """A single MITRE ATT&CK Enterprise technique or sub-technique."""

    technique_id: str
    name: str
    description: str = ""
    detection: str = ""
    data_sources: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    is_subtechnique: bool = False
    url: str = ""
    stix_id: str = ""

    @property
    def parent_technique_id(self) -> str | None:
        """Return the parent technique ID for sub-techniques (e.g. T1059 from T1059.001)."""
        if self.is_subtechnique and "." in self.technique_id:
            return self.technique_id.split(".")[0]
        return None

    def to_document(self) -> str:
        """Render a text document suitable for embedding.

        Fields are packed in priority order so the most important
        information lands in the first few hundred tokens.
        """
        parts: list[str] = [
            f"{self.technique_id} - {self.name}",
        ]
        if self.tactics:
            parts.append(f"Tactics: {', '.join(self.tactics)}")
        if self.platforms:
            parts.append(f"Platforms: {', '.join(self.platforms)}")
        if self.data_sources:
            parts.append(f"Data Sources: {', '.join(self.data_sources)}")
        if self.detection:
            parts.append(f"Detection Guidance:\n{self.detection}")
        if self.description:
            truncated = self.description[:2000]
            parts.append(f"Description:\n{truncated}")
        return "\n\n".join(parts)

    def to_metadata(self) -> dict:
        """Return a flat ChromaDB-compatible metadata dict.

        All values are str, int, float, or bool — never lists or dicts.
        Lists are serialized as comma-joined strings.
        """
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": ", ".join(self.tactics),
            "platforms": ", ".join(self.platforms),
            "data_sources": ", ".join(self.data_sources),
            "is_subtechnique": self.is_subtechnique,
            "url": self.url,
            "stix_id": self.stix_id,
            "has_detection": bool(self.detection),
        }


def download_attack_json(force: bool = False) -> Path:
    """Download the ATT&CK Enterprise STIX bundle JSON.

    Skips download if the file already exists unless *force* is True.
    Displays a Rich progress bar showing download speed.
    """
    if ATTACK_JSON_PATH.exists() and not force:
        console.print(
            f"[dim]ATT&CK JSON already cached at {ATTACK_JSON_PATH} "
            f"({ATTACK_JSON_PATH.stat().st_size / 1_048_576:.1f} MB). "
            f"Use --force to re-download.[/dim]"
        )
        return ATTACK_JSON_PATH

    console.print(f"[bold blue]Downloading ATT&CK Enterprise STIX bundle...[/bold blue]")
    response = requests.get(ATTACK_JSON_URL, stream=True, timeout=120)
    response.raise_for_status()

    total_size = int(response.headers.get("content-length", 0))

    ATTACK_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("enterprise-attack.json", total=total_size)
        with open(ATTACK_JSON_PATH, "wb") as f:
            for chunk in response.iter_content(chunk_size=65_536):
                f.write(chunk)
                progress.update(task, advance=len(chunk))

    console.print(
        f"[green]Saved ATT&CK JSON to {ATTACK_JSON_PATH} "
        f"({ATTACK_JSON_PATH.stat().st_size / 1_048_576:.1f} MB)[/green]"
    )
    return ATTACK_JSON_PATH


def parse_attack_json(path: Path) -> list[AttackTechnique]:
    """Parse the STIX bundle and return a sorted list of ATT&CK techniques.

    Filters:
    - Only ``attack-pattern`` type objects
    - Skips deprecated (``x_mitre_deprecated``) and revoked objects
    - Skips objects without a ``mitre-attack`` external reference
    """
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    techniques: list[AttackTechnique] = []
    skipped_deprecated = 0
    skipped_revoked = 0
    skipped_no_id = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("x_mitre_deprecated", False):
            skipped_deprecated += 1
            continue

        if obj.get("revoked", False):
            skipped_revoked += 1
            continue

        # Extract mitre-attack external reference
        ext_refs = obj.get("external_references", [])
        mitre_ref = next(
            (r for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None,
        )
        if mitre_ref is None or "external_id" not in mitre_ref:
            skipped_no_id += 1
            continue

        technique_id = mitre_ref["external_id"]
        url = mitre_ref.get("url", "")

        # Extract tactic names from kill chain phases
        tactics: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        technique = AttackTechnique(
            technique_id=technique_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            detection=obj.get("x_mitre_detection", ""),
            data_sources=obj.get("x_mitre_data_sources", []),
            tactics=tactics,
            platforms=obj.get("x_mitre_platforms", []),
            is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
            url=url,
            stix_id=obj.get("id", ""),
        )
        techniques.append(technique)

    techniques.sort(key=lambda t: t.technique_id)

    # Print summary statistics
    base_count = sum(1 for t in techniques if not t.is_subtechnique)
    sub_count = sum(1 for t in techniques if t.is_subtechnique)

    console.print(f"\n[bold]ATT&CK Parse Summary[/bold]")
    console.print(f"  Total techniques parsed: [cyan]{len(techniques)}[/cyan]")
    console.print(f"  Base techniques:         [cyan]{base_count}[/cyan]")
    console.print(f"  Sub-techniques:          [cyan]{sub_count}[/cyan]")
    console.print(f"  Skipped deprecated:      [yellow]{skipped_deprecated}[/yellow]")
    console.print(f"  Skipped revoked:         [yellow]{skipped_revoked}[/yellow]")
    console.print(f"  Skipped (no ATT&CK ID):  [yellow]{skipped_no_id}[/yellow]")

    return techniques


def load_attack_techniques(force_download: bool = False) -> list[AttackTechnique]:
    """Download (if needed) and parse the ATT&CK Enterprise STIX bundle.

    Returns a sorted list of ATT&CK techniques ready for embedding.
    """
    path = download_attack_json(force=force_download)
    return parse_attack_json(path)
