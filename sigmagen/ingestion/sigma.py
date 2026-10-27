"""SigmaHQ rule corpus ingestion — git clone with ZIP fallback."""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
import yaml
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from sigmagen.config import SIGMA_REPO_DIR, SIGMA_REPO_URL, SIGMA_STABLE_RULES_DIR

console = Console()

SIGMA_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"


@dataclass
class SigmaRule:
    """A parsed Sigma detection rule."""

    rule_id: str = ""
    title: str = ""
    description: str = ""
    status: str = ""
    level: str = ""
    tags: list[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    detection: dict = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    author: str = ""
    raw_yaml: str = ""
    file_path: str = ""

    @property
    def technique_ids(self) -> list[str]:
        """Extract ATT&CK technique IDs from tags.

        Tags like ``attack.t1059.001`` are normalised to ``T1059.001``.
        """
        ids: list[str] = []
        pattern = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
        for tag in self.tags:
            m = pattern.match(tag)
            if m:
                ids.append(m.group(1).upper())
        return ids

    @property
    def tactic_tags(self) -> list[str]:
        """Extract tactic names from tags like ``attack.execution``."""
        tactics: list[str] = []
        technique_pattern = re.compile(r"^attack\.t\d{4}", re.IGNORECASE)
        for tag in self.tags:
            if tag.startswith("attack.") and not technique_pattern.match(tag):
                tactic = tag.removeprefix("attack.")
                if tactic and not tactic.startswith("g") and not tactic.startswith("s"):
                    tactics.append(tactic)
        return tactics

    @property
    def logsource_category(self) -> str:
        """Return logsource category or empty string."""
        return self.logsource.get("category", "")

    @property
    def logsource_product(self) -> str:
        """Return logsource product or empty string."""
        return self.logsource.get("product", "")

    @property
    def logsource_service(self) -> str:
        """Return logsource service or empty string."""
        return self.logsource.get("service", "")

    def to_document(self) -> str:
        """Render a text document suitable for embedding."""
        parts: list[str] = [self.title]

        if self.description:
            parts.append(self.description)

        ls_parts: list[str] = []
        if self.logsource_category:
            ls_parts.append(f"category={self.logsource_category}")
        if self.logsource_product:
            ls_parts.append(f"product={self.logsource_product}")
        if self.logsource_service:
            ls_parts.append(f"service={self.logsource_service}")
        if ls_parts:
            parts.append(f"Logsource: {', '.join(ls_parts)}")

        # Detection condition and selection key names (not values)
        det = self.detection
        if "condition" in det:
            parts.append(f"Condition: {det['condition']}")
        selection_keys = [k for k in det if k != "condition"]
        if selection_keys:
            parts.append(f"Selection keys: {', '.join(selection_keys)}")

        if self.level:
            parts.append(f"Level: {self.level}")

        tids = self.technique_ids
        if tids:
            parts.append(f"Techniques: {', '.join(tids)}")

        ttags = self.tactic_tags
        if ttags:
            parts.append(f"Tactics: {', '.join(ttags)}")

        fps = self.falsepositives[:3]
        if fps:
            parts.append(f"False positives: {'; '.join(fps)}")

        return "\n".join(parts)

    def to_metadata(self) -> dict:
        """Return a flat ChromaDB-compatible metadata dict.

        All values are str, int, float, or bool.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title[:200],
            "status": self.status,
            "level": self.level,
            "tags": ", ".join(self.tags),
            "technique_ids": ", ".join(self.technique_ids),
            "tactic_tags": ", ".join(self.tactic_tags),
            "logsource_category": self.logsource_category,
            "logsource_product": self.logsource_product,
            "logsource_service": self.logsource_service,
            "author": (self.author or "")[:200],
            "file_path": self.file_path,
            "has_references": len(self.references) > 0,
            "reference_count": len(self.references),
        }


# ---------------------------------------------------------------------------
# Repository acquisition
# ---------------------------------------------------------------------------


def _git_available() -> bool:
    """Check whether git is available on PATH."""
    try:
        subprocess.run(
            ["git", "--version"],
            capture_output=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _clone_with_git() -> Path:
    """Shallow-clone the SigmaHQ repo via git."""
    console.print("[bold blue]Cloning SigmaHQ repo (shallow)...[/bold blue]")
    subprocess.run(
        [
            "git",
            "clone",
            "--depth=1",
            "--filter=blob:none",
            SIGMA_REPO_URL,
            str(SIGMA_REPO_DIR),
        ],
        check=True,
        timeout=300,
    )
    console.print(f"[green]Cloned to {SIGMA_REPO_DIR}[/green]")
    return SIGMA_REPO_DIR


def _download_zip_fallback() -> Path:
    """Download and extract the Sigma repo as a ZIP archive."""
    console.print(
        "[bold blue]git not available — downloading Sigma repo as ZIP...[/bold blue]"
    )
    response = requests.get(SIGMA_ZIP_URL, stream=True, timeout=300)
    response.raise_for_status()

    total_size = int(response.headers.get("content-length", 0))
    buf = io.BytesIO()

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("sigma-master.zip", total=total_size)
        for chunk in response.iter_content(chunk_size=65_536):
            buf.write(chunk)
            progress.update(task, advance=len(chunk))

    console.print("[blue]Extracting ZIP...[/blue]")
    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        zf.extractall(SIGMA_REPO_DIR.parent)

    extracted = SIGMA_REPO_DIR.parent / "sigma-master"
    if extracted.exists():
        if SIGMA_REPO_DIR.exists():
            shutil.rmtree(SIGMA_REPO_DIR)
        extracted.rename(SIGMA_REPO_DIR)

    console.print(f"[green]Extracted Sigma repo to {SIGMA_REPO_DIR}[/green]")
    return SIGMA_REPO_DIR


def clone_sigma_repo(force: bool = False) -> Path:
    """Clone (or download) the SigmaHQ rule repository.

    Tries ``git clone --depth=1`` first; falls back to downloading a ZIP
    archive if git is not available or the clone times out.
    """
    if SIGMA_REPO_DIR.exists() and not force:
        yml_count = len(list(SIGMA_REPO_DIR.rglob("*.yml")))
        console.print(
            f"[dim]Sigma repo already cached at {SIGMA_REPO_DIR} "
            f"({yml_count} .yml files). Use --force to re-clone.[/dim]"
        )
        return SIGMA_REPO_DIR

    if SIGMA_REPO_DIR.exists():
        shutil.rmtree(SIGMA_REPO_DIR)

    if _git_available():
        try:
            return _clone_with_git()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            console.print(f"[yellow]git clone failed ({exc}), trying ZIP fallback...[/yellow]")

    return _download_zip_fallback()


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------


def parse_sigma_rule(
    yaml_path: Path,
    repo_root: Path | None = None,
) -> Optional[SigmaRule]:
    """Parse a single Sigma YAML file and return a SigmaRule (or None on failure).

    Multi-document YAML files are supported — the first document that has
    both ``title`` and ``detection`` (with a ``condition`` key) is used.
    """
    try:
        text = yaml_path.read_text(encoding="utf-8")
    except Exception:
        return None

    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return None

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if not doc.get("title"):
            continue
        detection = doc.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            continue

        rel_path = ""
        if repo_root:
            try:
                rel_path = str(yaml_path.relative_to(repo_root))
            except ValueError:
                rel_path = str(yaml_path)
        else:
            rel_path = str(yaml_path)

        tags_raw = doc.get("tags", [])
        tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []

        fps_raw = doc.get("falsepositives", [])
        fps = [str(fp) for fp in fps_raw] if isinstance(fps_raw, list) else []

        refs_raw = doc.get("references", [])
        refs = [str(r) for r in refs_raw] if isinstance(refs_raw, list) else []

        logsource = doc.get("logsource", {})
        if not isinstance(logsource, dict):
            logsource = {}

        return SigmaRule(
            rule_id=str(doc.get("id", "")),
            title=str(doc["title"]),
            description=str(doc.get("description", "")),
            status=str(doc.get("status", "")),
            level=str(doc.get("level", "")),
            tags=tags,
            logsource=logsource,
            detection=detection,
            falsepositives=fps,
            references=refs,
            author=str(doc.get("author", "")),
            raw_yaml=text,
            file_path=rel_path,
        )

    return None


def load_sigma_rules(
    rules_dir: Path | None = None,
    full_corpus: bool = False,
) -> list[SigmaRule]:
    """Walk a directory of Sigma YAML files and return parsed rules.

    By default only ``SIGMA_STABLE_RULES_DIR`` (the ``rules/`` sub-directory)
    is scanned.  Set *full_corpus* to ``True`` to scan the entire repo.
    """
    if rules_dir is None:
        scan_dir = SIGMA_REPO_DIR if full_corpus else SIGMA_STABLE_RULES_DIR
    else:
        scan_dir = rules_dir

    if not scan_dir.exists():
        console.print(f"[red]Rules directory not found: {scan_dir}[/red]")
        console.print("[yellow]Run 'sigmagen ingest sigma' first to clone the repo.[/yellow]")
        return []

    yml_files = sorted(scan_dir.rglob("*.yml"))
    rules: list[SigmaRule] = []
    skipped = 0

    repo_root = SIGMA_REPO_DIR if SIGMA_REPO_DIR.exists() else scan_dir

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("Parsing Sigma rules", total=len(yml_files))
        for yml_file in yml_files:
            rule = parse_sigma_rule(yml_file, repo_root=repo_root)
            if rule is not None:
                rules.append(rule)
            else:
                skipped += 1
            progress.update(task, advance=1)

    # Statistics
    with_attack = sum(1 for r in rules if r.technique_ids)
    level_dist = Counter(r.level for r in rules if r.level)

    console.print(f"\n[bold]Sigma Parse Summary[/bold]")
    console.print(f"  Total YAML files scanned: [cyan]{len(yml_files)}[/cyan]")
    console.print(f"  Rules parsed:             [cyan]{len(rules)}[/cyan]")
    console.print(f"  Skipped/invalid:          [yellow]{skipped}[/yellow]")
    console.print(f"  With ATT&CK technique tags: [cyan]{with_attack}[/cyan]")
    console.print(f"  Level distribution:")
    for lvl in ("critical", "high", "medium", "low", "informational"):
        count = level_dist.get(lvl, 0)
        if count:
            console.print(f"    {lvl:15s} {count}")

    return rules
