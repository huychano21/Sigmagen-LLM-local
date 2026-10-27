"""ChromaDB embedding pipeline for ATT&CK techniques and Sigma rules."""
from __future__ import annotations

import hashlib
import logging
from collections import Counter

# Suppress ChromaDB posthog telemetry errors (version mismatch in posthog.capture)
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

import chromadb
from chromadb.config import Settings as _ChromaSettings
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from sigmagen.config import (
    ATTACK_COLLECTION,
    CHROMA_BATCH_SIZE,
    CHROMA_DIR,
    EMBEDDING_MODEL,
    SIGMA_COLLECTION,
)
from sigmagen.ingestion.attack import AttackTechnique
from sigmagen.ingestion.sigma import SigmaRule

console = Console()

_embedding_fn_cache: SentenceTransformerEmbeddingFunction | None = None


def get_chroma_client() -> chromadb.PersistentClient:
    """Return a persistent ChromaDB client backed by ``CHROMA_DIR``."""
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        settings=_ChromaSettings(anonymized_telemetry=False),
    )


def get_embedding_function() -> SentenceTransformerEmbeddingFunction:
    """Return a SentenceTransformer embedding function (cached singleton).

    The model is downloaded automatically the first time this is called.
    """
    global _embedding_fn_cache
    if _embedding_fn_cache is None:
        _embedding_fn_cache = SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)
    return _embedding_fn_cache


def get_collection(name: str) -> chromadb.Collection:
    """Retrieve an existing ChromaDB collection by name.

    Raises ``ValueError`` if the collection does not exist or is empty.
    """
    client = get_chroma_client()
    try:
        collection = client.get_collection(
            name=name,
            embedding_function=get_embedding_function(),
        )
    except Exception as exc:
        raise ValueError(
            f"Collection '{name}' not found in ChromaDB at {CHROMA_DIR}. "
            f"Run 'sigmagen ingest all' to build the knowledge base first.\n"
            f"Original error: {exc}"
        ) from exc
    return collection


# ---------------------------------------------------------------------------
# ATT&CK embedding
# ---------------------------------------------------------------------------


def embed_attack_techniques(
    techniques: list[AttackTechnique],
    force: bool = False,
) -> chromadb.Collection:
    """Embed ATT&CK techniques into the ``attack_techniques`` ChromaDB collection.

    If the collection already exists and *force* is ``False``, the operation
    is skipped with a hint to use ``--force``.
    """
    if not techniques:
        console.print("[yellow]No ATT&CK techniques to embed — skipping.[/yellow]")
        return get_chroma_client().get_or_create_collection(
            name=ATTACK_COLLECTION,
            embedding_function=get_embedding_function(),
            metadata={"hnsw:space": "cosine"},
        )

    client = get_chroma_client()
    ef = get_embedding_function()

    if force:
        try:
            client.delete_collection(ATTACK_COLLECTION)
        except ValueError:
            pass

    collection = client.get_or_create_collection(
        name=ATTACK_COLLECTION,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    existing_count = collection.count()
    if existing_count > 0 and not force:
        console.print(
            f"[yellow]ATT&CK collection already has {existing_count} documents. "
            f"Use --force to rebuild.[/yellow]"
        )
        return collection

    ids = [t.technique_id for t in techniques]
    documents = [t.to_document() for t in techniques]
    metadatas = [t.to_metadata() for t in techniques]

    _batch_upsert(collection, ids, documents, metadatas, label="ATT&CK techniques")

    console.print(
        f"[green]Embedded {collection.count()} ATT&CK techniques into "
        f"'{ATTACK_COLLECTION}' collection.[/green]"
    )
    return collection


# ---------------------------------------------------------------------------
# Sigma embedding
# ---------------------------------------------------------------------------


def _resolve_sigma_ids(rules: list[SigmaRule]) -> list[SigmaRule]:
    """Assign stable synthetic IDs to rules without UUID rule_ids and deduplicate.

    Rules that already have a UUID-like ``rule_id`` keep it.  Others get an
    MD5-based ID derived from ``title + file_path`` to ensure stability across
    re-ingestions.  Duplicate IDs get a ``-N`` counter suffix.
    """
    seen: Counter[str] = Counter()
    resolved: list[SigmaRule] = []

    for rule in rules:
        rid = rule.rule_id.strip()
        if not rid or len(rid) < 8:
            raw = f"{rule.title}|{rule.file_path}"
            rid = hashlib.md5(raw.encode()).hexdigest()
            rule.rule_id = rid

        seen[rid] += 1
        if seen[rid] > 1:
            rule.rule_id = f"{rid}-{seen[rid]}"

        resolved.append(rule)

    return resolved


def embed_sigma_rules(
    rules: list[SigmaRule],
    force: bool = False,
) -> chromadb.Collection:
    """Embed Sigma rules into the ``sigma_rules`` ChromaDB collection.

    If the collection already exists and *force* is ``False``, the operation
    is skipped with a hint to use ``--force``.
    """
    if not rules:
        console.print("[yellow]No Sigma rules to embed — skipping.[/yellow]")
        return get_chroma_client().get_or_create_collection(
            name=SIGMA_COLLECTION,
            embedding_function=get_embedding_function(),
            metadata={"hnsw:space": "cosine"},
        )

    client = get_chroma_client()
    ef = get_embedding_function()

    if force:
        try:
            client.delete_collection(SIGMA_COLLECTION)
        except ValueError:
            pass

    collection = client.get_or_create_collection(
        name=SIGMA_COLLECTION,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    existing_count = collection.count()
    if existing_count > 0 and not force:
        console.print(
            f"[yellow]Sigma collection already has {existing_count} documents. "
            f"Use --force to rebuild.[/yellow]"
        )
        return collection

    rules = _resolve_sigma_ids(rules)

    ids = [r.rule_id for r in rules]
    documents = [r.to_document() for r in rules]
    metadatas = [r.to_metadata() for r in rules]

    _batch_upsert(collection, ids, documents, metadatas, label="Sigma rules")

    console.print(
        f"[green]Embedded {collection.count()} Sigma rules into "
        f"'{SIGMA_COLLECTION}' collection.[/green]"
    )
    return collection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _batch_upsert(
    collection: chromadb.Collection,
    ids: list[str],
    documents: list[str],
    metadatas: list[dict],
    label: str = "documents",
) -> None:
    """Upsert documents into a ChromaDB collection in batches with a Rich progress bar."""
    total = len(ids)
    batch_size = max(1, CHROMA_BATCH_SIZE)
    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task(f"Embedding {label}", total=total)
        for start in range(0, total, batch_size):
            end = min(start + batch_size, total)
            collection.upsert(
                ids=ids[start:end],
                documents=documents[start:end],
                metadatas=metadatas[start:end],
            )
            progress.update(task, advance=end - start)


def get_collection_stats() -> dict[str, int]:
    """Return ``{collection_name: document_count}`` for both collections."""
    client = get_chroma_client()
    ef = get_embedding_function()
    stats: dict[str, int] = {}

    for name in (ATTACK_COLLECTION, SIGMA_COLLECTION):
        try:
            col = client.get_collection(name=name, embedding_function=ef)
            stats[name] = col.count()
        except Exception:
            stats[name] = 0

    return stats


def print_status_table() -> None:
    """Print a Rich table showing collection status."""
    stats = get_collection_stats()

    table = Table(title="SigmaGen Knowledge Base Status")
    table.add_column("Collection", style="cyan")
    table.add_column("Documents", justify="right", style="magenta")
    table.add_column("Status", style="bold")

    for name, count in stats.items():
        status = "[green]Ready[/green]" if count > 0 else "[red]Empty[/red]"
        table.add_row(name, str(count), status)

    console.print(table)
