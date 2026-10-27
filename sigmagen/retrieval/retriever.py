"""RAG retrieval module — queries ChromaDB for ATT&CK techniques and Sigma rules (with SQLite/offline fallback when chromadb is not installed)."""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from sigmagen.config import ATTACK_COLLECTION, CHROMA_DIR, RAG_TOP_K, SIGMA_COLLECTION
from sigmagen.ingestion.attack import AttackTechnique
from sigmagen.ingestion.sigma import SigmaRule

console = Console()

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


@dataclass
class RetrievedTechnique:
    """An ATT&CK technique retrieved from the vector store."""

    technique: AttackTechnique
    score: float


@dataclass
class RetrievedRule:
    """A Sigma rule retrieved from the vector store."""

    rule: SigmaRule
    score: float


@dataclass
class RetrievalResult:
    """Combined retrieval result from both knowledge bases."""

    techniques: list[RetrievedTechnique] = field(default_factory=list)
    sigma_rules: list[RetrievedRule] = field(default_factory=list)
    query: str = ""
    query_type: str = ""  # "technique_id" | "telemetry" | "description"


class SigmaGenRetriever:
    """RAG retriever that queries both ATT&CK and Sigma ChromaDB collections (or SQLite fallback)."""

    def __init__(self) -> None:
        self._use_sqlite_fallback = False
        try:
            from sigmagen.embeddings.pipeline import get_collection

            self._attack_col = get_collection(ATTACK_COLLECTION)
            self._sigma_col = get_collection(SIGMA_COLLECTION)
        except Exception:
            self._use_sqlite_fallback = True
            self._attack_col = None
            self._sigma_col = None

    def retrieve(self, input_text: str, n_results: int = RAG_TOP_K) -> RetrievalResult:
        cleaned = input_text.strip()
        if not cleaned:
            raise ValueError("Query cannot be empty.")
        n_results = max(1, min(n_results, 20))
        if self._use_sqlite_fallback:
            return self._retrieve_via_sqlite(cleaned, n_results=n_results)
        if TECHNIQUE_ID_RE.match(cleaned):
            return self.retrieve_by_technique_id(cleaned, n_results=n_results)
        return self.retrieve_by_telemetry(cleaned, n_results=n_results)

    def _retrieve_via_sqlite(self, query_text: str, n_results: int = 5) -> RetrievalResult:
        """Fallback keyword/metadata retrieval directly from chroma.sqlite3 when chromadb package is absent."""
        db_path = Path(CHROMA_DIR) / "chroma.sqlite3"
        if not db_path.exists():
            return RetrievalResult(query=query_text[:500], query_type="telemetry")

        # Extract any TXXXX technique IDs mentioned in query_text
        tids = sorted({m.group(0).upper() for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", query_text, re.I)})
        techniques: list[RetrievedTechnique] = []
        sigma_rules: list[RetrievedRule] = []

        try:
            conn = sqlite3.connect(str(db_path))
            cur = conn.cursor()
            for tid in tids[:3]:
                cur.execute(
                    "SELECT id, string_value FROM embedding_metadata WHERE key='technique_id' AND string_value=?",
                    (tid,),
                )
                for row_id, _ in cur.fetchall():
                    cur.execute("SELECT key, string_value FROM embedding_metadata WHERE id=?", (row_id,))
                    meta = {k: v for k, v in cur.fetchall() if v is not None}
                    techniques.append(self._meta_to_technique(meta, 0.95))

                cur.execute(
                    "SELECT id FROM embedding_metadata WHERE key='technique_ids' AND string_value LIKE ?",
                    (f"%{tid}%",),
                )
                for (row_id,) in cur.fetchall()[:n_results]:
                    cur.execute("SELECT key, string_value FROM embedding_metadata WHERE id=?", (row_id,))
                    meta = {k: v for k, v in cur.fetchall() if v is not None}
                    sigma_rules.append(self._meta_to_rule(meta, 0.85))
            conn.close()
        except Exception:
            pass

        return RetrievalResult(
            techniques=techniques[:n_results],
            sigma_rules=sigma_rules[:n_results],
            query=query_text[:500],
            query_type="telemetry",
        )

    def retrieve_by_technique_id(
        self,
        technique_id: str,
        n_results: int = RAG_TOP_K,
    ) -> RetrievalResult:
        tid = technique_id.strip().upper()
        techniques: dict[str, RetrievedTechnique] = {}

        exact = self._query_collection(
            self._attack_col,
            query_text=tid,
            n_results=1,
            where={"technique_id": tid},
        )
        for meta, score in exact:
            rt = self._meta_to_technique(meta, score)
            techniques[meta["technique_id"]] = rt

        query_text = tid
        if techniques:
            first = list(techniques.values())[0].technique
            query_text = f"{first.technique_id} {first.name} {' '.join(first.tactics)}"

        semantic_attack = self._query_collection(
            self._attack_col,
            query_text=query_text,
            n_results=n_results,
        )
        for meta, score in semantic_attack:
            mid = meta["technique_id"]
            if mid not in techniques or techniques[mid].score < score:
                techniques[mid] = self._meta_to_technique(meta, score)

        sigma_rules: dict[str, RetrievedRule] = {}

        sigma_meta = self._query_collection(
            self._sigma_col,
            query_text=query_text,
            n_results=n_results,
            where={"technique_ids": {"$contains": tid}},
        )
        for meta, score in sigma_meta:
            rid = meta.get("rule_id", "")
            if rid not in sigma_rules or sigma_rules[rid].score < score:
                sigma_rules[rid] = self._meta_to_rule(meta, score)

        sigma_semantic = self._query_collection(
            self._sigma_col,
            query_text=query_text,
            n_results=n_results,
        )
        for meta, score in sigma_semantic:
            rid = meta.get("rule_id", "")
            if rid not in sigma_rules or sigma_rules[rid].score < score:
                sigma_rules[rid] = self._meta_to_rule(meta, score)

        return RetrievalResult(
            techniques=sorted(techniques.values(), key=lambda t: t.score, reverse=True),
            sigma_rules=sorted(sigma_rules.values(), key=lambda r: r.score, reverse=True),
            query=tid,
            query_type="technique_id",
        )

    def retrieve_by_telemetry(
        self,
        telemetry_text: str,
        n_results: int = RAG_TOP_K,
    ) -> RetrievalResult:
        cleaned = telemetry_text.strip()[:1000]

        attack_results = self._query_collection(
            self._attack_col,
            query_text=cleaned,
            n_results=n_results,
        )
        techniques = [self._meta_to_technique(m, s) for m, s in attack_results]

        sigma_results = self._query_collection(
            self._sigma_col,
            query_text=cleaned,
            n_results=n_results,
        )
        sigma_rules = [self._meta_to_rule(m, s) for m, s in sigma_results]

        return RetrievalResult(
            techniques=techniques,
            sigma_rules=sigma_rules,
            query=cleaned,
            query_type="telemetry",
        )

    def _query_collection(
        self,
        collection,
        query_text: str,
        n_results: int,
        where: dict | None = None,
    ) -> list[tuple[dict, float]]:
        kwargs: dict = {
            "query_texts": [query_text],
            "n_results": n_results,
        }
        if where is not None:
            kwargs["where"] = where

        try:
            results = collection.query(**kwargs)
        except Exception:
            return []

        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        pairs: list[tuple[dict, float]] = []
        for meta, dist in zip(metadatas, distances):
            score = 1.0 - dist
            pairs.append((meta, score))
        return pairs

    @staticmethod
    def _meta_to_technique(meta: dict, score: float) -> RetrievedTechnique:
        return RetrievedTechnique(
            technique=AttackTechnique(
                technique_id=meta.get("technique_id", ""),
                name=meta.get("name", ""),
                tactics=[t.strip() for t in meta.get("tactics", "").split(",") if t.strip()],
                platforms=[p.strip() for p in meta.get("platforms", "").split(",") if p.strip()],
                data_sources=[
                    d.strip() for d in meta.get("data_sources", "").split(",") if d.strip()
                ],
                is_subtechnique=bool(meta.get("is_subtechnique", False)),
                url=meta.get("url", ""),
                stix_id=meta.get("stix_id", ""),
            ),
            score=score,
        )

    @staticmethod
    def _meta_to_rule(meta: dict, score: float) -> RetrievedRule:
        tags = [t.strip() for t in meta.get("tags", "").split(",") if t.strip()]
        return RetrievedRule(
            rule=SigmaRule(
                rule_id=meta.get("rule_id", ""),
                title=meta.get("title", ""),
                status=meta.get("status", ""),
                level=meta.get("level", ""),
                tags=tags,
                logsource={
                    k: meta.get(f"logsource_{k}", "")
                    for k in ("category", "product", "service")
                    if meta.get(f"logsource_{k}")
                },
                author=meta.get("author", ""),
                file_path=meta.get("file_path", ""),
            ),
            score=score,
        )
