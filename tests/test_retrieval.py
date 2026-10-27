"""Tests for the RAG retrieval module."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sigmagen.retrieval.retriever import SigmaGenRetriever, TECHNIQUE_ID_RE


def test_technique_id_regex_matches_base() -> None:
    """The regex should match base technique IDs like T1059."""
    assert TECHNIQUE_ID_RE.match("T1059")


def test_technique_id_regex_matches_subtechnique() -> None:
    """The regex should match sub-technique IDs like T1059.001."""
    assert TECHNIQUE_ID_RE.match("T1059.001")


def test_technique_id_regex_case_insensitive() -> None:
    """The regex should match lowercase t1059.001."""
    assert TECHNIQUE_ID_RE.match("t1059.001")


def test_technique_id_regex_rejects_freetext() -> None:
    """Free text should not match the technique ID regex."""
    assert not TECHNIQUE_ID_RE.match("powershell download cradle")


def test_technique_id_regex_rejects_partial() -> None:
    """Partial technique IDs should not match."""
    assert not TECHNIQUE_ID_RE.match("T10")


@patch("sigmagen.retrieval.retriever.get_collection")
def test_retrieve_dispatches_technique_id(mock_get_col: MagicMock) -> None:
    """Input matching TXXXX.XXX should be routed as technique_id query type."""
    mock_col = MagicMock()
    mock_col.query.return_value = {"metadatas": [[]], "distances": [[]]}
    mock_get_col.return_value = mock_col

    retriever = SigmaGenRetriever()
    result = retriever.retrieve("T1059.001")
    assert result.query_type == "technique_id"
    assert result.query == "T1059.001"


@patch("sigmagen.retrieval.retriever.get_collection")
def test_retrieve_dispatches_telemetry(mock_get_col: MagicMock) -> None:
    """Free text input should be routed as telemetry query type."""
    mock_col = MagicMock()
    mock_col.query.return_value = {"metadatas": [[]], "distances": [[]]}
    mock_get_col.return_value = mock_col

    retriever = SigmaGenRetriever()
    result = retriever.retrieve("powershell download cradle")
    assert result.query_type == "telemetry"


@patch("sigmagen.retrieval.retriever.get_collection")
def test_retrieve_by_technique_id_normalises_input(mock_get_col: MagicMock) -> None:
    """Technique ID input should be uppercased."""
    mock_col = MagicMock()
    mock_col.query.return_value = {"metadatas": [[]], "distances": [[]]}
    mock_get_col.return_value = mock_col

    retriever = SigmaGenRetriever()
    result = retriever.retrieve_by_technique_id("  t1059.001  ")
    assert result.query == "T1059.001"


@patch("sigmagen.retrieval.retriever.get_collection")
def test_retrieve_by_telemetry_truncates_input(mock_get_col: MagicMock) -> None:
    """Telemetry text should be truncated to 1000 characters."""
    mock_col = MagicMock()
    mock_col.query.return_value = {"metadatas": [[]], "distances": [[]]}
    mock_get_col.return_value = mock_col

    retriever = SigmaGenRetriever()
    long_text = "x" * 2000
    result = retriever.retrieve_by_telemetry(long_text)
    assert len(result.query) == 1000
