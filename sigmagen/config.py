"""Central configuration loaded from environment variables via python-dotenv."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = Path(os.getenv("SIGMAGEN_DATA_DIR", "")) or (BASE_DIR / "data")
ATTACK_DIR: Path = DATA_DIR / "attack"
SIGMA_DIR: Path = DATA_DIR / "sigma"

# Fall back to top-level BASE_DIR / "chroma" if DATA_DIR / "chroma" doesn't exist
_default_chroma = BASE_DIR / "chroma" if (BASE_DIR / "chroma" / "chroma.sqlite3").exists() else (DATA_DIR / "chroma")
CHROMA_DIR: Path = Path(os.getenv("SIGMAGEN_CHROMA_DIR", "")) or _default_chroma

for _d in (DATA_DIR, ATTACK_DIR, SIGMA_DIR, CHROMA_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# ATT&CK data source
# ---------------------------------------------------------------------------

ATTACK_JSON_URL: str = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
ATTACK_JSON_PATH: Path = (
    BASE_DIR / "attack" / "enterprise-attack.json"
    if (BASE_DIR / "attack" / "enterprise-attack.json").exists()
    else (ATTACK_DIR / "enterprise-attack.json")
)

# ---------------------------------------------------------------------------
# Sigma data source
# ---------------------------------------------------------------------------

SIGMA_REPO_URL: str = "https://github.com/SigmaHQ/sigma.git"
SIGMA_REPO_DIR: Path = SIGMA_DIR / "sigma"
SIGMA_STABLE_RULES_DIR: Path = SIGMA_REPO_DIR / "rules"

# ---------------------------------------------------------------------------
# ChromaDB
# ---------------------------------------------------------------------------

ATTACK_COLLECTION: str = "attack_techniques"
SIGMA_COLLECTION: str = "sigma_rules"
CHROMA_BATCH_SIZE: int = 100

# ---------------------------------------------------------------------------
# Embedding model
# ---------------------------------------------------------------------------

EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# ---------------------------------------------------------------------------
# LLM provider
# ---------------------------------------------------------------------------

LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "ollama").lower()
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

# Local Ollama (default for thesis local deployment)
OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")

# ---------------------------------------------------------------------------
# Generation & Verification parameters
# ---------------------------------------------------------------------------

GENERATION_TEMPERATURE: float = float(os.getenv("GENERATION_TEMPERATURE", "0.2"))
GENERATION_MAX_TOKENS: int = int(os.getenv("GENERATION_MAX_TOKENS", "4096"))
MAX_REPAIR_RETRIES: int = int(os.getenv("MAX_REPAIR_RETRIES", "2"))

# ---------------------------------------------------------------------------
# Wazuh XML Output Configuration (Matching LLM_API)
# ---------------------------------------------------------------------------

RULE_ID_MIN: int = int(os.getenv("RULE_ID_MIN", "100100"))
RULE_ID_MAX: int = int(os.getenv("RULE_ID_MAX", "109999"))
WAZUH_GROUP_WRAPPER: str = os.getenv("WAZUH_GROUP_WRAPPER", "ml_generated,sysmon,")

# ---------------------------------------------------------------------------
# Scoring Weights (Confidence Score 0-100% & Quality Gate)
# ---------------------------------------------------------------------------

WEIGHT_Q1_SYNTAX: float = float(os.getenv("WEIGHT_Q1_SYNTAX", "0.20"))
WEIGHT_Q2_DATA_LINKAGE: float = float(os.getenv("WEIGHT_Q2_DATA_LINKAGE", "0.30"))
WEIGHT_Q3_BEHAVIOR: float = float(os.getenv("WEIGHT_Q3_BEHAVIOR", "0.50"))
QUALITY_GATE_PASS_THRESHOLD: float = float(os.getenv("QUALITY_GATE_PASS_THRESHOLD", "80.0"))
QUALITY_GATE_WARN_THRESHOLD: float = float(os.getenv("QUALITY_GATE_WARN_THRESHOLD", "60.0"))

# ---------------------------------------------------------------------------
# RAG retrieval
# ---------------------------------------------------------------------------

RAG_TOP_K: int = int(os.getenv("RAG_TOP_K", "5"))
