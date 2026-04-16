from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    data_dir: Path
    docs_dir: Path
    db_path: Path
    agent_name: str
    default_run_limit: int
    host: str
    port: int
    log_level: str
    auto_seed: bool
    optional_llm_api_key: str


def get_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = Path(os.getenv("APP_DATA_DIR", base_dir / "data")).resolve()
    docs_dir = Path(os.getenv("APP_DOCS_DIR", data_dir / "docs")).resolve()
    db_path = Path(os.getenv("APP_DB_PATH", data_dir / "app.db")).resolve()
    return Settings(
        base_dir=base_dir,
        data_dir=data_dir,
        docs_dir=docs_dir,
        db_path=db_path,
        agent_name=os.getenv("APP_AGENT_NAME", "internal_copilot"),
        default_run_limit=int(os.getenv("APP_DEFAULT_RUN_LIMIT", "50")),
        host=os.getenv("APP_HOST", "127.0.0.1"),
        port=int(os.getenv("APP_PORT", "8000")),
        log_level=os.getenv("APP_LOG_LEVEL", "INFO").upper(),
        auto_seed=parse_bool(os.getenv("APP_AUTO_SEED", "false")),
        optional_llm_api_key=os.getenv("OPTIONAL_LLM_API_KEY", ""),
    )


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
