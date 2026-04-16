from __future__ import annotations

import pytest

from scripts.seed_data import seed_project


@pytest.fixture()
def seeded_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    db_path = data_dir / "app.db"
    docs_dir = data_dir / "docs"

    monkeypatch.setenv("APP_DATA_DIR", str(data_dir))
    monkeypatch.setenv("APP_DB_PATH", str(db_path))
    monkeypatch.setenv("APP_DOCS_DIR", str(docs_dir))

    seed_project(db_path=db_path, docs_dir=docs_dir)
    return {"db_path": db_path, "docs_dir": docs_dir}

