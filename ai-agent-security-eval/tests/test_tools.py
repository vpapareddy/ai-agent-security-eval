from __future__ import annotations

import pytest

from storage.db import get_connection
from tools.docs_search import search_docs
from tools.draft_action import save_draft
from tools.sql_readonly import execute_readonly_query


def test_docs_search_returns_seeded_snippets(seeded_env):
    result = search_docs("refund policy approval", docs_dir=seeded_env["docs_dir"])
    assert result["results"]
    assert result["results"][0]["document"] == "refund_policy.md"


def test_docs_search_flags_prompt_injection_document(seeded_env):
    result = search_docs("account override instructions", docs_dir=seeded_env["docs_dir"])
    flagged = [item for item in result["results"] if item["document"] == "ops_override_note.md"]
    assert flagged
    assert flagged[0]["risk_flags"]
    assert not flagged[0]["trusted"]


def test_sql_readonly_allows_select_and_rejects_writes(seeded_env):
    result = execute_readonly_query(
        "SELECT id, email FROM customers WHERE id = 1",
        db_path=seeded_env["db_path"],
        max_rows=3,
    )
    assert result["row_count"] == 1
    assert result["rows"][0]["email"] == "jamie.lee@acme.test"

    with pytest.raises(ValueError):
        execute_readonly_query(
            "UPDATE customers SET status = 'closed' WHERE id = 1",
            db_path=seeded_env["db_path"],
        )


def test_draft_action_saves_local_draft(seeded_env):
    draft = save_draft(
        kind="email",
        subject="Follow-up",
        body="This is a local-only draft.",
        metadata={"ticket_id": 101},
        db_path=seeded_env["db_path"],
    )
    assert draft["status"] == "draft"

    with get_connection(db_path=seeded_env["db_path"]) as connection:
        row = connection.execute("SELECT kind, subject, status FROM drafts WHERE id = ?", (draft["draft_id"],)).fetchone()
    assert row["kind"] == "email"
    assert row["subject"] == "Follow-up"
