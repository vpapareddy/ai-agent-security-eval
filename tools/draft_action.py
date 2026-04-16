from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from storage.db import create_draft_record


def save_draft(
    kind: str,
    subject: str,
    body: str,
    metadata: Optional[dict[str, Any]] = None,
    db_path: Optional[Path] = None,
) -> dict[str, Any]:
    draft = create_draft_record(
        kind=kind,
        subject=subject,
        body=body,
        metadata=metadata or {},
        db_path=db_path,
    )
    return {
        "draft_id": draft["id"],
        "status": draft["status"],
        "kind": draft["kind"],
        "subject": draft["subject"],
    }
