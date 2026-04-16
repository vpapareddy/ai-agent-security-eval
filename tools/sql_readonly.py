from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from storage.db import get_connection


def execute_readonly_query(
    query: str,
    max_rows: int = 5,
    db_path: Optional[Path] = None,
) -> dict:
    clean_query = query.strip().rstrip(";")
    validate_query(clean_query)
    limited_query = f"SELECT * FROM ({clean_query}) AS readonly_query LIMIT {int(max_rows)}"

    with get_connection(db_path=db_path, readonly=True) as connection:
        cursor = connection.execute(limited_query)
        columns = [description[0] for description in cursor.description or []]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

    return {
        "query": clean_query,
        "columns": columns,
        "row_count": len(rows),
        "rows": rows,
    }


def validate_query(query: str) -> None:
    if not re.match(r"^\s*select\b", query, flags=re.IGNORECASE):
        raise ValueError("Only SELECT queries are allowed.")
    if ";" in query:
        raise ValueError("Multiple SQL statements are not allowed.")
