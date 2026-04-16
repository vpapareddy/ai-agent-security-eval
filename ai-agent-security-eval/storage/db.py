from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import get_settings

SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        plan TEXT NOT NULL,
        status TEXT NOT NULL,
        balance_cents INTEGER NOT NULL,
        region TEXT NOT NULL,
        ssn_last4 TEXT,
        internal_note TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS support_tickets (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL,
        subject TEXT NOT NULL,
        status TEXT NOT NULL,
        priority TEXT NOT NULL,
        created_at TEXT NOT NULL,
        internal_summary TEXT,
        FOREIGN KEY(customer_id) REFERENCES customers(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        user_role TEXT NOT NULL,
        risk_tier TEXT NOT NULL,
        user_task TEXT NOT NULL,
        tools_considered_json TEXT NOT NULL,
        tools_executed_json TEXT NOT NULL,
        retrieved_docs_json TEXT NOT NULL,
        sql_queries_json TEXT NOT NULL,
        memory_action TEXT NOT NULL,
        memory_notes TEXT NOT NULL,
        findings_json TEXT NOT NULL,
        status TEXT NOT NULL,
        final_response TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        trace_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        tool_input TEXT NOT NULL,
        tool_output TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES runs(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS drafts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        trace_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        decision_type TEXT NOT NULL,
        allowed INTEGER NOT NULL,
        approval_required INTEGER NOT NULL,
        reason TEXT NOT NULL,
        rule_ids_json TEXT NOT NULL,
        input_payload TEXT NOT NULL,
        context_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES runs(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS memory_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        scope TEXT NOT NULL,
        content TEXT NOT NULL,
        source TEXT NOT NULL,
        trust_level TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES runs(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS eval_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scenario_id TEXT NOT NULL,
        category TEXT NOT NULL,
        expected_status TEXT NOT NULL,
        actual_status TEXT NOT NULL,
        passed INTEGER NOT NULL,
        run_id INTEGER,
        report_path TEXT,
        details_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES runs(id)
    )
    """,
]

MIGRATION_COLUMNS = {
    "runs": {
        "trace_id": "TEXT NOT NULL DEFAULT ''",
        "user_role": "TEXT NOT NULL DEFAULT 'support_agent'",
        "risk_tier": "TEXT NOT NULL DEFAULT 'medium'",
        "tools_considered_json": "TEXT NOT NULL DEFAULT '[]'",
        "tools_executed_json": "TEXT NOT NULL DEFAULT '[]'",
        "retrieved_docs_json": "TEXT NOT NULL DEFAULT '[]'",
        "sql_queries_json": "TEXT NOT NULL DEFAULT '[]'",
        "memory_action": "TEXT NOT NULL DEFAULT 'none'",
        "memory_notes": "TEXT NOT NULL DEFAULT ''",
        "findings_json": "TEXT NOT NULL DEFAULT '[]'",
    },
    "tool_calls": {
        "trace_id": "TEXT NOT NULL DEFAULT ''",
    },
    "policy_decisions": {
        "trace_id": "TEXT NOT NULL DEFAULT ''",
        "decision_type": "TEXT NOT NULL DEFAULT 'tool_call'",
        "rule_ids_json": "TEXT NOT NULL DEFAULT '[]'",
        "context_json": "TEXT NOT NULL DEFAULT '{}'",
    },
}


def init_db(db_path: Optional[Path] = None) -> None:
    with get_connection(db_path=db_path, readonly=False) as connection:
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        _apply_migrations(connection)
        connection.commit()


def get_connection(db_path: Optional[Path] = None, readonly: bool = False) -> sqlite3.Connection:
    settings = get_settings()
    database_path = (db_path or settings.db_path).resolve()
    database_path.parent.mkdir(parents=True, exist_ok=True)

    if readonly:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(database_path)

    connection.row_factory = sqlite3.Row
    return connection


def create_run(
    trace_id: str,
    agent_id: str,
    user_task: str,
    user_role: str,
    risk_tier: str,
    tools_considered: list[str],
    db_path: Optional[Path] = None,
) -> int:
    timestamp = utc_now()
    with get_connection(db_path=db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO runs (
                trace_id,
                agent_id,
                user_role,
                risk_tier,
                user_task,
                tools_considered_json,
                tools_executed_json,
                retrieved_docs_json,
                sql_queries_json,
                memory_action,
                memory_notes,
                findings_json,
                status,
                final_response,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace_id,
                agent_id,
                user_role,
                risk_tier,
                user_task,
                _json_dumps(tools_considered),
                _json_dumps([]),
                _json_dumps([]),
                _json_dumps([]),
                "none",
                "",
                _json_dumps([]),
                "running",
                "",
                timestamp,
                timestamp,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def update_run_trace(
    run_id: int,
    tools_executed: list[str],
    retrieved_docs: list[dict[str, Any]],
    sql_queries: list[str],
    findings: list[dict[str, Any]],
    memory_action: str = "none",
    memory_notes: str = "",
    db_path: Optional[Path] = None,
) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.execute(
            """
            UPDATE runs
            SET tools_executed_json = ?,
                retrieved_docs_json = ?,
                sql_queries_json = ?,
                findings_json = ?,
                memory_action = ?,
                memory_notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                _json_dumps(tools_executed),
                _json_dumps(retrieved_docs),
                _json_dumps(sql_queries),
                _json_dumps(findings),
                memory_action,
                memory_notes,
                utc_now(),
                run_id,
            ),
        )
        connection.commit()


def finalize_run(run_id: int, status: str, final_response: str, db_path: Optional[Path] = None) -> None:
    timestamp = utc_now()
    with get_connection(db_path=db_path) as connection:
        connection.execute(
            """
            UPDATE runs
            SET status = ?, final_response = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, final_response, timestamp, run_id),
        )
        connection.commit()


def record_tool_call(
    run_id: int,
    trace_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
    tool_output: dict[str, Any],
    status: str,
    db_path: Optional[Path] = None,
) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.execute(
            """
            INSERT INTO tool_calls (run_id, trace_id, tool_name, tool_input, tool_output, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                trace_id,
                tool_name,
                _json_dumps(tool_input),
                _json_dumps(tool_output),
                status,
                utc_now(),
            ),
        )
        connection.commit()


def record_policy_decision(
    run_id: int,
    trace_id: str,
    tool_name: str,
    decision_type: str,
    allowed: bool,
    reason: str,
    approval_required: bool,
    rule_ids: list[str],
    input_payload: dict[str, Any],
    context: dict[str, Any],
    db_path: Optional[Path] = None,
) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.execute(
            """
            INSERT INTO policy_decisions (
                run_id,
                trace_id,
                tool_name,
                decision_type,
                allowed,
                approval_required,
                reason,
                rule_ids_json,
                input_payload,
                context_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                trace_id,
                tool_name,
                decision_type,
                int(allowed),
                int(approval_required),
                reason,
                _json_dumps(rule_ids),
                _json_dumps(input_payload),
                _json_dumps(context),
                utc_now(),
            ),
        )
        connection.commit()


def create_draft_record(
    kind: str,
    subject: str,
    body: str,
    metadata: dict[str, Any],
    db_path: Optional[Path] = None,
) -> dict[str, Any]:
    created_at = utc_now()
    with get_connection(db_path=db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO drafts (kind, subject, body, metadata_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (kind, subject, body, _json_dumps(metadata), "draft", created_at),
        )
        connection.commit()
        draft_id = int(cursor.lastrowid)

    return {
        "id": draft_id,
        "kind": kind,
        "subject": subject,
        "status": "draft",
        "created_at": created_at,
    }


def create_memory_entry(
    run_id: int,
    scope: str,
    content: str,
    source: str,
    trust_level: str,
    status: str,
    db_path: Optional[Path] = None,
) -> int:
    with get_connection(db_path=db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO memory_entries (run_id, scope, content, source, trust_level, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, scope, content, source, trust_level, status, utc_now()),
        )
        connection.commit()
        return int(cursor.lastrowid)


def record_eval_result(
    scenario_id: str,
    category: str,
    expected_status: str,
    actual_status: str,
    passed: bool,
    details: dict[str, Any],
    run_id: Optional[int] = None,
    report_path: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.execute(
            """
            INSERT INTO eval_results (
                scenario_id,
                category,
                expected_status,
                actual_status,
                passed,
                run_id,
                report_path,
                details_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scenario_id,
                category,
                expected_status,
                actual_status,
                int(passed),
                run_id,
                report_path,
                _json_dumps(details),
                utc_now(),
            ),
        )
        connection.commit()


def fetch_runs(limit: int = 50, db_path: Optional[Path] = None) -> list[dict[str, Any]]:
    with get_connection(db_path=db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                trace_id,
                agent_id,
                user_role,
                risk_tier,
                user_task,
                tools_considered_json,
                tools_executed_json,
                retrieved_docs_json,
                sql_queries_json,
                memory_action,
                memory_notes,
                findings_json,
                status,
                final_response,
                created_at,
                updated_at
            FROM runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_row_to_run_summary(row) for row in rows]


def fetch_run_by_id(run_id: int, db_path: Optional[Path] = None) -> Optional[dict[str, Any]]:
    with get_connection(db_path=db_path) as connection:
        row = connection.execute(
            """
            SELECT
                id,
                trace_id,
                agent_id,
                user_role,
                risk_tier,
                user_task,
                tools_considered_json,
                tools_executed_json,
                retrieved_docs_json,
                sql_queries_json,
                memory_action,
                memory_notes,
                findings_json,
                status,
                final_response,
                created_at,
                updated_at
            FROM runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

        if row is None:
            return None

        tool_rows = connection.execute(
            """
            SELECT tool_name, tool_input, tool_output, status, created_at
            FROM tool_calls
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()
        policy_rows = connection.execute(
            """
            SELECT tool_name, decision_type, allowed, approval_required, reason, rule_ids_json, input_payload, context_json, created_at
            FROM policy_decisions
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()
        memory_rows = connection.execute(
            """
            SELECT scope, content, source, trust_level, status, created_at
            FROM memory_entries
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()

    run = _row_to_run_summary(row)
    run["tool_calls"] = [
        {
            "tool_name": tool_row["tool_name"],
            "tool_input": _json_loads(tool_row["tool_input"], {}),
            "tool_output": _json_loads(tool_row["tool_output"], {}),
            "status": tool_row["status"],
            "created_at": tool_row["created_at"],
        }
        for tool_row in tool_rows
    ]
    run["policy_decisions"] = [
        {
            "tool_name": policy_row["tool_name"],
            "decision_type": policy_row["decision_type"],
            "allowed": bool(policy_row["allowed"]),
            "approval_required": bool(policy_row["approval_required"]),
            "reason": policy_row["reason"],
            "rule_ids": _json_loads(policy_row["rule_ids_json"], []),
            "input_payload": _json_loads(policy_row["input_payload"], {}),
            "context": _json_loads(policy_row["context_json"], {}),
            "created_at": policy_row["created_at"],
        }
        for policy_row in policy_rows
    ]
    run["memory_entries"] = [
        {
            "scope": memory_row["scope"],
            "content": memory_row["content"],
            "source": memory_row["source"],
            "trust_level": memory_row["trust_level"],
            "status": memory_row["status"],
            "created_at": memory_row["created_at"],
        }
        for memory_row in memory_rows
    ]
    return run


def fetch_findings(limit: int = 50, db_path: Optional[Path] = None) -> dict[str, Any]:
    with get_connection(db_path=db_path) as connection:
        policy_rows = connection.execute(
            """
            SELECT
                pd.run_id,
                r.trace_id,
                pd.tool_name,
                pd.decision_type,
                pd.reason,
                pd.rule_ids_json,
                pd.context_json,
                pd.created_at
            FROM policy_decisions pd
            JOIN runs r ON r.id = pd.run_id
            WHERE pd.allowed = 0
            ORDER BY pd.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        eval_rows = connection.execute(
            """
            SELECT scenario_id, category, expected_status, actual_status, run_id, report_path, details_json, created_at
            FROM eval_results
            WHERE passed = 0
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "policy_blocks": [
            {
                "run_id": row["run_id"],
                "trace_id": row["trace_id"],
                "tool_name": row["tool_name"],
                "decision_type": row["decision_type"],
                "reason": row["reason"],
                "rule_ids": _json_loads(row["rule_ids_json"], []),
                "context": _json_loads(row["context_json"], {}),
                "created_at": row["created_at"],
            }
            for row in policy_rows
        ],
        "eval_failures": [
            {
                "scenario_id": row["scenario_id"],
                "category": row["category"],
                "expected_status": row["expected_status"],
                "actual_status": row["actual_status"],
                "run_id": row["run_id"],
                "report_path": row["report_path"],
                "details": _json_loads(row["details_json"], {}),
                "created_at": row["created_at"],
            }
            for row in eval_rows
        ],
    }


def reset_demo_data(db_path: Optional[Path] = None) -> None:
    with get_connection(db_path=db_path) as connection:
        for table_name in [
            "customers",
            "support_tickets",
            "runs",
            "tool_calls",
            "drafts",
            "policy_decisions",
            "memory_entries",
            "eval_results",
        ]:
            connection.execute("DELETE FROM {table}".format(table=table_name))
        connection.commit()


def insert_customers(customers: list[dict[str, Any]], db_path: Optional[Path] = None) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.executemany(
            """
            INSERT INTO customers (id, name, email, plan, status, balance_cents, region, ssn_last4, internal_note)
            VALUES (:id, :name, :email, :plan, :status, :balance_cents, :region, :ssn_last4, :internal_note)
            """,
            customers,
        )
        connection.commit()


def insert_support_tickets(tickets: list[dict[str, Any]], db_path: Optional[Path] = None) -> None:
    with get_connection(db_path=db_path) as connection:
        connection.executemany(
            """
            INSERT INTO support_tickets (id, customer_id, subject, status, priority, created_at, internal_summary)
            VALUES (:id, :customer_id, :subject, :status, :priority, :created_at, :internal_summary)
            """,
            tickets,
        )
        connection.commit()


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _apply_migrations(connection: sqlite3.Connection) -> None:
    for table_name, columns in MIGRATION_COLUMNS.items():
        existing = _get_existing_columns(connection, table_name)
        for column_name, definition in columns.items():
            if column_name not in existing:
                connection.execute(
                    "ALTER TABLE {table} ADD COLUMN {column} {definition}".format(
                        table=table_name,
                        column=column_name,
                        definition=definition,
                    )
                )


def _get_existing_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute("PRAGMA table_info({table})".format(table=table_name)).fetchall()
    return {row["name"] for row in rows}


def _row_to_run_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "trace_id": row["trace_id"],
        "agent_id": row["agent_id"],
        "user_role": row["user_role"],
        "risk_tier": row["risk_tier"],
        "user_task": row["user_task"],
        "tools_considered": _json_loads(row["tools_considered_json"], []),
        "tools_executed": _json_loads(row["tools_executed_json"], []),
        "retrieved_docs": _json_loads(row["retrieved_docs_json"], []),
        "sql_queries": _json_loads(row["sql_queries_json"], []),
        "memory_action": row["memory_action"],
        "memory_notes": row["memory_notes"],
        "findings": _json_loads(row["findings_json"], []),
        "status": row["status"],
        "final_response": row["final_response"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _json_dumps(value: Any) -> str:
    return json.dumps(value)


def _json_loads(value: Optional[str], default: Any = None) -> Any:
    if not value:
        return [] if default is None else default
    return json.loads(value)
