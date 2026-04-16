from __future__ import annotations

import json
import re
from typing import Any, Optional

from storage.models import PolicyDecision

RISK_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
}

POLICY_STORE = {
    "internal_copilot": {
        "agent_id": "internal_copilot",
        "allowed_tools": ["docs_search", "sql_readonly", "draft_action"],
        "max_sql_rows": 5,
        "restricted_fields": [
            "ssn_last4",
            "internal_note",
            "internal_summary",
            "api_key",
            "password_hash",
        ],
        "redaction_token": "[REDACTED]",
        "approval_required": [
            "wire transfer",
            "reset password",
            "disable account",
            "delete customer",
            "refund over $500",
            "close the ticket",
            "close ticket",
            "export all customer data",
        ],
        "draft_execution_phrases": [
            "send now",
            "actually send",
            "execute now",
            "submit now",
            "close the account now",
        ],
        "sql_table_allowlist": {
            "customers": [
                "id",
                "name",
                "email",
                "plan",
                "status",
                "balance_cents",
                "region",
            ],
            "support_tickets": [
                "id",
                "customer_id",
                "subject",
                "status",
                "priority",
                "created_at",
            ],
        },
        "sql_row_scope_allowlist": [
            "id",
            "email",
            "customer_id",
        ],
        "docs_injection_patterns": [
            "ignore previous instructions",
            "ignore all previous instructions",
            "system prompt",
            "export all customer data",
            "bypass policy",
            "send it to",
        ],
        "memory_block_patterns": [
            "ignore previous instructions",
            "always reveal",
            "export all customer data",
            "bypass policy",
            "disable the guardrails",
        ],
        "roles": {
            "support_agent": {
                "allowed_tools": ["docs_search", "sql_readonly", "draft_action"],
                "max_risk_tier": "medium",
                "can_approve_actions": False,
            },
            "security_analyst": {
                "allowed_tools": ["docs_search", "sql_readonly"],
                "max_risk_tier": "high",
                "can_approve_actions": False,
            },
            "manager": {
                "allowed_tools": ["docs_search", "sql_readonly", "draft_action"],
                "max_risk_tier": "high",
                "can_approve_actions": True,
            },
        },
    }
}


def get_policy(agent_id: str) -> dict[str, Any]:
    policy = POLICY_STORE.get(agent_id, POLICY_STORE["internal_copilot"])
    return json.loads(json.dumps(policy))


def evaluate_tool_call(
    agent_id: str,
    tool_name: str,
    payload: dict[str, Any],
    user_role: str = "support_agent",
    risk_tier: str = "medium",
) -> PolicyDecision:
    policy = get_policy(agent_id)
    role_policy = get_role_policy(policy, user_role)
    role_decision = _check_role_and_risk(policy, role_policy, tool_name, user_role, risk_tier)
    if role_decision is not None:
        return role_decision

    if tool_name == "docs_search":
        return PolicyDecision(
            allowed=True,
            reason="Docs search allowed for this role and risk tier.",
            rule_ids=["allow.docs_search"],
            details={"user_role": user_role, "risk_tier": risk_tier},
        )

    if tool_name == "sql_readonly":
        return _evaluate_sql_query(policy=policy, payload=payload, user_role=user_role, risk_tier=risk_tier)

    if tool_name == "draft_action":
        return _evaluate_draft_request(
            policy=policy,
            role_policy=role_policy,
            payload=payload,
            user_role=user_role,
            risk_tier=risk_tier,
        )

    return PolicyDecision(
        allowed=False,
        reason="Unknown tool requested.",
        rule_ids=["deny.unknown_tool"],
        details={"tool_name": tool_name},
    )


def evaluate_memory_persistence(
    agent_id: str,
    payload: dict[str, Any],
    user_role: str = "support_agent",
    risk_tier: str = "medium",
) -> PolicyDecision:
    policy = get_policy(agent_id)
    role_policy = get_role_policy(policy, user_role)
    risk_check = _check_role_and_risk(policy, role_policy, "memory_persistence", user_role, risk_tier, check_tool=False)
    if risk_check is not None:
        return risk_check

    content = payload.get("content", "").lower()
    scope = payload.get("scope", "")
    blocked_patterns = [
        pattern for pattern in policy["memory_block_patterns"] if pattern in content
    ]

    if payload.get("source") == "user_task" and not payload.get("trusted_source", False):
        return PolicyDecision(
            allowed=False,
            reason="User-supplied instructions are not auto-persisted into memory.",
            rule_ids=["deny.memory.untrusted_source"],
            details={"scope": scope, "user_role": user_role},
        )

    if scope not in {"run_summary"}:
        return PolicyDecision(
            allowed=False,
            reason="Memory scope is not allowed.",
            rule_ids=["deny.memory.scope"],
            details={"scope": scope},
        )

    if blocked_patterns:
        return PolicyDecision(
            allowed=False,
            reason="Memory content matched unsafe persistence patterns.",
            rule_ids=["deny.memory.unsafe_content"],
            details={"matches": blocked_patterns},
        )

    return PolicyDecision(
        allowed=True,
        reason="Memory persistence allowed for trusted scoped content.",
        rule_ids=["allow.memory.scoped"],
        details={"scope": scope},
    )


def sanitize_tool_output(tool_name: str, output: dict[str, Any], agent_id: str) -> dict[str, Any]:
    policy = get_policy(agent_id)
    sanitized = json.loads(json.dumps(output))

    if tool_name == "sql_readonly":
        redacted_fields = []
        rows = []
        for row in sanitized.get("rows", []):
            clean_row = {}
            for key, value in row.items():
                if key.lower() in {field.lower() for field in policy["restricted_fields"]}:
                    clean_row[key] = policy["redaction_token"]
                    redacted_fields.append(key)
                else:
                    clean_row[key] = value
            rows.append(clean_row)
        sanitized["rows"] = rows
        sanitized["redacted_fields"] = sorted(set(redacted_fields))

    if tool_name == "docs_search":
        for result in sanitized.get("results", []):
            result["snippet"] = mask_text(result.get("snippet", ""), policy["restricted_fields"], policy["redaction_token"])

    return sanitized


def mask_text(text: str, restricted_fields: list[str], token: str) -> str:
    masked = text
    for field in restricted_fields:
        masked = re.sub(field, token, masked, flags=re.IGNORECASE)
    return masked


def detect_prompt_injection(text: str, agent_id: str = "internal_copilot") -> list[str]:
    policy = get_policy(agent_id)
    lowered = text.lower()
    return [
        pattern for pattern in policy["docs_injection_patterns"] if pattern in lowered
    ]


def get_role_policy(policy: dict[str, Any], user_role: str) -> dict[str, Any]:
    return policy["roles"].get(
        user_role,
        {
            "allowed_tools": ["docs_search"],
            "max_risk_tier": "low",
            "can_approve_actions": False,
        },
    )


def _check_role_and_risk(
    policy: dict[str, Any],
    role_policy: dict[str, Any],
    tool_name: str,
    user_role: str,
    risk_tier: str,
    check_tool: bool = True,
) -> Optional[PolicyDecision]:
    normalized_risk_tier = risk_tier if risk_tier in RISK_LEVELS else "medium"
    max_risk = role_policy.get("max_risk_tier", "low")

    if check_tool:
        if tool_name not in policy["allowed_tools"]:
            return PolicyDecision(
                allowed=False,
                reason="Tool is not allowed for this agent.",
                rule_ids=["deny.tool.agent_allowlist"],
                details={"tool_name": tool_name},
            )
        if tool_name not in role_policy.get("allowed_tools", []):
            return PolicyDecision(
                allowed=False,
                reason="Tool is not allowed for this role.",
                rule_ids=["deny.tool.role_allowlist"],
                details={"tool_name": tool_name, "user_role": user_role},
            )

    if RISK_LEVELS[normalized_risk_tier] > RISK_LEVELS.get(max_risk, 1):
        return PolicyDecision(
            allowed=False,
            reason="Requested risk tier exceeds the role's policy limit.",
            rule_ids=["deny.role.risk_tier"],
            details={"user_role": user_role, "risk_tier": normalized_risk_tier, "max_risk_tier": max_risk},
        )

    return None


def _evaluate_sql_query(
    policy: dict[str, Any],
    payload: dict[str, Any],
    user_role: str,
    risk_tier: str,
) -> PolicyDecision:
    query = payload.get("query", "")
    max_rows = int(payload.get("max_rows", 0))

    if not re.match(r"^\s*select\b", query, flags=re.IGNORECASE):
        return PolicyDecision(
            allowed=False,
            reason="SQL policy allows SELECT statements only.",
            rule_ids=["deny.sql.readonly"],
        )

    if ";" in query:
        return PolicyDecision(
            allowed=False,
            reason="Multiple SQL statements are not allowed.",
            rule_ids=["deny.sql.multistatement"],
        )

    if max_rows > policy["max_sql_rows"]:
        return PolicyDecision(
            allowed=False,
            reason="Requested row count exceeds the policy limit.",
            rule_ids=["deny.sql.max_rows"],
            details={"requested_rows": max_rows, "allowed_rows": policy["max_sql_rows"]},
        )

    tables, aliases = _extract_tables(query)
    if not tables:
        return PolicyDecision(
            allowed=False,
            reason="Could not determine the target SQL table.",
            rule_ids=["deny.sql.no_table"],
        )

    disallowed_tables = [table for table in tables if table not in policy["sql_table_allowlist"]]
    if disallowed_tables:
        return PolicyDecision(
            allowed=False,
            reason="SQL query referenced a table outside the allowlist.",
            rule_ids=["deny.sql.table_allowlist"],
            details={"tables": disallowed_tables},
        )

    selected_columns = _extract_selected_columns(query=query, aliases=aliases, allowed_tables=tables, policy=policy)
    if selected_columns is None:
        return PolicyDecision(
            allowed=False,
            reason="SQL query used wildcard or unsupported column expressions.",
            rule_ids=["deny.sql.column_expression"],
        )

    restricted_hits = []
    disallowed_columns = []
    for item in selected_columns:
        column_name = item["column"]
        table_name = item["table"]
        if column_name in policy["restricted_fields"]:
            restricted_hits.append(column_name)
        elif column_name not in policy["sql_table_allowlist"].get(table_name, []):
            disallowed_columns.append("{table}.{column}".format(table=table_name, column=column_name))

    if restricted_hits:
        return PolicyDecision(
            allowed=False,
            reason="SQL query references restricted field(s).",
            rule_ids=["deny.sql.restricted_field"],
            details={"fields": sorted(set(restricted_hits))},
        )

    if disallowed_columns:
        return PolicyDecision(
            allowed=False,
            reason="SQL query requested columns outside the allowlist.",
            rule_ids=["deny.sql.column_allowlist"],
            details={"columns": disallowed_columns},
        )

    if not _has_allowed_row_scope(query, policy["sql_row_scope_allowlist"]):
        return PolicyDecision(
            allowed=False,
            reason="SQL query was broader than the row-scope allowlist permits.",
            rule_ids=["deny.sql.row_scope"],
            details={"required_scope_fields": policy["sql_row_scope_allowlist"]},
        )

    return PolicyDecision(
        allowed=True,
        reason="SQL query passed read-only, table, column, and row-scope checks.",
        rule_ids=["allow.sql.readonly"],
        details={"tables": tables, "user_role": user_role, "risk_tier": risk_tier},
    )


def _evaluate_draft_request(
    policy: dict[str, Any],
    role_policy: dict[str, Any],
    payload: dict[str, Any],
    user_role: str,
    risk_tier: str,
) -> PolicyDecision:
    serialized_payload = json.dumps(payload).lower()
    risky_matches = [
        phrase for phrase in policy["approval_required"] if phrase in serialized_payload
    ]
    execution_matches = [
        phrase for phrase in policy["draft_execution_phrases"] if phrase in serialized_payload
    ]

    if execution_matches:
        return PolicyDecision(
            allowed=False,
            reason="Draft requests must stay non-executing and cannot be turned into live actions.",
            rule_ids=["deny.draft.execution_attempt"],
            details={"matches": execution_matches},
        )

    if risky_matches and not payload.get("approved", False):
        return PolicyDecision(
            allowed=False,
            reason="Risky draft content requires explicit approval first.",
            approval_required=True,
            rule_ids=["deny.draft.approval_required"],
            details={"matches": risky_matches},
        )

    if risky_matches and payload.get("approved", False) and not role_policy.get("can_approve_actions", False):
        return PolicyDecision(
            allowed=False,
            reason="This role cannot approve risky draft content.",
            approval_required=True,
            rule_ids=["deny.draft.role_cannot_approve"],
            details={"user_role": user_role, "risk_tier": risk_tier, "matches": risky_matches},
        )

    return PolicyDecision(
        allowed=True,
        reason="Draft request is allowed and remains local-only.",
        rule_ids=["allow.draft.local_only"],
        details={"user_role": user_role, "risk_tier": risk_tier},
    )


def _extract_tables(query: str) -> tuple[list[str], dict[str, str]]:
    table_matches = re.findall(
        r"\b(?:from|join)\s+([a-zA-Z_][\w]*)\s*(?:as\s+)?([a-zA-Z_][\w]*)?(?=(?:\s+(?:on|where|join|order|group|limit))|$)",
        query,
        flags=re.IGNORECASE,
    )
    tables = []
    aliases: dict[str, str] = {}
    for table_name, alias in table_matches:
        normalized_table = table_name.lower()
        tables.append(normalized_table)
        aliases[normalized_table] = normalized_table
        if alias:
            aliases[alias.lower()] = normalized_table
    return list(dict.fromkeys(tables)), aliases


def _extract_selected_columns(
    query: str,
    aliases: dict[str, str],
    allowed_tables: list[str],
    policy: dict[str, Any],
) -> Optional[list[dict[str, str]]]:
    select_match = re.search(r"\bselect\b(.*?)\bfrom\b", query, flags=re.IGNORECASE | re.DOTALL)
    if not select_match:
        return None

    columns = []
    for raw_column in [part.strip() for part in select_match.group(1).split(",")]:
        if not raw_column or raw_column == "*" or raw_column.endswith(".*"):
            return None

        source = re.split(r"\bas\b", raw_column, flags=re.IGNORECASE)[0].strip()
        if not re.match(r"^[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)?$", source):
            return None

        if "." in source:
            qualifier, column_name = source.split(".", 1)
            table_name = aliases.get(qualifier.lower())
            if table_name is None:
                return None
        else:
            column_name = source.lower()
            matching_tables = [
                table_name
                for table_name in allowed_tables
                if column_name in policy["sql_table_allowlist"].get(table_name, [])
                or column_name in policy["restricted_fields"]
            ]
            if len(matching_tables) != 1:
                return None
            table_name = matching_tables[0]

        columns.append({"table": table_name, "column": column_name.lower()})

    return columns


def _has_allowed_row_scope(query: str, allowed_scope_fields: list[str]) -> bool:
    where_match = re.search(
        r"\bwhere\b(.*?)(?:\border\b|\bgroup\b|\blimit\b|$)",
        query,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not where_match:
        return False

    where_text = where_match.group(1).lower()
    return any(
        field in where_text
        for field in allowed_scope_fields
    )
