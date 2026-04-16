from __future__ import annotations

import logging
import re
from typing import Any
from uuid import uuid4

from agent.policy import (
    evaluate_memory_persistence,
    evaluate_tool_call,
    get_policy,
    sanitize_tool_output,
)
from storage.db import (
    create_memory_entry,
    create_run,
    finalize_run,
    record_policy_decision,
    record_tool_call,
    update_run_trace,
)
from tools.docs_search import search_docs
from tools.draft_action import save_draft
from tools.sql_readonly import execute_readonly_query

logger = logging.getLogger("agent.orchestrator")
EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.\w+")
CUSTOMER_ID_RE = re.compile(r"\bcustomer\s*(?:id)?\s*#?\s*(\d+)\b", flags=re.IGNORECASE)
TICKET_ID_RE = re.compile(r"\bticket\s*#?\s*(\d+)\b", flags=re.IGNORECASE)
SQL_RE = re.compile(r"(select\b.+)$", flags=re.IGNORECASE | re.DOTALL)
MEMORY_REQUEST_PATTERNS = [
    "remember ",
    "remember for future",
    "store this for later",
    "save this instruction",
    "persist this",
    "next time always",
]


def run_task(
    task: str,
    agent_id: str = "internal_copilot",
    user_role: str = "support_agent",
    risk_tier: str = "medium",
    approval_confirmed: bool = False,
) -> dict[str, Any]:
    trace_id = str(uuid4())
    considered_tools = plan_tool_sequence(task)
    logger.info(
        "Starting run trace_id=%s agent_id=%s user_role=%s risk_tier=%s tools_considered=%s",
        trace_id,
        agent_id,
        user_role,
        risk_tier,
        considered_tools,
    )
    run_id = create_run(
        trace_id=trace_id,
        agent_id=agent_id,
        user_task=task,
        user_role=user_role,
        risk_tier=risk_tier,
        tools_considered=considered_tools,
    )
    policy = get_policy(agent_id)
    executed_tools: list[str] = []
    executed_results: list[dict[str, Any]] = []
    retrieved_docs: list[dict[str, Any]] = []
    sql_queries: list[str] = []
    findings: list[dict[str, Any]] = []
    memory_action = "none"
    memory_notes = ""

    try:
        if should_attempt_memory_persistence(task):
            memory_payload = build_memory_payload(task)
            memory_decision = evaluate_memory_persistence(
                agent_id=agent_id,
                payload=memory_payload,
                user_role=user_role,
                risk_tier=risk_tier,
            )
            logger.info(
                "Policy decision trace_id=%s decision_type=memory_persistence allowed=%s rule_ids=%s reason=%s",
                trace_id,
                memory_decision.allowed,
                memory_decision.rule_ids,
                memory_decision.reason,
            )
            record_policy_decision(
                run_id=run_id,
                trace_id=trace_id,
                tool_name="memory_persistence",
                decision_type="memory_persistence",
                allowed=memory_decision.allowed,
                reason=memory_decision.reason,
                approval_required=memory_decision.approval_required,
                rule_ids=memory_decision.rule_ids,
                input_payload=memory_payload,
                context={"user_role": user_role, "risk_tier": risk_tier, "details": memory_decision.details},
            )

            if not memory_decision.allowed:
                memory_action = "blocked"
                memory_notes = memory_decision.reason
                findings.append(
                    {
                        "type": "memory_persistence",
                        "severity": "high",
                        "reason": memory_decision.reason,
                        "rule_ids": memory_decision.rule_ids,
                    }
                )
                update_run_trace(
                    run_id=run_id,
                    tools_executed=executed_tools,
                    retrieved_docs=retrieved_docs,
                    sql_queries=sql_queries,
                    findings=findings,
                    memory_action=memory_action,
                    memory_notes=memory_notes,
                )
                response_text = "Task blocked by policy before persisting memory: {reason}".format(
                    reason=memory_decision.reason
                )
                logger.warning("Blocked run trace_id=%s reason=%s", trace_id, response_text)
                finalize_run(run_id=run_id, status="blocked", final_response=response_text)
                return {
                    "run_id": run_id,
                    "trace_id": trace_id,
                    "agent_id": agent_id,
                    "status": "blocked",
                    "response": response_text,
                    "tools_considered": considered_tools,
                    "tools_used": executed_tools,
                }

            create_memory_entry(
                run_id=run_id,
                scope=memory_payload["scope"],
                content=memory_payload["content"],
                source=memory_payload["source"],
                trust_level="trusted",
                status="active",
            )
            memory_action = "stored"
            memory_notes = "Stored scoped trusted memory entry."
            logger.info("Stored scoped memory entry trace_id=%s", trace_id)

        for tool_name in considered_tools:
            tool_input = build_tool_input(
                tool_name=tool_name,
                task=task,
                previous_outputs=executed_results,
                agent_id=agent_id,
                approval_confirmed=approval_confirmed,
            )
            decision = evaluate_tool_call(
                agent_id=agent_id,
                tool_name=tool_name,
                payload=tool_input,
                user_role=user_role,
                risk_tier=risk_tier,
            )
            logger.info(
                "Policy decision trace_id=%s tool=%s allowed=%s rule_ids=%s reason=%s",
                trace_id,
                tool_name,
                decision.allowed,
                decision.rule_ids,
                decision.reason,
            )
            record_policy_decision(
                run_id=run_id,
                trace_id=trace_id,
                tool_name=tool_name,
                decision_type="tool_call",
                allowed=decision.allowed,
                reason=decision.reason,
                approval_required=decision.approval_required,
                rule_ids=decision.rule_ids,
                input_payload=tool_input,
                context={"user_role": user_role, "risk_tier": risk_tier, "details": decision.details},
            )

            if not decision.allowed:
                findings.append(
                    {
                        "type": "policy_block",
                        "severity": "high" if decision.approval_required else "medium",
                        "tool_name": tool_name,
                        "reason": decision.reason,
                        "rule_ids": decision.rule_ids,
                    }
                )
                record_tool_call(
                    run_id=run_id,
                    trace_id=trace_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    tool_output={"error": decision.reason},
                    status="blocked",
                )
                update_run_trace(
                    run_id=run_id,
                    tools_executed=executed_tools,
                    retrieved_docs=retrieved_docs,
                    sql_queries=sql_queries,
                    findings=findings,
                    memory_action=memory_action,
                    memory_notes=memory_notes,
                )
                response_text = "Task blocked by policy before '{tool_name}': {reason}".format(
                    tool_name=tool_name,
                    reason=decision.reason,
                )
                logger.warning("Blocked tool call trace_id=%s tool=%s reason=%s", trace_id, tool_name, decision.reason)
                finalize_run(run_id=run_id, status="blocked", final_response=response_text)
                return {
                    "run_id": run_id,
                    "trace_id": trace_id,
                    "agent_id": agent_id,
                    "status": "blocked",
                    "response": response_text,
                    "tools_considered": considered_tools,
                    "tools_used": executed_tools,
                }

            tool_output = execute_tool(tool_name=tool_name, tool_input=tool_input)
            logger.info("Executed tool trace_id=%s tool=%s", trace_id, tool_name)
            sanitized_output = sanitize_tool_output(
                tool_name=tool_name,
                output=tool_output,
                agent_id=agent_id,
            )
            executed_tools.append(tool_name)
            executed_results.append({"tool_name": tool_name, "input": tool_input, "output": sanitized_output})
            record_tool_call(
                run_id=run_id,
                trace_id=trace_id,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=sanitized_output,
                status="completed",
            )
            findings.extend(extract_findings_from_output(tool_name, sanitized_output))
            if tool_name == "docs_search":
                retrieved_docs.extend(
                    [
                        {
                            "document": result["document"],
                            "trusted": result.get("trusted", True),
                            "risk_flags": result.get("risk_flags", []),
                            "snippet": result.get("snippet", ""),
                        }
                        for result in sanitized_output.get("results", [])
                    ]
                )
            if tool_name == "sql_readonly":
                sql_queries.append(sanitized_output.get("query", ""))

        response_text = compose_final_response(
            task=task,
            tool_results=executed_results,
            findings=findings,
            memory_action=memory_action,
        )
        update_run_trace(
            run_id=run_id,
            tools_executed=executed_tools,
            retrieved_docs=retrieved_docs,
            sql_queries=sql_queries,
            findings=findings,
            memory_action=memory_action,
            memory_notes=memory_notes,
        )
        finalize_run(run_id=run_id, status="completed", final_response=response_text)
        logger.info("Completed run trace_id=%s status=completed tools_executed=%s", trace_id, executed_tools)
        return {
            "run_id": run_id,
            "trace_id": trace_id,
            "agent_id": agent_id,
            "status": "completed",
            "response": response_text,
            "tools_considered": considered_tools,
            "tools_used": executed_tools,
            "policy": policy,
        }
    except Exception as exc:  # pragma: no cover - defensive path
        findings.append({"type": "runtime_error", "severity": "high", "reason": str(exc)})
        update_run_trace(
            run_id=run_id,
            tools_executed=executed_tools,
            retrieved_docs=retrieved_docs,
            sql_queries=sql_queries,
            findings=findings,
            memory_action=memory_action,
            memory_notes=memory_notes,
        )
        response_text = "Run failed: {message}".format(message=exc)
        logger.exception("Run failed trace_id=%s", trace_id)
        finalize_run(run_id=run_id, status="failed", final_response=response_text)
        return {
            "run_id": run_id,
            "trace_id": trace_id,
            "agent_id": agent_id,
            "status": "failed",
            "response": response_text,
            "tools_considered": considered_tools,
            "tools_used": executed_tools,
        }


def plan_tool_sequence(task: str) -> list[str]:
    task_lower = task.lower()
    selected: list[str] = []

    if needs_sql_lookup(task_lower, task):
        selected.append("sql_readonly")

    if needs_docs_search(task_lower):
        selected.append("docs_search")

    if needs_draft(task_lower):
        selected.append("draft_action")

    if not selected and not should_attempt_memory_persistence(task):
        selected.append("docs_search")

    return selected


def build_tool_input(
    tool_name: str,
    task: str,
    previous_outputs: list[dict[str, Any]],
    agent_id: str,
    approval_confirmed: bool = False,
) -> dict[str, Any]:
    if tool_name == "sql_readonly":
        max_rows = get_policy(agent_id)["max_sql_rows"]
        return {"query": build_sql_query(task), "max_rows": max_rows}

    if tool_name == "docs_search":
        return {"query": task, "limit": 3}

    if tool_name == "draft_action":
        return build_draft_payload(
            task=task,
            previous_outputs=previous_outputs,
            approval_confirmed=approval_confirmed,
        )

    raise ValueError("Unsupported tool: {tool_name}".format(tool_name=tool_name))


def execute_tool(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "docs_search":
        return search_docs(query=tool_input["query"], limit=tool_input.get("limit", 3))
    if tool_name == "sql_readonly":
        return execute_readonly_query(
            query=tool_input["query"],
            max_rows=tool_input.get("max_rows", 5),
        )
    if tool_name == "draft_action":
        return save_draft(
            kind=tool_input["kind"],
            subject=tool_input["subject"],
            body=tool_input["body"],
            metadata=tool_input.get("metadata", {}),
        )
    raise ValueError("Unsupported tool: {tool_name}".format(tool_name=tool_name))


def build_sql_query(task: str) -> str:
    explicit_sql = extract_requested_sql(task)
    if explicit_sql:
        return explicit_sql

    task_lower = task.lower()
    email_match = EMAIL_RE.search(task)
    customer_match = CUSTOMER_ID_RE.search(task)
    ticket_match = TICKET_ID_RE.search(task)

    if "ssn" in task_lower:
        fields = "id, name, email, ssn_last4"
    elif "internal note" in task_lower or "internal notes" in task_lower:
        fields = "id, name, email, internal_note"
    else:
        fields = "id, name, email, plan, status, balance_cents, region"

    if email_match:
        email = email_match.group(0).replace("'", "''")
        return (
            "SELECT {fields} FROM customers WHERE lower(email) = lower('{email}')".format(
                fields=fields,
                email=email,
            )
        )

    if customer_match:
        customer_id = int(customer_match.group(1))
        return "SELECT {fields} FROM customers WHERE id = {customer_id}".format(
            fields=fields,
            customer_id=customer_id,
        )

    if ticket_match:
        ticket_id = int(ticket_match.group(1))
        ticket_fields = (
            "t.id, c.name AS customer_name, c.email, t.subject, t.status, t.priority, t.created_at"
        )
        if "internal summary" in task_lower:
            ticket_fields += ", t.internal_summary"
        return (
            "SELECT {fields} "
            "FROM support_tickets t "
            "JOIN customers c ON c.id = t.customer_id "
            "WHERE t.id = {ticket_id}".format(fields=ticket_fields, ticket_id=ticket_id)
        )

    return "SELECT id, name, email FROM customers"


def build_draft_payload(
    task: str,
    previous_outputs: list[dict[str, Any]],
    approval_confirmed: bool = False,
) -> dict[str, Any]:
    kind = "email" if "email" in task.lower() or EMAIL_RE.search(task) else "ticket"
    subject = "Draft for: {summary}".format(summary=task[:72].strip())
    context_lines = []

    for output in previous_outputs:
        tool_name = output["tool_name"]
        if tool_name == "docs_search":
            for result in output["output"].get("results", [])[:2]:
                context_lines.append(
                    "- Docs: {document} -> {snippet}".format(
                        document=result["document"],
                        snippet=result["snippet"],
                    )
                )
        if tool_name == "sql_readonly":
            for row in output["output"].get("rows", [])[:2]:
                context_lines.append("- Record: {row}".format(row=row))

    body_parts = [
        "This is a local draft only. It has not been sent or executed.",
        "",
        "Requested task: {task}".format(task=task),
    ]
    if context_lines:
        body_parts.extend(["", "Context:"] + context_lines)

    return {
        "kind": kind,
        "subject": subject,
        "body": "\n".join(body_parts),
        "metadata": {"source_tools": [entry["tool_name"] for entry in previous_outputs]},
        "approved": approval_confirmed,
    }


def build_memory_payload(task: str) -> dict[str, Any]:
    return {
        "scope": "user_session",
        "content": task,
        "source": "user_task",
        "trusted_source": False,
    }


def compose_final_response(
    task: str,
    tool_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    memory_action: str,
) -> str:
    messages = ["Completed task: {task}".format(task=task)]

    for result in tool_results:
        tool_name = result["tool_name"]
        output = result["output"]
        if tool_name == "docs_search":
            snippets = output.get("results", [])
            suspicious_count = sum(1 for item in snippets if item.get("risk_flags"))
            if snippets:
                top = snippets[0]
                messages.append(
                    "Docs search found {count} matching snippet(s); top match is from '{document}'.".format(
                        count=len(snippets),
                        document=top["document"],
                    )
                )
            if suspicious_count:
                messages.append(
                    "Detected {count} untrusted document snippet(s) with prompt-injection style content.".format(
                        count=suspicious_count
                    )
                )
        elif tool_name == "sql_readonly":
            rows = output.get("rows", [])
            messages.append("Read-only SQL lookup returned {count} row(s).".format(count=len(rows)))
        elif tool_name == "draft_action":
            messages.append(
                "Created local draft #{draft_id} with status '{status}'.".format(
                    draft_id=output["draft_id"],
                    status=output["status"],
                )
            )

    if memory_action == "stored":
        messages.append("Stored a scoped trusted memory entry.")

    high_findings = [finding for finding in findings if finding.get("severity") == "high"]
    if high_findings:
        messages.append("Recorded {count} high-severity finding(s) in the run trace.".format(count=len(high_findings)))

    return " ".join(messages)


def extract_findings_from_output(tool_name: str, output: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if tool_name == "docs_search":
        for result in output.get("results", []):
            if result.get("risk_flags"):
                findings.append(
                    {
                        "type": "untrusted_document",
                        "severity": "medium",
                        "document": result["document"],
                        "risk_flags": result["risk_flags"],
                    }
                )
    if tool_name == "sql_readonly" and output.get("redacted_fields"):
        findings.append(
            {
                "type": "redaction",
                "severity": "low",
                "fields": output["redacted_fields"],
            }
        )
    return findings


def extract_requested_sql(task: str) -> str:
    match = SQL_RE.search(task)
    if not match:
        return ""
    return match.group(1).strip().rstrip(";")


def should_attempt_memory_persistence(task: str) -> bool:
    lowered = task.lower()
    return any(pattern in lowered for pattern in MEMORY_REQUEST_PATTERNS)


def needs_sql_lookup(task_lower: str, task: str) -> bool:
    keywords = ["customer", "ticket", "database", "record", "lookup", "sql"]
    return any(keyword in task_lower for keyword in keywords) or bool(EMAIL_RE.search(task)) or bool(extract_requested_sql(task))


def needs_docs_search(task_lower: str) -> bool:
    keywords = ["doc", "docs", "policy", "runbook", "guide", "handbook", "search", "instructions"]
    return any(keyword in task_lower for keyword in keywords)


def needs_draft(task_lower: str) -> bool:
    keywords = ["draft", "email", "reply", "response", "follow up", "compose"]
    return any(keyword in task_lower for keyword in keywords)
