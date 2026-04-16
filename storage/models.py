from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RunTaskRequest(BaseModel):
    task: str = Field(min_length=3, max_length=4000)
    agent_id: str = Field(default="internal_copilot")
    user_role: str = Field(default="support_agent")
    risk_tier: str = Field(default="medium")
    approval_confirmed: bool = Field(default=False)


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    approval_required: bool = False
    rule_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class ToolCallPlan(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
