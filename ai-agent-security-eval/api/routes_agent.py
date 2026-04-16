from fastapi import APIRouter

from agent.orchestrator import run_task
from storage.models import RunTaskRequest

router = APIRouter()


@router.post("/run-task")
def run_task_route(payload: RunTaskRequest) -> dict:
    return run_task(
        task=payload.task,
        agent_id=payload.agent_id,
        user_role=payload.user_role,
        risk_tier=payload.risk_tier,
        approval_confirmed=payload.approval_confirmed,
    )
