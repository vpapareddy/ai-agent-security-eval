from fastapi import APIRouter, HTTPException

from agent.policy import get_policy
from app.config import get_settings
from storage.db import fetch_findings, fetch_run_by_id, fetch_runs

router = APIRouter()


@router.get("/runs")
def get_runs() -> dict:
    settings = get_settings()
    return {"runs": fetch_runs(limit=settings.default_run_limit)}


@router.get("/runs/{run_id}")
def get_run_detail(run_id: int) -> dict:
    run = fetch_run_by_id(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return run


@router.get("/findings")
def get_findings() -> dict:
    settings = get_settings()
    return fetch_findings(limit=settings.default_run_limit)


@router.get("/policy")
def get_policy_route() -> dict:
    settings = get_settings()
    return get_policy(settings.agent_name)


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}
