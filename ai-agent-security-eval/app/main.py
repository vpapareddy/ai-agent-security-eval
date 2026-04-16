from contextlib import asynccontextmanager
import logging
from time import perf_counter

from fastapi import FastAPI, Request

from api.routes_agent import router as agent_router
from app.config import get_settings
from app.logging_config import configure_logging
from api.routes_system import router as system_router
from scripts.seed_data import seed_project
from storage.db import init_db

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(
        "Starting AI Agent Security Evaluation app host=%s port=%s data_dir=%s auto_seed=%s",
        settings.host,
        settings.port,
        settings.data_dir,
        settings.auto_seed,
    )
    init_db()
    if settings.auto_seed:
        logger.info("Auto-seeding local data on startup")
        seed_project(db_path=settings.db_path, docs_dir=settings.docs_dir, reset_existing=False)
    yield
    logger.info("Shutting down AI Agent Security Evaluation app")


app = FastAPI(
    title="AI Agent Security Evaluation",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started_at = perf_counter()
    logger.info("Handling request method=%s path=%s", request.method, request.url.path)
    response = await call_next(request)
    duration_ms = round((perf_counter() - started_at) * 1000, 2)
    logger.info(
        "Completed request method=%s path=%s status_code=%s duration_ms=%s",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


app.include_router(agent_router)
app.include_router(system_router)
