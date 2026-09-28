"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes import (
    alerts,
    cases,
    correlations,
    data_assets,
    dataset_events,
    dataset_upload,
    events,
    health,
    incidents,
    investigations,
    response,
    risk,
    settings as settings_routes,
    threat_intel,
)
from .config import get_settings
from .database import get_session, init_db

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if get_session not in app.dependency_overrides:
        init_db()
    logger.info("IncidentForge API started", extra={"environment": settings.environment})
    yield


app = FastAPI(title=settings.application_name, version="0.1.0", lifespan=lifespan)

cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(correlations.router)
app.include_router(incidents.router)
app.include_router(risk.router)
app.include_router(settings_routes.router)
app.include_router(threat_intel.router)
app.include_router(investigations.router)
app.include_router(cases.router)
app.include_router(response.router)
# v2: Dataset Security Operations
app.include_router(data_assets.router)
app.include_router(dataset_events.router)
app.include_router(dataset_upload.router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning("Request validation failed", extra={"path": request.url.path, "error_count": len(exc.errors())})
    return JSONResponse(status_code=422, content={"detail": exc.errors()})
