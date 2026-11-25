"""Application factory. Run with:  uvicorn app.main:app --reload"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.api.routes import health, partners
from app.core.config import Settings, get_settings
from app.core.error_handlers import register_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware
from app.core.redis import create_redis
from app.core.request_limits import RequestSizeLimitMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.db.session import create_engine, create_session_factory
from app.services.sms import create_sms_sender
from app.services.awareness_gradio import mount_awareness_gradio
from app.services.awareness_scheduler import run_due_awareness

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = create_engine(settings)
        redis = create_redis(settings)
        app.state.settings = settings
        app.state.engine = engine
        app.state.session_factory = create_session_factory(engine)
        app.state.redis = redis
        app.state.sms_sender = getattr(app.state, "sms_sender", None) or create_sms_sender(settings)
        scheduler_stop = asyncio.Event()
        scheduler_task = None
        if settings.awareness_scheduler_enabled:
            scheduler_task = asyncio.create_task(
                _awareness_scheduler_loop(app, scheduler_stop),
                name="continuous-awareness-scheduler",
            )
            app.state.awareness_scheduler_task = scheduler_task
            logger.info("awareness_scheduler_started", extra={
                "interval_seconds": settings.awareness_scheduler_interval_seconds,
                "delivery_mode": settings.sms_provider,
            })
        else:
            app.state.awareness_scheduler_task = None
            logger.info("awareness_scheduler_disabled")
        logger.info("startup", extra={"environment": settings.environment})
        try:
            yield
        finally:
            scheduler_stop.set()
            if scheduler_task is not None:
                await scheduler_task
            await redis.aclose()
            await engine.dispose()
            logger.info("shutdown")

    app = FastAPI(
        title=settings.app_name,
        lifespan=lifespan,
        debug=settings.debug,
        docs_url=None if settings.is_production_like else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production_like else "/openapi.json",
    )

    # added last = outermost: request id is set before anything else runs
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"],
        )
    if settings.is_production_like:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    if settings.max_request_body_bytes > 0:
        app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    if settings.security_headers:
        frame_ancestors = list(settings.cors_origins)
        if not settings.is_production_like:
            frame_ancestors.extend(("http://localhost:5173", "http://127.0.0.1:5173"))
        app.add_middleware(
            SecurityHeadersMiddleware,
            production=settings.is_production_like,
            frame_ancestors=frame_ancestors,
        )
    app.add_middleware(RequestContextMiddleware)

    register_error_handlers(app)
    app.include_router(health.router)  # unversioned: probes shouldn't move with API versions
    app.include_router(api_router, prefix=settings.api_prefix)
    # Keep the requested /api/v1 partner integration paths available alongside
    # this project's existing /v1 API prefix.
    app.include_router(partners.router, prefix="/api/v1")
    return mount_awareness_gradio(app, settings)


async def _awareness_scheduler_loop(app: FastAPI, stop: asyncio.Event) -> None:
    """Run recurring awareness dispatch in this API process, at the configured interval."""
    interval = app.state.settings.effective_awareness_scheduler_interval_seconds
    while not stop.is_set():
        try:
            async with app.state.session_factory() as db:
                result = await run_due_awareness(
                    db,
                    app.state.sms_sender,
                    trigger_source="in_process",
                    sms_operational=app.state.settings.sms_provider == "http",
                    allow_test_schedule=app.state.settings.environment in {"development", "test"},
                    groq_api_key=(app.state.settings.groq_api_key.get_secret_value()
                                  if app.state.settings.groq_api_key else None),
                )
            logger.info("awareness_scheduler_run_finished", extra=result)
        except Exception:
            logger.exception("awareness_scheduler_run_failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue


app = create_app()
