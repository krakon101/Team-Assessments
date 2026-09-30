"""FastAPI Application Main Module.

Initializes database on startup, registers middleware, custom exception handlers,
API routes, and serves the static frontend demonstration interface.
"""
from contextlib import asynccontextmanager
import os
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.config import get_settings
from app.database import init_db
from app.errors import (
    AppException,
    app_exception_handler,
    general_exception_handler,
    validation_exception_handler
)
from app.routers.auth import router as auth_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager handling startup & shutdown events."""
    # Initialize database tables on startup
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise User Registration & Email OTP Verification API for EDABIP",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Custom Exception Handlers
app.add_exception_handler(AppException, app_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

# Include Authentication Router
app.include_router(auth_router)

# Mount Static Files for Demo Frontend
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def serve_demo_index():
    """Serve the interactive single-page demo UI."""
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "EDABIP Authentication API is operational. Visit /docs for Swagger UI."}


@app.get("/api/health", tags=["Health"])
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "environment": settings.APP_ENV
    }
