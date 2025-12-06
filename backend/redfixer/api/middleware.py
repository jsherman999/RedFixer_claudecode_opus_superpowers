"""FastAPI middleware for logging, error handling, and CORS."""
import logging
import time
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Log request details and response status.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware or route handler

        Returns:
            HTTP response
        """
        # Start timer
        start_time = time.time()

        # Get request details
        method = request.method
        path = request.url.path
        client_host = request.client.host if request.client else "unknown"

        # Log request
        logger.info(f"Request started: {method} {path} from {client_host}")

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration = time.time() - start_time

        # Log response
        logger.info(
            f"Request completed: {method} {path} - "
            f"Status: {response.status_code} - "
            f"Duration: {duration:.3f}s"
        )

        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for catching unhandled exceptions and returning proper JSON errors."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Catch exceptions and return JSON error responses.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware or route handler

        Returns:
            HTTP response or JSON error response
        """
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            # Log the error
            logger.exception(
                f"Unhandled exception during request {request.method} {request.url.path}"
            )

            # Return JSON error response
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "error": str(exc),
                },
            )


def setup_cors(app: FastAPI, allow_origins: list = None) -> None:
    """
    Set up CORS middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
        allow_origins: List of allowed origins (default: ["*"] for development)
    """
    if allow_origins is None:
        allow_origins = ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def setup_middleware(app: FastAPI, enable_cors: bool = True) -> None:
    """
    Set up all middleware for the FastAPI application.

    Args:
        app: FastAPI application instance
        enable_cors: Whether to enable CORS middleware (default: True)
    """
    # Add error handling middleware first (outermost)
    app.add_middleware(ErrorHandlingMiddleware)

    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)

    # Add CORS if enabled
    if enable_cors:
        setup_cors(app)

    logger.info("Middleware setup completed")
