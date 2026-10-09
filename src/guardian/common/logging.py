"""Structured logging framework for GUARDIAN using structlog.

Provides high-throughput JSON logging for automated SIEM/pipeline ingestion
and human-readable console formatting for local testing and debugging.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, TextIO

import structlog
from structlog.types import Processor


def setup_logging(
    json_logs: bool = True,
    log_level: str = "INFO",
    stream: TextIO | None = None,
) -> None:
    """Configure structured logging pipeline globally.

    Args:
        json_logs: If True, serialize records to newline-delimited JSON.
            If False, render colored human-readable text.
        log_level: Minimum logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
        stream: Optional output stream (defaults to sys.stdout).
    """
    out_stream = stream if stream is not None else sys.stdout
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", key="timestamp"),
    ]

    if json_logs:
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False if stream is not None else True)

    processors = [*shared_processors, renderer]

    structlog.reset_defaults()
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(file=out_stream),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None) -> Any:
    """Return a configured structlog logger instance.

    Args:
        name: Optional hierarchical logger name (e.g., 'guardian.pipeline').

    Returns:
        A contextual structlog bound logger.
    """
    return structlog.get_logger(name)
