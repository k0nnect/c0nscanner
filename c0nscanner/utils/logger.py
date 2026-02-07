"""custom logging for c0nscanner."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from rich.logging import RichHandler


def setup_logger(
    verbose: bool = False,
    log_file: str | None = None,
) -> logging.Logger:
    """configure and return the c0nscanner logger."""
    logger = logging.getLogger("c0nscanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # console handler with rich formatting
    console_handler = RichHandler(
        show_time=False,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_fmt = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """get the c0nscanner logger instance."""
    return logging.getLogger("c0nscanner")
