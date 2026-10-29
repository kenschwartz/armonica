"""Timestamps on every log line, so the log answers "when did Claude read the vault".

Two sources write the service log: uvicorn's own loggers (access lines) and the
root handler the mcp SDK installs, which our "armonica" loggers propagate
to. Both get the same ISO-8601 local timestamp with offset.
"""

from __future__ import annotations

import copy
import logging

DATEFMT = "%Y-%m-%dT%H:%M:%S%z"
APP_FORMAT = "%(asctime)s %(message)s"


def uvicorn_log_config() -> dict:
    """uvicorn's default logging config with a timestamp in front of every format."""
    from uvicorn.config import LOGGING_CONFIG

    cfg = copy.deepcopy(LOGGING_CONFIG)
    for formatter in cfg["formatters"].values():
        formatter["fmt"] = "%(asctime)s " + formatter["fmt"]
        formatter["datefmt"] = DATEFMT
    return cfg


def stamp_root() -> None:
    """Timestamp the root handlers (call after build_app: the SDK installs them there)."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO)
    stamp = logging.Formatter(APP_FORMAT, DATEFMT)
    for handler in root.handlers:
        handler.setFormatter(stamp)
