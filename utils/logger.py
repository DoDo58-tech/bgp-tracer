import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOG_LEVEL, LOG_FILE

# Track which file paths already have an attached handler so repeated
_HANDLER_PATHS: set[str] = set()


def _build_handlers():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if LOG_FILE in _HANDLER_PATHS:
        # Subsequent loggers share the parent ``bgp_tracer`` file
        null_handler = logging.NullHandler()
        null_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(LOG_LEVEL)
        stream_handler.setFormatter(formatter)
        return null_handler, stream_handler

    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)
    _HANDLER_PATHS.add(LOG_FILE)
    return file_handler, console_handler


logger = logging.getLogger('bgp_tracer')
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    fh, ch = _build_handlers()
    logger.addHandler(fh)
    logger.addHandler(ch)


def setup_logger(name):
    """Create (or fetch) a child logger that shares the parent's handlers.

    Repeated calls with the same ``name`` return a logger with at most
    one set of handlers attached — preventing the FD leak that occurred
    when callers re-invoked ``setup_logger`` per request.
    """
    new_logger = logging.getLogger(name)
    new_logger.setLevel(LOG_LEVEL)
    if not new_logger.handlers:
        fh, ch = _build_handlers()
        new_logger.addHandler(fh)
        new_logger.addHandler(ch)
    return new_logger
