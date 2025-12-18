import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOG_LEVEL, LOG_FILE

def _build_handlers():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)
    return file_handler, console_handler


logger = logging.getLogger('bgp_tracer')
logger.setLevel(LOG_LEVEL)
if not logger.handlers:
    fh, ch = _build_handlers()
    logger.addHandler(fh)
    logger.addHandler(ch)

def setup_logger(name: str) -> logging.Logger:
    """
    Set up a new logger
    
    Args:
        name: Logger name
        
    Returns:
        logging.Logger: Configured logger instance
    """
    new_logger = logging.getLogger(name)
    new_logger.setLevel(LOG_LEVEL)
    if not new_logger.handlers:
        fh, ch = _build_handlers()
        new_logger.addHandler(fh)
        new_logger.addHandler(ch)
    return new_logger