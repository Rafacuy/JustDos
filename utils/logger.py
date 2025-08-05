# utils/logger.py

"""
Logger Configuration for JustDos.

This module provides a centralized function to set up logging for the application.
It configures a logger that writes to both a file and the console, ensuring that
attack details and potential errors are captured for later analysis.
"""

import logging
import sys
from typing import Optional

# Store the logger instance to prevent re-configuration.
_logger: Optional[logging.Logger] = None

def setup_logging() -> logging.Logger:
    global _logger
    if _logger:
        return _logger

    logger = logging.getLogger("JustDos")
    logger.setLevel(logging.INFO)

    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # File handler
    try:
        file_handler = logging.FileHandler('justdos_attack.log', mode='a', encoding='utf-8', delay=False)
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
    except PermissionError:
        print("Warning: Cannot write to log file 'justdos_attack.log'", file=sys.stderr)

    # Stream handler for real-time console output
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)

    logger.propagate = False
    _logger = logger
    return logger