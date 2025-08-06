# utils/logger.py

"""
Logger Configuration for JustDos.

This module provides a centralized function to set up logging for the application.
It configures a logger that writes exclusively to a file.
"""

import logging
import sys
from typing import Optional

# Store the logger instance to prevent re-configuration.
_logger: Optional[logging.Logger] = None

class ConnectionErrorFilter(logging.Filter):
    """A custom filter to suppress repetitive connection error warnings."""
    def __init__(self, name: str = "") -> None:
        super().__init__(name)
        self.last_log_time = 0
        self.suppress_interval = 10  # seconds

    def filter(self, record: logging.LogRecord) -> bool:
        """Filters log records to reduce noise."""
        if "failed" in record.getMessage() and "Request" in record.getMessage():
            current_time = record.created
            if current_time - self.last_log_time < self.suppress_interval:
                return False
            self.last_log_time = current_time
        return True

def setup_logging() -> logging.Logger:
    global _logger
    if _logger:
        return _logger

    logger = logging.getLogger("JustDos")
    logger.setLevel(logging.INFO)

    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # File handler for detailed logging
    try:
        file_handler = logging.FileHandler('justdos_attack.log', mode='a', encoding='utf-8', delay=False)
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)
    except PermissionError:
        print("Warning: Cannot write to log file 'justdos_attack.log'", file=sys.stderr)

    logger.propagate = False
    _logger = logger
    return logger