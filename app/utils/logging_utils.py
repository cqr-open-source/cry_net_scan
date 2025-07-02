import logging
import os

from app.core.paths import LOG_FILE_PATH, LOG_PATH


async def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Configures the logging for the application.

    Sets up a root logger with a console handler and a file handler.
    Log messages will be displayed in the console and written to a file.
    """
    logger = logging.getLogger()
    logger.setLevel(log_level.upper())

    # Prevent duplicate handlers if called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Console Handler (StreamHandler)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level.upper())
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Check if the folder for logs exists
    os.makedirs(LOG_PATH, exist_ok=True)

    # File Handler
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_handler.setLevel(log_level.upper())
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info(
        f"Logging initialized. Log level: {log_level.upper()}. Log file: {LOG_FILE_PATH}"
    )

    return logger
