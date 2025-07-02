import logging
import os
from typing import List

from app.core.paths import AFROG_TEMP_PATH, NUCLEI_PATH, HOSTS_PATH, WEBANALYZE_PATH


async def delete_temp_files() -> None:
    logger = logging.getLogger(__name__)

    temp_files: List[str] = [
        HOSTS_PATH,
        NUCLEI_PATH,
        AFROG_TEMP_PATH,
        WEBANALYZE_PATH,
    ]
    for file in temp_files:
        if os.path.exists(file):
            os.remove(file)
            logger.debug(f"Temp file {file} deleted.")
        else:
            logger.debug(f"File {file} does not exists. Skipping...")

    return None
