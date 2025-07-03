import asyncio
import logging
from typing import List

from app.core.paths import ROOT_PATH


async def subprocess_run(
    command: List[str],
    module_name: str,
) -> str:
    logger = logging.getLogger(__name__)

    logger.info(f"Running {module_name} command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(ROOT_PATH),
        )

        stdout_bytes, stderr_bytes = await process.communicate()

        return stdout_bytes.decode("utf-8").strip()

    except Exception as e:
        logger.error(
            f"Error running {module_name} or parsing output: {e}", exc_info=True
        )
        return ""
