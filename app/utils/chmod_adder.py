import asyncio
import logging

from app.models.system_config import SystemName


async def make_executable(
    tool_path: str,
    system_name: SystemName,
) -> None:
    if system_name is SystemName.WINDOWS:
        return None

    """Make module executable using async subprocess"""
    logger = logging.getLogger(__name__)

    chmod_process = await asyncio.create_subprocess_exec(
        "chmod",
        "+x",
        f"{tool_path}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await chmod_process.communicate()

    if chmod_process.returncode != 0:
        logger.error(f"chmod failed for {tool_path}: {stderr_bytes.decode().strip()}")
        return None

    logger.debug(f"Successfully set executable permissions for {tool_path}")
    return None
