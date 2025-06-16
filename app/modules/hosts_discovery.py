import asyncio
import logging
from typing import List

from app.core.paths import TOOLS_LINUX_NMAP_PATH
from app.models.host_config import Host


# No longer needed.
# Kept here just in case.
async def discover_hosts(ips: List[str]) -> List[Host]:
    """
    Runs nmap -sn (host discovery) for the given list of targets.
    Parses the grepable output to determine which hosts are up/down.
    Returns  all scanned IP addresses with their status.
    """
    logger = logging.getLogger(__name__)

    if not ips:
        logger.error("No hosts provided to scan.")
        raise ValueError("IP list is empty.")

    command = [f"{str(TOOLS_LINUX_NMAP_PATH)}", "-sn", *ips, "-oG", "-"]
    logger.info(f"Running Nmap command: {' '.join(command)}")

    all_hosts: List[Host] = []

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stderr:
            logger.warning(f"Nmap stderr: {stderr.decode().strip()}")

        for line in stdout.decode().splitlines():
            if line.startswith("Host:"):
                parts = line.split()
                ip = parts[1]
                alive = True if "Status: Up" in line else False
                all_hosts.append(Host(ip_address=ip, is_alive=alive))
                logger.info(f"{ip} is alive.")

    except Exception as e:
        logger.error(f"Error running Nmap: {e}")

    return all_hosts
