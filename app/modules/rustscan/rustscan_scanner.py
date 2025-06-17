import asyncio
import logging

from app.core.paths import TOOLS_LINUX_RUSTSCAN_PATH
from app.models.host_config import Host
from app.modules.rustscan.rustscan_parser import parse_rustscan


async def rustscan_scan(
    all_hosts: set[Host],
) -> None:
    """Performs network scanning using RustScan and Nmap to identify live hosts, open ports, and associated services.

    This function executes RustScan with Nmap integration to scan a list of IP addresses, parsing the output to determine
    host availability, open TCP ports, and services running on those ports."""
    logger = logging.getLogger(__name__)

    ips = [host.ip_address for host in all_hosts]

    command = [
        str(TOOLS_LINUX_RUSTSCAN_PATH),
        "-a",
        ",".join(ips),
        "--no-banner",
        "--ulimit",
        "30000",
        "--",
        "-sV",
        "-sC",
        "-oG",
        "-",
    ]
    logger.info(f"Running RUSTSCAN command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, stderr_bytes = await process.communicate()

        stdout = stdout_bytes.decode("utf-8").strip()
        stderr = stderr_bytes.decode("utf-8").strip()

        if stderr:
            logger.warning(f"RUSTSCAN stderr: {stderr}")

        await parse_rustscan(stdout=stdout, all_hosts=all_hosts)

    except Exception as e:
        logger.error(f"Error running RUSTSCAN or parsing output: {e}", exc_info=True)

    return None
