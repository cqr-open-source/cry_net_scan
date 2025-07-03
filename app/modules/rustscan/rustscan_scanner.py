import logging
import pathlib
from typing import List, Set

import app.utils.paths_getter as paths_getter
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.rustscan.rustscan_parser import parse_rustscan
from app.utils.subprocess_runner import subprocess_run


async def rustscan_scan(
    all_hosts: List[Host],
) -> None:
    """
    Performs network scanning using RustScan and Nmap to identify live hosts, open ports, and associated services.

    This function executes RustScan with Nmap integration to scan a list of IP addresses parsing the output to determine
    host availability, open TCP ports, and services running on those ports.

    Target: prefers IP, list of IPs etc., because of Nmap.
    """

    logger = logging.getLogger(__name__)

    # Get the necessary targets from all_hosts
    targets: Set[str] = {host.ip_address for host in all_hosts}

    if not targets:
        logger.info("No targets found for RustScan. Skipping.")
        return None

    rustscan_path: pathlib.Path = paths_getter.TOOLS_PATHS[
        ScannerName.RUSTSCAN.value.lower()
    ]

    command = [
        str(rustscan_path),
        "-a",
        ",".join(targets),
        "--no-banner",
        "--ulimit",
        "30000",
        "--",
        "-sV",
        "-sC",
        "-oG",
        "-",
    ]

    result: str = await subprocess_run(
        command=command,
        module_name=ScannerName.RUSTSCAN.value,
    )

    if result:
        await parse_rustscan(stdout=result, all_hosts=all_hosts)

    return None
