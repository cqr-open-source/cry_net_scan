from typing import List

from app.core.paths import TOOLS_LINUX_RUSTSCAN_PATH
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.models.target_type_config import TargetType
from app.modules.rustscan.rustscan_parser import parse_rustscan
from app.utils.subprocess_runner import subprocess_run


async def rustscan_scan(
    all_hosts: List[Host],
) -> None:
    """Performs network scanning using RustScan and Nmap to identify live hosts, open ports, and associated services.

    This function executes RustScan with Nmap integration to scan a list of IP addresses and domains, parsing the output to determine
    host availability, open TCP ports, and services running on those ports."""

    # Get needed targets from all_hosts
    targets: List[str] = []
    for host in all_hosts:
        if host.target_type == TargetType.domain.value:
            targets.append(host.target)
        else:
            targets.append(host.ip_address)

    command = [
        str(TOOLS_LINUX_RUSTSCAN_PATH),
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
