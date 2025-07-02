import asyncio
from typing import List

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.auth_scan.auth_single_scanner import _run_single_auth_scan


async def auth_scan(
    hosts: List[Host],
) -> None:
    """
    Initiates and manages asynchronous unauthorized access scans across a list of target hosts.

    This function iterates through each host provided, creates a scan task for it,
    and then runs all these tasks concurrently. Each scan is performed
    by the `_run_single_auth_scan` function, which is responsible for executing
    the actual unauthorized access.
    """
    scan_tasks = []
    for host in hosts:
        scan_tasks.append(
            _run_single_auth_scan(
                host=host,
                scanner_name=ScannerName.AUTH.value,
            )
        )

    # Run all scan tasks concurrently and collect results
    await asyncio.gather(*scan_tasks)

    return None
