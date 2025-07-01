import asyncio
from typing import List, Dict, Any

from app.core.paths import TOOLS_SMB_PATH
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.smb_enumerator.smb_enumeration_single_scanner import _run_single_smb_scan


async def smb_enumeration_scan(
        hosts: List[Host],
) -> List[Dict[str, Any]]:
    """
    Executes an SMB enumeration scan against provided hosts using the smb_enum_module.py script.

    It runs the smb_enum_module.py via subprocess, then parses and processes the JSON output.
    This function is asynchronous to allow for concurrent scanning.
    """

    scan_tasks = []
    for host in hosts:
        scan_tasks.append(_run_single_smb_scan(host, str(TOOLS_SMB_PATH), ScannerName.SMB_ENUMERATION.value))

    # Run all scan tasks concurrently and collect results
    results = await asyncio.gather(*scan_tasks)

    # Filter out None results (e.g., if a task failed and returned None)
    all_smb_results = [res for res in results if res is not None]

    return all_smb_results
