import logging
import sys
from typing import Dict, Any

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.smb_enumerator.smb_enumeration_parser import parse_smb_enumeration
from app.utils.subprocess_runner import subprocess_run


async def _run_single_smb_scan(
        host: Host,
        # target_ip: str,
        script_path: str,
        scanner_name: ScannerName,
) -> Dict[str, Any] | None:
    """
    Runs the smb_enum_module.py script for a single target IP address.
    """
    logger = logging.getLogger(__name__)

    target_ip = host.ip_address

    try:
        # Call the generic subprocess_run utility
        stdout_decoded = await subprocess_run(
            command=[sys.executable, script_path, target_ip],
            module_name=scanner_name,
        )

        if not stdout_decoded:  # subprocess_run returns empty string on error
            logger.error(
                f"{scanner_name} subprocess for {target_ip} returned empty output, indicating an error.")
            return

        await parse_smb_enumeration(
            stdout_decoded=stdout_decoded,
            host=host,
            target_ip=target_ip,
            scanner_name=scanner_name,
        )

    except Exception as e:
        logger.error(f"An unexpected error occurred during {scanner_name} for {target_ip}: {e}")
