import logging
from typing import Dict, Any

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.smb_enumerator.smb_enumeration_parser import parse_smb_enumeration
from tools.smb_enumeration.run_smb_enumeration import run_smb_enumeration


async def _run_single_smb_scan(
    host: Host,
    scanner_name: ScannerName,
) -> Dict[str, Any] | None:
    """
    Runs the smb_enum_module.py script for a single target IP address.
    """
    logger = logging.getLogger(__name__)

    target_ip = host.ip_address

    logger.info(f"Running {scanner_name} for {target_ip}")
    result: str = run_smb_enumeration(target_ip)

    try:
        await parse_smb_enumeration(
            temp_result=result,
            host=host,
            target_ip=target_ip,
            scanner_name=scanner_name,
        )

    except Exception as e:
        logger.error(
            f"An unexpected error occurred during {scanner_name} for {target_ip}: {e}"
        )
