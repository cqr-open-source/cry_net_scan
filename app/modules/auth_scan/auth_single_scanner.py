import logging
from typing import List

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.auth_scan.auth_parser import parse_auth
from tools.auth.multiple_hosts_scanner import scan_multiple_hosts


async def _run_single_auth_scan(
    host: Host,
    scanner_name: ScannerName,
) -> None:
    """
    Executes a single asynchronous unauthorized access scan against a specified host.
    """
    logger = logging.getLogger(__name__)

    target_ip: str = host.ip_address
    ports: str = ",".join(str(port_.port) for port_ in host.ports)

    results: List = scan_multiple_hosts(
        ip_list=[target_ip],
        ports=ports,
    )

    try:
        if results:
            await parse_auth(
                result=results,
                host=host,
                scanner_name=scanner_name,
            )

    except Exception as e:
        logger.error(
            f"An unexpected error occurred during {scanner_name} for {target_ip}: {e}"
        )

    return None
