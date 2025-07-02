import logging
import sys

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.auth_scan.auth_parser import parse_auth
from app.utils.subprocess_runner import subprocess_run


async def _run_single_auth_scan(
    host: Host,
    script_path: str,
    scanner_name: ScannerName,
) -> None:
    """
    Executes a single asynchronous unauthorized access scan against a specified host.
    """
    logger = logging.getLogger(__name__)

    target_ip: str = host.ip_address
    ports: str = ",".join(str(port_.port) for port_ in host.ports)

    try:
        # Call the generic subprocess_run utility
        stdout_decoded = await subprocess_run(
            command=[
                sys.executable,
                script_path,
                "-t",
                target_ip,
                "--format",
                "json",
                "-T",
                "10",
                "--ports",
                ports,
            ],
            module_name=scanner_name,
        )

        if stdout_decoded:
            await parse_auth(
                result=stdout_decoded,
                host=host,
                scanner_name=scanner_name,
            )

    except Exception as e:
        logger.error(
            f"An unexpected error occurred during {scanner_name} for {target_ip}: {e}"
        )

    return None
