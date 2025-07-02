import logging
from typing import List

from app.models.host_config import Host
from app.models.port_config import Port
from app.models.scanner_config import ScannerName
from app.models.vulnerability_config import Vulnerability


async def parse_auth(
    result: List,
    host: Host,
    scanner_name: ScannerName,
) -> None:
    """Parse and save to host Auth Scanner results."""

    logger = logging.getLogger(__name__)

    logger.debug(f"Found {len(result)} vulnerabilities on {host.ip_address}")

    for vulnerability_object in result:
        found_port: Port | None = None
        for port_obj in host.ports:
            if port_obj.port == vulnerability_object["port"]:
                found_port = port_obj
                break

        cve = vulnerability_object["cve"]
        banner = vulnerability_object["banner"]

        found_port.vulnerabilities.append(
            Vulnerability(
                name=vulnerability_object["name"],
                severity=vulnerability_object["severity"],
                scanner_name=scanner_name,
                description=vulnerability_object["description"],
                remediation=vulnerability_object["remediation"],
                cve=cve if isinstance(cve, list) else [cve],
                extracted_results=banner if isinstance(banner, list) else [banner],
                type=vulnerability_object["service"],
            )
        )

        logger.info(f"{vulnerability_object["name"]} on {host.ip_address}")

    return None
