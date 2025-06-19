import logging
from typing import List

from app.models.host_config import Host
from app.models.raw_http_exchange_config import RawHttpExchange
from app.models.scanner_config import ScannerName
from app.models.vulnerability_config import Vulnerability
from app.modules.afrog.duplicate_finder import search_duplicate_vulnerabilities
from app.utils.host_getter import get_host


async def parse_afrog(json_result: List, hosts: List[Host]) -> None:
    logger = logging.getLogger(__name__)

    for vulnerability_info in json_result:
        target = vulnerability_info.get("target")
        host: Host = await get_host(
            hosts=hosts,
            data=target,
        )
        if not host:
            logger.warning(f"Host {target} not found in the provided hosts list.")
            continue

        raw_http_exchange: List = []

        for request_info in vulnerability_info.get("pocresult", []):
            raw_http_exchange.append(
                RawHttpExchange(
                    request=request_info["request"],
                    response=request_info["response"],
                )
            )

        vulnerability: Vulnerability = Vulnerability(
            template_id=vulnerability_info["pocinfo"]["id"],
            name=vulnerability_info["pocinfo"]["infoname"],
            severity=vulnerability_info["pocinfo"]["infoseg"],
            raw_http_exchange=raw_http_exchange,
            finding_url=vulnerability_info["fulltarget"],
            scanner_name=ScannerName.AFROG.value,
        )

        if await search_duplicate_vulnerabilities(
            host=host,
            vulnerability=vulnerability,
        ):
            logger.debug(
                f"Duplicate vulnerability {vulnerability.name} found on host {host.ip_address}. Skipping."
            )
            continue

        host.vulnerabilities.append(vulnerability)

        logger.info(
            f"{target}: vulnerability '{vulnerability.name}' "
            f"with severity '{vulnerability.severity}' on the target '{vulnerability.finding_url}'"
        )

    return None
