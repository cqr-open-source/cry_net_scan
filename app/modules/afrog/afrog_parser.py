import logging
from typing import List, Optional, Union

from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.models.vulnerability_config import Vulnerability
from app.modules.afrog.duplicate_finder import search_duplicate_vulnerabilities
from app.utils.target_getter.target_getter import get_target


async def parse_afrog(
    json_result: List,
    hosts: List[Host],
) -> None:
    logger = logging.getLogger(__name__)

    for vulnerability_info in json_result:
        target = vulnerability_info.get("target")
        received_target: Optional[Union[Application, Host]] = await get_target(
            hosts=hosts,
            data=target,
            scanner_name=ScannerName.AFROG.value,
        )
        if not received_target:
            logger.warning(f"Host {target} not found in the provided hosts list.")
            continue

        vulnerability: Vulnerability = Vulnerability(
            template_id=vulnerability_info["pocinfo"]["id"],
            name=vulnerability_info["pocinfo"]["infoname"],
            severity=vulnerability_info["pocinfo"]["infoseg"],
            finding_url=vulnerability_info["fulltarget"],
            scanner_name=ScannerName.AFROG.value,
        )

        if await search_duplicate_vulnerabilities(
            host=received_target,
            vulnerability=vulnerability,
        ):
            continue

        received_target.vulnerabilities.append(vulnerability)

        logger.info(
            f"{target}: vulnerability '{vulnerability.name}' "
            f"with severity '{vulnerability.severity}' on the target '{vulnerability.finding_url}'"
        )

    return None
