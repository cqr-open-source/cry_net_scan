import logging
from typing import Optional

from app.models.host_config import Host
from app.models.vulnerability_config import Vulnerability
from app.utils.parsing_utils import is_substring, is_similar_vuln


async def search_duplicate_vulnerabilities(
    host: Host,
    vulnerability: Vulnerability,
) -> bool:
    """
    Search for duplicate vulnerabilities on any port for a given host.
    Returns True if a duplicate is found, otherwise False.
    """
    logger = logging.getLogger(__name__)

    result: Optional[bool] = None

    for port_info in host.ports:
        for port_vulnerability in port_info.vulnerabilities:
            if vulnerability.cve and port_vulnerability.cve:
                result = True if vulnerability.cve == port_vulnerability.cve else False
            elif vulnerability.cwe and port_vulnerability.cwe:
                result = True if vulnerability.cwe == port_vulnerability.cwe else False
            elif vulnerability.finding_url and port_vulnerability.finding_url:
                result = (
                    True
                    if vulnerability.finding_url == port_vulnerability.finding_url
                    else False
                )
            else:
                if await is_substring(
                    str1=port_vulnerability.name,
                    str2=vulnerability.name,
                ):
                    result = True

                # A last chance to check similarity
                if await is_similar_vuln(
                    name_1=vulnerability.name,
                    name_2=port_vulnerability.name,
                    template_id_1=vulnerability.template_id,
                    template_id_2=port_vulnerability.template_id,
                ):
                    result = True

    if not result:
        return False

    if result:
        logger.debug(f"Duplicate vulnerability found: {vulnerability.name}")

    return result
