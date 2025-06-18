import json
import logging
from typing import Optional, List

from app.models.host_config import Host
from app.models.port_config import Port
from app.models.vulnerability_config import VulnerabilityInfo
from app.utils.host_getter import get_host
from app.utils.jsonl_parser import parse_jsonl


async def parse_nuclei(nuclei_result: str, hosts: list[Host]) -> None:
    """
    Parses a multiline string of Nuclei JSONL outputs (nuclei_result) and adds the discovered
    vulnerabilities to the appropriate Host and Port objects within the
    provided 'hosts' list. This function modifies the 'hosts' list in-place.
    """
    logger = logging.getLogger(__name__)

    # Parse the JSONL content into a list of dictionaries
    parsed_objects: List[dict] | List[None] = await parse_jsonl(
        jsonl_content=nuclei_result
    )

    for result_item in parsed_objects:
        nuclei_ip_address = result_item.get("ip")

        if nuclei_ip_address:
            # Iterate directly over the provided hosts list to find the matching host
            found_host: Optional[Host] = await get_host(
                hosts=hosts,
                data=nuclei_ip_address,
                ip_required=True,
            )
        else:
            host = result_item.get("host")
            found_host: Optional[Host] = await get_host(
                hosts=hosts,
                data=host,
            )
            if not found_host:
                logger.warning(
                    f"Skipping Nuclei result due to missing IP address: {result_item.get('template-id')}"
                )
                continue

        if not found_host:
            logger.warning(
                f"Host with IP {nuclei_ip_address} found in Nuclei output but not in the provided hosts list. Skipping vulnerability for this host."
            )
            continue

        port = None
        try:
            if "port" in result_item and result_item["port"]:
                port = int(result_item["port"])
            elif (
                ":" in result_item.get("host", "") and result_item.get("type") == "http"
            ):
                parts = result_item["host"].split(":")
                if len(parts) > 1 and parts[-1].isdigit():
                    port = int(parts[-1])
        except ValueError:
            logger.warning(
                f"No valid port found for template {result_item.get('template-id')} on {nuclei_ip_address}. Skipping vulnerability as it cannot be assigned to a specific port."
            )
            continue

        found_port_info: Optional[Port] = None
        for p_info in found_host.ports:
            if p_info.port == port:
                found_port_info = p_info
                break

        if not found_port_info:
            continue

        try:
            classification_data = result_item["info"].get("classification")
            # Initialize cve_ids and cwe_ids as empty lists
            cve, cwe = None, None

            if classification_data:
                if (
                    "cve-id" in classification_data
                    and classification_data["cve-id"] is not None
                ):
                    cve = (
                        classification_data["cve-id"]
                        if isinstance(classification_data["cve-id"], list)
                        else [classification_data["cve-id"]]
                    )

                if (
                    "cwe-id" in classification_data
                    and classification_data["cwe-id"] is not None
                ):
                    cwe = (
                        classification_data["cwe-id"]
                        if isinstance(classification_data["cwe-id"], list)
                        else [classification_data["cwe-id"]]
                    )

            vulnerability = VulnerabilityInfo(
                template_id=result_item["template-id"],
                template_url=result_item.get("template-url"),
                name=result_item["info"]["name"],
                description=result_item["info"].get("description"),
                reference=result_item["info"].get("reference"),
                severity=result_item["info"]["severity"],
                cve=cve,
                cwe=cwe,
                remediation=result_item["info"].get("remediation"),
                type=result_item["type"],
                extracted_results=result_item.get("extracted-results"),
                request=result_item.get("request"),
                response=result_item.get("response"),
                curl_command=result_item.get("curl-command"),
            )
            found_port_info.vulnerabilities.append(vulnerability)

            logger.debug(
                f"Found {vulnerability} for {nuclei_ip_address} on port {port}"
            )

        except Exception as e:
            logger.error(
                f"Error creating VulnerabilityInfo for {result_item.get('template-id')} on IP {nuclei_ip_address}: {e}"
            )
            logger.error(f"Problematic data: {json.dumps(result_item, indent=2)}")
            continue
    return None
