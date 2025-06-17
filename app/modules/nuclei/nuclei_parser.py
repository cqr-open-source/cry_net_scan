import json
import logging
from typing import Optional

from app.models.host_config import Host
from app.models.port_config import PortInfo
from app.models.vulnerability_config import VulnerabilityInfo
from app.utils.host_by_ip_getter import get_host_by_ip


async def parse_nuclei(nuclei_result: str, hosts: list[Host]) -> None:
    """
    Parses a multiline string of Nuclei JSONL outputs (nuclei_result) and adds the discovered
    vulnerabilities to the appropriate Host and PortInfo objects within the
    provided 'hosts' list. This function modifies the 'hosts' list in-place.
    """
    logger = logging.getLogger(__name__)

    processed_nuclei_result = nuclei_result.strip()

    # Split the string by the unique JSON object
    raw_json_objects = processed_nuclei_result.split("}\n{")

    parsed_objects = []
    if not raw_json_objects:
        return None

    # Reconstruct each JSON object
    for i, part in enumerate(raw_json_objects):
        if i == 0:
            # First part should already start with '{'
            full_json_str = part
        elif i == len(raw_json_objects) - 1:
            # Last part should already end with '}'
            full_json_str = "{" + part
        else:
            # Middle parts need both '{' and '}'
            full_json_str = "{" + part + "}"

        try:
            parsed_objects.append(json.loads(full_json_str))
        except json.JSONDecodeError as e:
            logger.warning(
                f"Error decoding JSON segment: {e}\nSegment: {full_json_str.strip()}"
            )
            continue

    for nuclei_result_item in parsed_objects:
        nuclei_ip_address = nuclei_result_item.get("ip")

        if not nuclei_ip_address:
            logger.warning(
                f"Skipping Nuclei result due to missing IP address: {nuclei_result_item.get('template-id')}"
            )
            continue

        # Iterate directly over the provided hosts list to find the matching host
        found_host: Optional[Host] = await get_host_by_ip(
            hosts=hosts, ip=nuclei_ip_address
        )

        if not found_host:
            logger.warning(
                f"Host with IP {nuclei_ip_address} found in Nuclei output but not in the provided hosts list. Skipping vulnerability for this host."
            )
            continue

        port = None
        try:
            if "port" in nuclei_result_item and nuclei_result_item["port"]:
                port = int(nuclei_result_item["port"])
            elif (
                ":" in nuclei_result_item.get("host", "")
                and nuclei_result_item.get("type") == "http"
            ):
                parts = nuclei_result_item["host"].split(":")
                if len(parts) > 1 and parts[-1].isdigit():
                    port = int(parts[-1])
        except ValueError:
            logger.warning(
                f"No valid port found for template {nuclei_result_item.get('template-id')} on {nuclei_ip_address}. Skipping vulnerability as it cannot be assigned to a specific port."
            )
            continue

        found_port_info: Optional[PortInfo] = None
        for p_info in found_host.ports:
            if p_info.port == port:
                found_port_info = p_info
                break

        if not found_port_info:
            continue

        try:
            classification_data = nuclei_result_item["info"].get("classification")
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
                template_id=nuclei_result_item["template-id"],
                template_url=nuclei_result_item.get("template-url"),
                name=nuclei_result_item["info"]["name"],
                description=nuclei_result_item["info"].get("description"),
                reference=nuclei_result_item["info"].get("reference"),
                severity=nuclei_result_item["info"]["severity"],
                cve=cve,
                cwe=cwe,
                remediation=nuclei_result_item["info"].get("remediation"),
                type=nuclei_result_item["type"],
                extracted_results=nuclei_result_item.get("extracted-results"),
                request=nuclei_result_item.get("request"),
                response=nuclei_result_item.get("response"),
                curl_command=nuclei_result_item.get("curl-command"),
            )
            found_port_info.vulnerabilities.append(vulnerability)
        except Exception as e:
            logger.error(
                f"Error creating VulnerabilityInfo for {nuclei_result_item.get('template-id')} on IP {nuclei_ip_address}: {e}"
            )
            logger.error(
                f"Problematic data: {json.dumps(nuclei_result_item, indent=2)}"
            )
            continue
    return None
