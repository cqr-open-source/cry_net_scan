import json
import logging
from typing import List

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.models.smb_enumeration_config import SmbEnumeration, SmbContent


async def parse_smb_enumeration(
    temp_result: str,
    host: Host,
    target_ip: str,
    scanner_name: ScannerName,
) -> None:
    logger = logging.getLogger(__name__)

    try:
        smb_results = json.loads(temp_result)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON output for {target_ip}: {e}")
        logger.error(f"Raw stdout:\n{temp_result}")
        return None

    results: List[SmbEnumeration | None] = []
    for key, finding in smb_results.get("findings", {}).items():
        if finding.get("success", False):
            if key != "smb_shares_detailed":
                result = finding.get("data", {}).get("message", "")

                results.append(
                    SmbEnumeration(
                        name=key,
                        result=result,
                    )
                )

            else:

                for data in finding.get("data", {}):
                    contents: List[SmbContent | None] = []

                    name = data.get("name", "")
                    remark = data.get("remark", "")
                    permission_status = data.get("permission_status", "")

                    for content in data.get("contents", []):
                        contents.append(
                            SmbContent(
                                type=content.get("type", ""),
                                name=content.get("name", ""),
                                size=content.get("size", 0),
                            )
                        )

                    results.append(
                        SmbEnumeration(
                            name=name,
                            remark=remark,
                            permission_status=permission_status,
                            contents=contents,
                        )
                    )

    smb_port = smb_results.get("port", {})

    if smb_port is not None:
        found_port_object = None
        for p in host.ports:
            if p.port == smb_port:
                found_port_object = p
                break

        if found_port_object:
            found_port_object.smb_enumeration_data = results
            logger.info(
                f"Attached {scanner_name} data to existing Port {smb_port} for {target_ip}."
            )
        else:
            host.smb_enumeration_data = results

    logger.info(f"Successfully completed {scanner_name} for {target_ip}.")
    return None
