import ipaddress
import logging
from typing import Dict

from app.models.host_config import Host
from app.models.target_type_config import TargetType


async def parse_ip_range(
    target: str,
    # ips: Set,
    # hosts: List[Host],
    unique_hosts_by_ip: Dict[str, Host],
) -> None:
    logger = logging.getLogger(__name__)

    try:
        start_ip_str, end_ip_str = [ip.strip() for ip in target.split("-")]
        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)

        if start_ip.version != end_ip.version:
            logger.warning(f"Skipping invalid range (mismatched IP versions): {target}")
            return

        logger.debug(f"Parsing IP range: {target}")
        current_ip = start_ip
        while current_ip <= end_ip:
            ip_str = str(current_ip)
            if ip_str not in unique_hosts_by_ip:
                unique_hosts_by_ip[ip_str] = Host(
                    target=target,
                    target_type=TargetType.ip_range.value,
                    ip_address=ip_str,
                )
                logger.debug(f"Added host from range '{target}': {ip_str}")

            current_ip = ipaddress.ip_address(int(current_ip) + 1)
        logger.info(f"Processed IP range '{target}'.")

    except ValueError as e:
        logger.error(f"Failed to parse range '{target}': {e}. Skipping.")
