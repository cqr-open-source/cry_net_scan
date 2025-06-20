import ipaddress
import logging
from typing import Dict

from app.models.host_config import Host
from app.models.target_type_config import TargetType


async def parse_single_ip(
    target: str,
    unique_hosts_by_ip: Dict[str, Host],
) -> None:
    logger = logging.getLogger(__name__)

    try:
        ip = ipaddress.ip_address(target)
        ip_str = str(ip)

        if ip_str not in unique_hosts_by_ip:
            unique_hosts_by_ip[ip_str] = Host(
                target=target,
                target_type=TargetType.ip.value,
                ip_address=ip_str,
            )
            logger.info(f"Added host for single IP '{target}': {ip_str}")
        else:
            logger.debug(f"Skipping duplicate single IP '{target}': {ip_str}")

    except ValueError as e:
        logger.error(f"Failed to parse IP '{target}': {e}. Skipping.")
