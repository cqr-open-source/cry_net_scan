import ipaddress
import logging
from typing import Dict

from app.models.host_config import Host
from app.models.target_type_config import TargetType


async def parse_ip_cidr(
    target: str,
    # ips: Set,
    # hosts: List[Host],
    unique_hosts_by_ip: Dict[str, Host],
) -> None:
    logger = logging.getLogger(__name__)

    try:
        network = ipaddress.ip_network(target, strict=False)
        logger.debug(f"Parsing CIDR: {target}")

        ips_in_cidr_count = 0  # To track individual IPs added from this CIDR
        for ip in network:
            if ips_in_cidr_count >= 1000:  # Limit for CIDR-generated IPs
                logger.warning(
                    f"Too many IPs generated for CIDR '{target}'. Limiting to {ips_in_cidr_count} IPs."
                )
                break

            ip_str = str(ip)
            if ip_str not in unique_hosts_by_ip:
                unique_hosts_by_ip[ip_str] = Host(
                    target=target,
                    target_type=TargetType.ip_cidr.value,
                    ip_address=ip_str,
                )
                logger.debug(f"Added host from CIDR '{target}': {ip_str}")
            ips_in_cidr_count += 1
        logger.info(f"Processed CIDR '{target}', added {ips_in_cidr_count} IPs.")

    except ValueError as e:
        logger.error(f"Failed to parse CIDR '{target}': {e}. Skipping.")
