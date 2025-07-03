import ipaddress
import logging
from typing import Dict

from app.models.host_config import Host
from app.models.target_type_config import TargetType
from app.utils.args_parser.host_source_appender import add_host_and_source_target


async def parse_ip_cidr(
    target: str,
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
            await add_host_and_source_target(
                unique_hosts_by_ip=unique_hosts_by_ip,
                ip=ip_str,
                original_target_value=target,
                original_target_type=TargetType.ip_cidr,
            )
            logger.debug(f"Added host from CIDR '{target}': {ip_str}")
            ips_in_cidr_count += 1

        logger.info(f"Processed CIDR '{target}', added {ips_in_cidr_count} IPs.")

    except ValueError as e:
        logger.error(f"Failed to parse CIDR '{target}': {e}. Skipping.")
