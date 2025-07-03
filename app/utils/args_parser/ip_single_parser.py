import ipaddress
import logging
from typing import Dict

from app.models.host_config import Host
from app.models.target_type_config import TargetType
from app.utils.args_parser.host_source_appender import add_host_and_source_target


async def parse_single_ip(
    target: str,
    unique_hosts_by_ip: Dict[str, Host],
) -> None:
    logger = logging.getLogger(__name__)

    try:
        ip = ipaddress.ip_address(target)
        ip_str = str(ip)

        await add_host_and_source_target(
            unique_hosts_by_ip=unique_hosts_by_ip,
            ip=ip_str,
            original_target_value=target,
            original_target_type=TargetType.ip,
        )

    except ValueError as e:
        logger.error(f"Failed to parse IP '{target}': {e}. Skipping.")
