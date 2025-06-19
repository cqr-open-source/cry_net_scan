import logging

from app.models.host_config import Host
from app.utils.parsing_utils import is_substring


async def search_duplicate_technologies(host: Host, technology: str) -> bool:
    """
    Search for duplicate technologies on any port for a given host.
    Returns True if a duplicate is found, otherwise False.
    """
    logger = logging.getLogger(__name__)

    for port_info in host.ports:
        if await is_substring(
            str1=port_info.technology,
            str2=technology,
        ):
            logger.debug(
                f"Duplicate technology {technology} found on port {port_info.port} for host {host.ip_address}. Skipping."
            )
            return True

    return False
