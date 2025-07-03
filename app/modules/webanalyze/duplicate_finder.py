import logging
from typing import List, Optional

from app.models.application_config import Application
from app.models.host_config import Host
from app.utils.parsing_utils import is_substring
from app.utils.target_getter.host_getter import get_host


async def search_duplicate_technologies(
    host: Host | Application,
    technology_name: str,
    hosts: List[Host],
) -> bool:
    """
    Search for duplicate technologies within a Host object, including its ports and associated applications.
    Returns True if a duplicate is found, otherwise False.
    """
    logger = logging.getLogger(__name__)

    # Check host-level technologies
    for tech in host.technologies:
        if await is_substring(tech.name, technology_name):
            logger.debug(
                f"Duplicate technology '{technology_name}' found at host level for {host.ip_address}. Skipping."
            )
            return True

    # Check technologies on ports
    if isinstance(host, Host):
        for port_info in host.ports:
            # Check the 'technology' string field directly on the port
            if await is_substring(port_info.technology, technology_name):
                logger.debug(
                    f"Duplicate technology '{technology_name}' found on port {port_info.port} "
                    f"for host {host.ip_address}. Skipping."
                )
                return True

        # Check technologies within associated applications
        for app in host.associated_applications:
            for tech in app.technologies:
                if await is_substring(tech.name, technology_name):
                    logger.debug(
                        f"Duplicate technology '{technology_name}' found in application '{app.target}' "
                        f"associated with host {host.ip_address}. Skipping."
                    )
                    return True
    elif isinstance(host, Application):
        # For an Application, iterate through its resolved IPs
        # and try to find the corresponding Host objects.
        for ip_address in host.resolved_ips:
            host_for_ip: Optional[Host] = await get_host(
                data=ip_address,
                hosts=hosts,
            )
            if host_for_ip:
                # Check technologies on ports of the found Host
                for port_info in host_for_ip.ports:
                    if await is_substring(port_info.technology, technology_name):
                        logger.debug(
                            f"Duplicate technology '{technology_name}' found on port {port_info.port} "
                            f"for host {ip_address} (resolved from application '{host.target}'). Skipping."
                        )
                        return True
            else:
                logger.warning(
                    f"Could not find Host for IP '{ip_address}' resolved from application '{host.target}'."
                )

    return False
