import logging

from app.models.host_config import Host
from app.utils.parsing_utils import is_substring


async def get_host(
    hosts: list[Host],
    data: str,
    ip_required: bool = False,
) -> Host | None:
    """Get a host by its IP address or target."""
    logger = logging.getLogger(__name__)

    for host in hosts:
        if ip_required:
            if host.ip_address == data:
                return host
        else:
            # If target is domain, but data is url, we need to extract the domain part
            start_index = data.find("//")
            data = data[start_index + 2 if start_index != -1 else 0 :]

            if host.ip_address == data:
                return host

            # TODO: Check if it is correct. Target AND IP address?
            for app in host.associated_applications:
                if await is_substring(data, app.target):
                    return host

    logger.warning(f"Host with data '{data}' not found in the provided hosts list.")
    return None
