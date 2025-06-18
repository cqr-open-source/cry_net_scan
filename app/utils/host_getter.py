import logging

from app.models.host_config import Host


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
            start_index = data.index("//")
            data = data[start_index if start_index != -1 else 0 :]

            if data in host.target:
                return host

    logger.warning(f"Host with data '{data}' not found in the provided hosts list.")
    return None
