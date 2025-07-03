import logging
from typing import Optional, List


from app.models.application_config import Application
from app.models.host_config import Host
from app.utils.parsing_utils import is_substring


async def get_application(
    hosts: List[Host],
    data: str,  # The URL or domain string to search for
) -> Optional[Application]:
    """
    Retrieves an Application object by matching its target URL/domain.
    """
    logger = logging.getLogger(__name__)

    for host in hosts:
        for app in host.associated_applications:

            if await is_substring(data, app.target):
                logger.debug(f"Found application for '{data}': {app.target}")
                return app

    logger.warning(
        f"Application with target '{data}' not found in the provided host's associated applications."
    )
    return None
