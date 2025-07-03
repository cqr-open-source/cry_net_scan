import logging
from typing import Optional, List, Union

from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.utils.target_getter.app_getter import get_application
from app.utils.target_getter.host_getter import get_host


async def get_target(
    hosts: List[Host],
    data: str,
    scanner_name: ScannerName,
) -> Optional[Union[Application, Host]]:
    logger = logging.getLogger(__name__)

    target: Optional[Application] = await get_application(
        hosts=hosts,
        data=data,
    )
    if not target:
        target: Optional[Host] = await get_host(
            hosts=hosts,
            data=data,
        )

    if target:
        if isinstance(target, Application):
            logger.debug(f"{target.target}: discover {scanner_name} technologies")
        else:
            logger.debug(f"{target.ip_address}: discover {scanner_name} technologies")

    return target
