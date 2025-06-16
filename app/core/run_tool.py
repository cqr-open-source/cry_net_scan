import logging
from typing import List

from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.rustscan_scanner import rustscan_scan
from app.utils.target_parser import parse_targets


def get_live_hosts_only(all_hosts: List[Host]) -> List[Host]:
    return [host for host in all_hosts if host.is_alive]


async def run_tool(scan_config: ScanConfig):
    logger = logging.getLogger(__name__)

    parsed_targets: List[str] = await parse_targets(raw_targets=scan_config.target)
    if not parsed_targets:
        logger.info("There are no VALID targets.")
        return

    all_hosts: List[Host] = await rustscan_scan(ips=parsed_targets)

    live_hosts: List[Host] = get_live_hosts_only(all_hosts=all_hosts)

    if not live_hosts:
        logger.info("There are no alive targets.")
        return

    # for host in live_hosts:
    #     await rustscan_scan(host=host)

    # TODO: continue...
