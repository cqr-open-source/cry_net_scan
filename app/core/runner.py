import logging
from typing import List

from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.nuclei.nuclei_scanner import nuclei_scan
from app.modules.rustscan.rustscan_scanner import rustscan_scan
from app.utils.target_parser import parse_targets


def get_live_hosts_only(all_hosts: set[Host]) -> List[Host]:
    return [host for host in all_hosts if host.is_alive]


async def run_tool(scan_config: ScanConfig) -> set[Host]:
    logger = logging.getLogger(__name__)

    all_hosts: set[Host] = await parse_targets(raw_targets=scan_config.target)
    if not all_hosts:
        logger.info("There are no VALID targets.")
        return all_hosts

    await rustscan_scan(all_hosts=all_hosts)

    live_hosts: List[Host] = get_live_hosts_only(all_hosts=all_hosts)

    if not live_hosts:
        logger.info("There are no alive targets.")
        return all_hosts

    if not scan_config.disable_nuclei:
        await nuclei_scan(hosts=live_hosts)

    # for host in live_hosts:
    #     await rustscan_scan(host=host)

    # TODO: continue...
    return all_hosts
