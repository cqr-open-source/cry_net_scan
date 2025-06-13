import logging
from typing import List

from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.hosts_discovery import discover_hosts
from app.modules.ports_discovery import search_ports
from app.utils.target_parser import parse_targets


def get_live_hosts_only(all_hosts: List[Host]) -> List[Host]:
    return [host for host in all_hosts if host.is_alive]


async def run_tool(scan_config: ScanConfig):
    logger = logging.getLogger(__name__)

    parsed_targets: List[str] = await parse_targets(raw_targets=scan_config.target)

    all_hosts: List[Host] = await discover_hosts(ips=parsed_targets)
    # TODO: scan only live hosts?

    live_hosts: List[Host] = get_live_hosts_only(all_hosts=all_hosts)

    if not live_hosts:
        logger.info("There is no alive target. Scan is finished.")
        return

    # TODO: for host in live_hosts or smth like this
    # all_hosts: List[Host] = await search_ports(all_hosts=all_hosts)
    await search_ports(live_hosts=live_hosts)
    # TODO: continue...
