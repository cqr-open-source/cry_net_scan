import logging
from typing import List

from app.core.data_saver import save_data
from app.core.file_remover import delete_temp_files
from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.afrog.afrog_scanner import afrog_scan
from app.modules.nuclei.nuclei_scanner import nuclei_scan
from app.modules.rustscan.rustscan_scanner import rustscan_scan
from app.modules.webanalyze.webanalyze_scanner import webanalyze_scan
from app.utils.target_parser import parse_targets


def get_live_hosts_only(all_hosts: List[Host]) -> List[Host]:
    return [host for host in all_hosts if host.is_alive]


async def run_tool(scan_config: ScanConfig) -> None:
    logger = logging.getLogger(__name__)

    # Get parsed hosts
    all_hosts: List[Host] = await parse_targets(raw_targets=scan_config.target)
    if not all_hosts:
        logger.info("There are no VALID targets.")
        return None

    # Identify live hosts, open ports, and associated services.
    await rustscan_scan(all_hosts=all_hosts)

    # Gather only live hosts
    live_hosts: List[Host] = get_live_hosts_only(all_hosts=all_hosts)

    if not live_hosts:
        logger.info("There are no alive targets.")
        return None

    # Detect technologies
    await webanalyze_scan(hosts=live_hosts)

    # Executes a vulnerability scan on the provided list of hosts with ports.
    if not scan_config.disable_nuclei:
        await nuclei_scan(hosts=live_hosts)

    # Executes a vulnerability scan on the provided list of hosts.
    if not scan_config.disable_afrog:
        await afrog_scan(hosts=live_hosts)

    # for host in live_hosts:
    #     await rustscan_scan(host=host)

    # TODO: continue...

    # Save the results to the specified format and location
    await save_data(
        all_hosts=all_hosts,
        report_format=scan_config.report_format,
        report_base_dir=scan_config.report_base_dir,
        report_file=scan_config.report_file,
        report_zip=scan_config.report_zip,
    )

    await delete_temp_files()

    return None
