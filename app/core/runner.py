import asyncio
import logging
from typing import List, Tuple

import app.utils.paths_getter as paths_getter
from app.core.data_saver import save_data
from app.core.file_remover import delete_temp_files
from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.afrog.afrog_scanner import afrog_scan
from app.modules.auth_scan.auth_scanner import auth_scan
from app.modules.nuclei.nuclei_scanner import nuclei_scan
from app.modules.rustscan.rustscan_scanner import rustscan_scan
from app.modules.smb_enumerator.smb_enumeration_scanner import smb_enumeration_scan
from app.modules.webanalyze.webanalyze_scanner import webanalyze_scan
from app.utils.chmod_adder import make_executable
from app.utils.target_parser import parse_targets


def get_live_hosts_only(
    targets: List[Host] | List[Application],
) -> List[Host] | List[Application]:
    return [host for host in targets if host.is_alive]


async def run_tool(scan_config: ScanConfig) -> None:
    logger = logging.getLogger(__name__)

    # Get parsed hosts
    result: Tuple[List[Host], List[Application]] = await parse_targets(
        raw_targets=scan_config.target
    )
    all_hosts: List[Host] = result[0]
    all_applications: List[Application] = result[1]  # noqa: F841

    if not all_hosts:
        logger.info("There are no VALID targets.")
        return None

    # Get tools paths per system
    paths_getter.get_paths(system_name=scan_config.system_name)
    # Make these tools paths executable
    tasks = [
        make_executable(str(tool_path), scan_config.system_name)
        for tool_path in paths_getter.TOOLS_PATHS.values()
    ]

    await asyncio.gather(*tasks)

    # --- [START] TOOLS RUNNER [START] ---
    # Identify live hosts, open ports, and associated services.
    await rustscan_scan(
        all_hosts=all_hosts,
    )

    # Gather only live hosts and live applications
    live_hosts: List[Host] = get_live_hosts_only(targets=all_hosts)
    live_applications: List[Application] = get_live_hosts_only(targets=all_applications)

    if not live_hosts:
        logger.info("There are no alive targets.")
        return None

    # Detect technologies
    await webanalyze_scan(
        hosts=live_hosts,
        applications=live_applications,
    )

    # Manages unauthorized access scans.
    await auth_scan(
        hosts=live_hosts,
    )

    # Scans SMB, RPC, NetBIOS, users.
    await smb_enumeration_scan(
        hosts=live_hosts,
    )

    # Executes a vulnerability scan on the provided list of hosts with ports.
    if not scan_config.disable_nuclei:
        await nuclei_scan(
            hosts=live_hosts,
        )

    # Executes a vulnerability scan on the provided list of hosts.
    if not scan_config.disable_afrog:
        await afrog_scan(
            hosts=live_hosts,
            applications=live_applications,
        )

    # # for host in live_hosts:
    # #     await rustscan_scan(host=host)
    #
    # # TODO: continue...
    # # --- [END] TOOLS RUNNER [END] ---

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
