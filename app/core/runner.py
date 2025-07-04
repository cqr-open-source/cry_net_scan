import asyncio
import logging
from typing import List, Optional

import app.utils.paths_getter as paths_getter
from app.core.data_saver import save_data
from app.core.file_remover import delete_temp_files
from app.core.scanners_runner import execute_scanners
from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scan_config import ScanConfig
from app.modules.ai.ai_interaction import interact_with_ai
from app.modules.rustscan.rustscan_scanner import rustscan_scan
from app.utils.chmod_adder import make_executable
from app.utils.target_parser import parse_targets


def get_live_hosts_only(
    targets: List[Host] | List[Application],
) -> List[Host] | List[Application]:
    return [host for host in targets if host.is_alive]


async def run_tool(scan_config: ScanConfig) -> None:
    logger = logging.getLogger(__name__)

    ### Get parsed, validated hosts ###
    all_hosts: List[Host]
    all_applications: List[Application]
    all_hosts, all_applications = await parse_targets(raw_targets=scan_config.target)
    if not all_hosts:
        logger.info("There are no VALID targets.")
        return None

    ### Get tools paths per system ###
    paths_getter.get_paths(system_name=scan_config.system_name)
    # Make these tools paths executable
    tasks = [
        make_executable(str(tool_path), scan_config.system_name)
        for tool_path in paths_getter.TOOLS_PATHS.values()
    ]
    await asyncio.gather(*tasks)

    ### Execute basic scan ###
    # Identify live hosts, open ports, and associated services.
    await rustscan_scan(
        all_hosts=all_hosts,
    )

    ### Gather only live hosts and live applications ###
    live_hosts: List[Host] = get_live_hosts_only(targets=all_hosts)
    live_applications: List[Application] = get_live_hosts_only(targets=all_applications)

    if not live_hosts:
        logger.info("There are no alive targets.")
        return None

    ### Run scanners ###
    await execute_scanners(
        live_hosts=live_hosts,
        live_applications=live_applications,
        disable_afrog=scan_config.disable_afrog,
        disable_nuclei=scan_config.disable_nuclei,
    )

    ### AI part ###
    ai_api_key: Optional[str] = scan_config.ai_api_key

    if ai_api_key:
        await interact_with_ai(
            ai_api_key=scan_config.ai_api_key,
            live_hosts=live_hosts,
            # ai_model=
        )

    ### Save the results to the specified format and location ###
    await save_data(
        all_hosts=all_hosts,
        report_format=scan_config.report_format,
        report_base_dir=scan_config.report_base_dir,
        report_file=scan_config.report_file,
        report_zip=scan_config.report_zip,
    )

    ### Delete temp files ###
    await delete_temp_files()

    return None
