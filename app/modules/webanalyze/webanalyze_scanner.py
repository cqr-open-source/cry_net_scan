import pathlib
from typing import List

import app.utils.paths_getter as paths_getter
from app.core.paths import WEBANALYZE_PATH
from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.webanalyze.webanalyze_parser import parse_webanalyze
from app.utils.hosts_to_file import write_hosts_to_file
from app.utils.subprocess_runner import subprocess_run


async def webanalyze_scan(
    hosts: List[Host],
    applications: List[Application],
) -> None:
    """
    Executes a technology detection scan on the provided list of hosts using Webanalyze.

    Target: only url/urls. Can be http://<ip>.
    """
    await write_hosts_to_file(
        hosts=hosts,
        file=WEBANALYZE_PATH,
        applications=applications,
    )

    webanalyze_path: pathlib.Path = paths_getter.TOOLS_PATHS[
        ScannerName.WEBANALYZE.value.lower()
    ]

    command = [
        str(webanalyze_path),
        "-hosts",
        str(WEBANALYZE_PATH),
        "-output",
        "json",
    ]

    result: str = await subprocess_run(
        command=command,
        module_name=ScannerName.WEBANALYZE.value,
    )

    if result:
        await parse_webanalyze(
            result=result,
            hosts=hosts,
        )

    return None
