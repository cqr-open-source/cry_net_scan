from typing import List

from app.core.paths import HOSTS_PATH, TOOLS_LINUX_WEBANALYZE_PATH
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.webanalyze.webanalyze_parser import parse_webanalyze
from app.utils.http_to_file_writer import write_hosts_to_file
from app.utils.subprocess_runner import subprocess_run


async def webanalyze_scan(
    hosts: List[Host],
) -> None:
    """Executes a technology detection scan on the provided list of hosts using Webanalyze."""

    await write_hosts_to_file(
        hosts=hosts,
        file=HOSTS_PATH,
    )

    command = [
        str(TOOLS_LINUX_WEBANALYZE_PATH),
        "-hosts",
        str(HOSTS_PATH),
        "-output",
        "json",
    ]

    result: str = await subprocess_run(
        command=command,
        module_name=ScannerName.WEBANALYZE.value,
    )

    if result:
        await parse_webanalyze(result=result, hosts=hosts)

    return None
