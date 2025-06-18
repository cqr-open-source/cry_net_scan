from typing import List

from app.core.paths import WEBANALYZE_PATH, TOOLS_LINUX_WEBANALYZE_PATH
from app.models.host_config import Host
from app.modules.webanalyze.webanalyze_parser import parse_webanalyze
from app.utils.http_to_file_writer import write_hosts_to_file
from app.utils.subprocess_runner import subprocess_run


async def webanalyze_scan(
    hosts: List[Host],
) -> None:
    """Executes a technology detection scan on the provided list of hosts using Wappalyzer."""

    await write_hosts_to_file(
        hosts=hosts,
        file=WEBANALYZE_PATH,
    )

    command = [
        str(TOOLS_LINUX_WEBANALYZE_PATH),
        "-hosts",
        str(WEBANALYZE_PATH),
        "-output",
        "json",
    ]

    result: str = await subprocess_run(
        command=command,
        module_name="WAPPALYZER",
    )

    if result:
        await parse_webanalyze(result=result, hosts=hosts)

    return None
