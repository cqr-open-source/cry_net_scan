from typing import List

from app.core.paths import NUCLEI_PATH
from app.core.paths import TOOLS_LINUX_NUCLEI_PATH
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.nuclei.nuclei_parser import parse_nuclei
from app.utils.http_to_file_writer import write_hosts_to_file
from app.utils.subprocess_runner import subprocess_run


async def nuclei_scan(
    hosts: List[Host],
) -> None:
    """Executes a vulnerability scan on the provided list of hosts using the Nuclei scanner.
    Target: list of IPs with HTTP ports."""

    # Get IPS with HTTP/HTTPS ports
    required_hosts: List[Host] = []
    for host in hosts:
        for port in host.ports:
            if port.service in ("http", "https"):
                required_hosts.append(host)
            break

    await write_hosts_to_file(
        hosts=required_hosts,
        file=NUCLEI_PATH,
        need_ports=True,
        need_ips=True,
    )

    # [START] If we need to fast check!
    # from app.core.paths import ROOT_PATH
    #
    # with open(ROOT_PATH.joinpath("nuclei.json"), "r") as f:
    #     stdout = f.read()
    # await parse_nuclei(nuclei_result=stdout, hosts=hosts)
    # return None
    # [END] If we need to fast check!

    command = [
        str(TOOLS_LINUX_NUCLEI_PATH),
        "-l",
        str(NUCLEI_PATH),
        "-jsonl",
    ]

    result: str = await subprocess_run(
        command=command,
        module_name=ScannerName.NUCLEI.value,
    )

    if result:
        await parse_nuclei(nuclei_result=result, hosts=hosts)

    return None
