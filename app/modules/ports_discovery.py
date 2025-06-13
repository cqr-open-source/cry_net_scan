import asyncio
import logging
from typing import List

from app.models.host_config import Host


async def search_ports(live_hosts: List[Host]) -> None:
    logger = logging.getLogger(__name__)

    ips = [host.ip_address for host in live_hosts]

    #
    ip = ips[0]

    command = [
        "rustscan",
        # TODO: correct path
        # f"{str(TOOLS_LINUX_RUSTSCAN_PATH)}",
        "-a",
        ip,
        "--ulimit",
        "5000",
    ]
    logger.info(f"Running RUSTSCAN command: {' '.join(command)}")

    ports: List = []

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stderr:
            logger.warning(f"RUSTSCAN stderr: {stderr.decode().strip()}")

        # TODO: ports are only int? Or status - too?
        # TODO: add parsing
        for line in stdout.decode().splitlines():
            line = line.strip()
            # RustScan output line contain: "Open 80/tcp"
            if line.lower().startswith("open"):
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[1]  # e.g. "80/tcp"
                    port_str = port_proto.split("/")[0]
                    if port_str.isdigit():
                        ports.append(int(port_str))

        # live_hosts[ip].ports = ports

    except Exception as e:
        logger.error(f"Error running RUSTSCAN: {e}")
