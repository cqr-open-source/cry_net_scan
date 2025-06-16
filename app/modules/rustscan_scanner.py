import asyncio
import logging
import re
from typing import List, Dict

from app.core.paths import TOOLS_LINUX_RUSTSCAN_PATH
from app.models.host_config import Host
from app.models.port_config import PortInfo


async def rustscan_scan(
    ips: List[str],
) -> List[Host]:
    """Performs network scanning using RustScan and Nmap to identify live hosts, open ports, and associated services.

    This function executes RustScan with Nmap integration to scan a list of IP addresses, parsing the output to determine
    host availability, open TCP ports, and services running on those ports."""
    logger = logging.getLogger(__name__)

    hosts_map: Dict[str, Host] = {}

    command = [
        str(TOOLS_LINUX_RUSTSCAN_PATH),
        "-a",
        ",".join(ips),
        "--no-banner",
        "--ulimit",
        "10000",
        "--",
        "-sV",
        "-sC",
        "-oG",
        "-",
    ]
    logger.info(f"Running RUSTSCAN command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, stderr_bytes = await process.communicate()

        stdout = stdout_bytes.decode("utf-8").strip()
        stderr = stderr_bytes.decode("utf-8").strip()

        if stderr:
            logger.warning(f"RUSTSCAN stderr: {stderr}")

        # Regex patterns
        open_port_regex = re.compile(r"Open (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)")
        nmap_host_regex = re.compile(
            r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \([^\)]*\)\s+Status: Up"
        )
        nmap_ports_regex = re.compile(
            r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \([^\)]*\)\s+Ports: (.*)"
        )
        port_detail_regex = re.compile(r"(\d+)/open/tcp//([^/]*)/?/?([^/]*)/?(.*)")

        for line in stdout.split("\n"):
            line = line.strip()
            logger.debug(f"Processing line: {line}")

            # Parse RustScan open ports
            if match := open_port_regex.match(line):
                ip, port = match.groups()
                port_num = int(port)
                logger.debug(f"Found open port: {ip}:{port_num}")

                if ip not in hosts_map:
                    hosts_map[ip] = Host(ip_address=ip, is_alive=True)

                if not any(p.port == port_num for p in hosts_map[ip].ports):
                    hosts_map[ip].ports.append(PortInfo(port=port_num))

            # Parse Nmap host status
            elif match := nmap_host_regex.match(line):
                ip = match.group(1)
                logger.debug(f"Found up host: {ip}")
                if ip not in hosts_map:
                    hosts_map[ip] = Host(ip_address=ip, is_alive=True)
                else:
                    hosts_map[ip].is_alive = True

            # Parse Nmap detailed port info
            elif match := nmap_ports_regex.match(line):
                ip, ports_section = match.groups()
                logger.debug(f"Nmap ports line matched: IP={ip}, Ports={ports_section}")

                if ip not in hosts_map:
                    hosts_map[ip] = Host(ip_address=ip, is_alive=True)

                for port_str in ports_section.split(","):
                    port_str = port_str.strip()
                    if port_match := port_detail_regex.match(port_str):
                        port_num = int(port_match.group(1))
                        service = port_match.group(2) or ""
                        version = port_match.group(3) or ""
                        logger.debug(
                            f"Found port detail: {port_num}/{service}/{version}"
                        )

                        existing_port = next(
                            (p for p in hosts_map[ip].ports if p.port == port_num), None
                        )
                        if existing_port:
                            existing_port.service = service
                            existing_port.version = version
                        else:
                            hosts_map[ip].ports.append(
                                PortInfo(
                                    port=port_num,
                                    service=service,
                                    version=version,
                                )
                            )

    except Exception as e:
        logger.error(f"Error running RUSTSCAN or parsing output: {e}", exc_info=True)

    return list(hosts_map.values())
