import logging
import re

from app.models.host_config import Host
from app.models.port_config import PortInfo


async def parse_rustscan(stdout: str, all_hosts: set[Host]) -> None:
    logger = logging.getLogger(__name__)

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

            for host in all_hosts:
                if host.ip_address == ip:
                    host.is_alive = True
                    if not any(p.port == port_num for p in host.ports):
                        host.ports.append(PortInfo(port=port_num))
                    break
            else:
                logger.warning(
                    f"IP {ip} found in RustScan output but not in initial hosts set."
                )

        # Parse Nmap host status
        elif match := nmap_host_regex.match(line):
            ip = match.group(1)
            logger.debug(f"Found up host: {ip}")
            for host in all_hosts:
                if host.ip_address == ip:
                    host.is_alive = True
                    break
            else:
                logger.warning(
                    f"IP {ip} found in Nmap host status but not in initial hosts set."
                )

        # Parse Nmap detailed port info
        elif match := nmap_ports_regex.match(line):
            ip, ports_section = match.groups()
            logger.debug(f"Nmap ports line matched: IP={ip}, Ports={ports_section}")

            for host in all_hosts:
                if host.ip_address == ip:
                    host.is_alive = True
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
                                (p for p in host.ports if p.port == port_num), None
                            )
                            if existing_port:
                                existing_port.service = service
                                existing_port.version = version
                            else:
                                host.ports.append(
                                    PortInfo(
                                        port=port_num,
                                        service=service,
                                        version=version,
                                    )
                                )
                    break
            else:
                logger.warning(
                    f"IP {ip} found in Nmap port details but not in initial hosts set."
                )
