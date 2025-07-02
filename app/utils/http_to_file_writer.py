import logging
import pathlib
from typing import List, Set
from urllib.parse import urlparse

from app.models.host_config import Host
from app.models.target_type_config import TargetType


async def write_hosts_to_file(
    hosts: List[Host],
    file: pathlib.Path,
    need_ports: bool = False,
    need_http: bool = False,
    need_ips: bool = False,
) -> None:
    logger = logging.getLogger(__file__)

    urls: Set = set()

    for host in hosts:
        domain_part = host.ip_address

        if not need_ips:
            if host.target_type == TargetType.url:
                # If the target is a URL, we need to parse it
                domain_part = urlparse(host.target).hostname
            elif host.target_type == TargetType.domain:
                # If the target is a domain, we use the domain directly
                domain_part = host.target

        for port in host.ports:
            service = port.service.lower()
            if need_http:
                if service.startswith("http"):
                    http_part = f"{service}://"
                else:
                    http_part = "http://"
            else:
                http_part = ""

            port_part = f":{port.port}" if need_ports else ""

            url = f"{http_part}{domain_part}{port_part}"

            urls.add(url)

    file.write_text("\n".join(urls), encoding="utf-8")
    logger.debug(f"Hosts are written to the file: {file}")

    return None
