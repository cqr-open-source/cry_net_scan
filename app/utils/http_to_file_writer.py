import pathlib
from typing import List
from urllib.parse import urlparse

from app.models.host_config import Host


async def write_hosts_to_file(
    hosts: List[Host],
    file: pathlib.Path,
    need_ports: bool = False,
) -> None:
    urls = []

    for host in hosts:
        for port in host.ports:
            service = port.service.lower()
            if service in ("http", "https"):
                if (
                    host.target != host.ip_address
                    and host.ip_address not in host.target
                ):
                    if host.target.startswith("http"):
                        # Url
                        medium_part = urlparse(host.target).hostname

                    else:
                        # Domain
                        medium_part = host.target
                else:
                    medium_part = host.ip_address

                url = (
                    f"{service}://{medium_part}:{port.port}"
                    if need_ports
                    else f"{service}://{medium_part}"
                )

                urls.append(url)

    file.write_text("\n".join(urls), encoding="utf-8")

    return None
