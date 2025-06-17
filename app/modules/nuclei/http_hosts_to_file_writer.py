import pathlib
from typing import List

from app.models.host_config import Host


async def write_http_hosts_to_file(
    hosts: List[Host],
    file: pathlib.Path,
) -> None:
    urls = []

    for host in hosts:
        for port in host.ports:
            service = port.service.lower()
            if service in ("http", "https"):
                url = f"{service}://{host.ip_address}:{port.port}"
                urls.append(url)

    file.write_text("\n".join(urls), encoding="utf-8")

    return None
