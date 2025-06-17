from app.models.host_config import Host


async def get_host_by_ip(hosts: list[Host], ip: str) -> Host | None:
    for host in hosts:
        if host.ip_address == ip:
            return host
    return None
