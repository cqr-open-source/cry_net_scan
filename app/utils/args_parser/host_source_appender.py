from typing import Dict

from app.models.host_config import Host
from app.models.source_target_config import SourceTarget
from app.models.target_type_config import TargetType


async def add_host_and_source_target(
    unique_hosts_by_ip: Dict[str, Host],
    ip: str,
    original_target_value: str,
    original_target_type: TargetType,
):
    host = unique_hosts_by_ip.get(ip)
    if host is None:
        host = Host(ip_address=ip)
        unique_hosts_by_ip[ip] = host

    new_source = SourceTarget(value=original_target_value, type=original_target_type)
    if new_source not in host.source_targets:
        host.source_targets.append(new_source)
