from typing import List

from app.models.application_config import Application
from app.models.host_config import Host
from app.modules.afrog.afrog_scanner import afrog_scan
from app.modules.auth_scan.auth_scanner import auth_scan
from app.modules.nuclei.nuclei_scanner import nuclei_scan
from app.modules.smb_enumerator.smb_enumeration_scanner import smb_enumeration_scan
from app.modules.webanalyze.webanalyze_scanner import webanalyze_scan


async def execute_scanners(
    live_hosts: List[Host],
    live_applications: List[Application],
    disable_nuclei: bool,
    disable_afrog: bool,
) -> None:
    """TOOLS RUNNER"""

    # Detect technologies
    await webanalyze_scan(
        hosts=live_hosts,
        applications=live_applications,
    )

    # Manages unauthorized access scans.
    await auth_scan(
        hosts=live_hosts,
    )

    # Scans SMB, RPC, NetBIOS, users.
    await smb_enumeration_scan(
        hosts=live_hosts,
    )

    # Executes a vulnerability scan on the provided list of hosts with ports.
    if not disable_nuclei:
        await nuclei_scan(
            hosts=live_hosts,
        )

    # Executes a vulnerability scan on the provided list of hosts.
    if not disable_afrog:
        await afrog_scan(
            hosts=live_hosts,
            applications=live_applications,
        )

    return None
