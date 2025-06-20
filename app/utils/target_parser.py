import logging
from typing import List, Dict, Tuple

from app.models.application_config import Application
from app.models.host_config import Host
from app.utils.args_parser.ip_cidr_parser import parse_ip_cidr
from app.utils.args_parser.ip_range_parser import parse_ip_range
from app.utils.args_parser.ip_single_parser import parse_single_ip
from app.utils.args_parser.url_domain_parser import parse_url_domain


async def parse_targets(raw_targets: List[str]) -> Tuple[List[Host], List[Application]]:
    """
    Parses a list of raw target strings into Host and Application objects.
    Supports single IPs, CIDR ranges, IP ranges, and domain names/URLs.
    """
    logger = logging.getLogger(__name__)

    # Use dictionaries to ensure uniqueness by IP address for Hosts
    # and by canonical URL for Applications.
    unique_hosts_by_ip: Dict[str, Host] = {}
    unique_applications_by_url: Dict[str, Application] = {}

    logger.info(f"Targets to validate: {len(raw_targets)}")

    for target in raw_targets:
        target = target.strip()
        logger.debug(f"Processing target: {target}")

        # Check in specific order: IP Range, CIDR, URL/Domain, then Single IP as fallback
        if "-" in target and not target.startswith("http"):
            await parse_ip_range(target=target, unique_hosts_by_ip=unique_hosts_by_ip)

        elif "/" in target and "//" not in target:
            await parse_ip_cidr(target=target, unique_hosts_by_ip=unique_hosts_by_ip)

        elif " " not in target and (
            "." in target
            or target.startswith("http://")
            or target.startswith("https://")
        ):
            await parse_url_domain(
                target=target,
                unique_hosts_by_ip=unique_hosts_by_ip,
                unique_applications_by_url=unique_applications_by_url,
            )
        else:
            # If none of the above, try to parse as a single IP
            await parse_single_ip(target=target, unique_hosts_by_ip=unique_hosts_by_ip)

    logger.info(f"Total unique hosts processed: {len(unique_hosts_by_ip)}")
    logger.info(
        f"Total unique applications processed: {len(unique_applications_by_url)}"
    )

    return list(unique_hosts_by_ip.values()), list(unique_applications_by_url.values())
