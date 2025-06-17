import ipaddress
import logging
import socket
from typing import List

from app.models.host_config import Host


async def parse_targets(raw_targets: List[str]) -> set[Host]:
    # List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Parses a list of raw target strings into ipaddress objects,
    or resolves domain names/URLs to IP addresses.
    Supports single IPs, CIDR ranges, IP ranges (e.g., 192.168.1.1-192.168.1.10),
    and domain names/URLs.
    """
    logger = logging.getLogger(__name__)

    hosts = set()

    for target in raw_targets:
        target = target.strip()
        logger.info(f"Processing target: {target}")

        # Try to parse as IP range (e.g., "192.168.1.1 - 192.168.1.255")
        if "-" in target and not target.startswith("http"):
            try:
                start_ip, end_ip = [ip.strip() for ip in target.split("-")]
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)

                # Ensure both IPs are of the same version
                if start.version != end.version:
                    logger.warning(
                        f"Skipping invalid range (mismatched IP versions): {target}"
                    )
                    continue

                logger.info(f"Parsing range: {start_ip} - {end_ip}")
                current = start
                while current <= end:
                    hosts.add(Host(target=target, ip_address=str(current)))
                    current = int(current) + 1
                    current = ipaddress.ip_address(current)

                continue
            except ValueError as e:
                logger.error(f"Failed to parse range {target}: {e}")
                raise e

        # Try to parse as CIDR (e.g., "192.168.1.0/24" or "2001:db8::/64")
        if "/" in target and "//" not in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                logger.info(f"Parsing CIDR: {target}")
                for ip in network:
                    # Added limit for CIDR.
                    # TODO: find better decision
                    if len(hosts) > 9:
                        logger.warning(f"Too many IPs! Finishing adding it on IP: {ip}")
                        break
                    hosts.add(Host(target=target, ip_address=str(ip)))
                continue

            except ValueError as e:
                logger.error(f"Failed to parse CIDR {target}: {e}")
                continue

        # Try to resolve as a domain or URL
        # Simple check for potential domain/URL (lacks space, has a dot, or starts with http/https)
        if " " not in target and (
            "." in target
            or target.startswith("http://")
            or target.startswith("https://")
        ):
            try:
                # Extract hostname if it's a URL
                hostname = target
                if target.startswith("http://"):
                    hostname = target[len("http://") :]
                elif target.startswith("https://"):
                    hostname = target[len("https://") :]

                # Remove path and query parameters if present
                if "/" in hostname:
                    hostname = hostname.split("/")[0]
                if "?" in hostname:
                    hostname = hostname.split("?")[0]

                ip_address = socket.gethostbyname(hostname)
                logger.info(f"Resolved {hostname} to IP: {ip_address}")
                hosts.add(Host(target=target, ip_address=ip_address))
                continue
            except socket.gaierror as e:
                logger.warning(f"Could not resolve domain/URL {target}: {e}")
            except ValueError as e:
                logger.error(f"Error processing URL/domain {target}: {e}")

        # Try to parse as single IP (e.g., "192.168.1.1" or "2001:db8::1")
        try:
            ip = ipaddress.ip_address(target)
            logger.info(f"Parsed single IP: {target}")
            hosts.add(Host(target=target, ip_address=str(ip)))
            continue
        except ValueError as e:
            logger.error(f"Failed to parse IP {target}: {e}. Skipping.")
            continue

    logger.info(f"Total IPs added: {len(hosts)}")
    return hosts
