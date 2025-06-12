import ipaddress
import logging
from typing import List


async def parse_targets(raw_targets: List[str]) -> List[str]:
    # List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Parses a list of raw target strings into ipaddress objects.
    Supports single IPs, CIDR ranges, and IP ranges (e.g., 192.168.1.1-192.168.1.10).
    """
    logger = logging.getLogger(__name__)

    result = []

    for target in raw_targets:
        target = target.strip()
        logger.info(f"Processing target: {target}")

        # Try to parse as IP range (e.g., "192.168.1.1 - 192.168.1.255")
        if "-" in target:
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
                    result.append(str(current))
                    current = int(current) + 1
                    current = ipaddress.ip_address(current)
                logger.info(f"Added {len(result)} IPs from range {target}")
                continue
            except ValueError as e:
                logger.error(f"Failed to parse range {target}: {e}")
                raise e

        # Try to parse as CIDR (e.g., "192.168.1.0/24" or "2001:db8::/64")
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                logger.info(f"Parsing CIDR: {target}")
                for ip in network:
                    # Added limit for CIDR.
                    # TODO: find better decision
                    if len(result) > 9:
                        logger.warning(
                            f"Too many IPs! Finishing appending it on IP: {ip}"
                        )
                        break
                    result.append(str(ip))
                continue

            except ValueError as e:
                logger.error(f"Failed to parse CIDR {target}: {e}")
                raise e

        # Try to parse as single IP (e.g., "192.168.1.1" or "2001:db8::1")
        try:
            ip = ipaddress.ip_address(target)
            logger.info(f"Parsed single IP: {target}")
            result.append(str(ip))
            continue
        except ValueError as e:
            logger.error(f"Failed to parse IP {target}: {e}")
            raise e

    logger.info(f"Total IPs parsed: {len(result)}")
    return result
