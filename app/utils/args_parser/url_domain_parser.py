import asyncio
import ipaddress
import logging
import socket
from typing import List, Dict
from urllib.parse import urlparse

from app.models.application_config import Application
from app.models.host_config import Host
from app.models.target_type_config import TargetType
from app.utils.args_parser.ip_single_parser import parse_single_ip


async def get_all_ips(domain: str) -> List[str]:
    """
    Gets all unique IP addresses for a given domain,
    executing the blocking operation in a separate thread.
    """
    ips = set()
    try:
        results = await asyncio.to_thread(socket.getaddrinfo, domain, None)
        for res in results:
            # res[4] - is the address info tuple, res[4][0] - is the IP address itself
            ips.add(res[4][0])
    except socket.gaierror as e:
        logging.warning(f"Could not resolve domain '{domain}': {e}")
    except Exception as e:
        logging.error(f"Error getting IPs for domain '{domain}': {e}")
    return list(ips)


async def parse_url_domain(
    target: str,
    unique_hosts_by_ip: Dict[str, Host],
    unique_applications_by_url: Dict[str, Application],
) -> None:
    logger = logging.getLogger(__name__)

    try:
        # Pre-pend 'http://' if no scheme is present to ensure urlparse correctly identifies the hostname.
        # Store the original string to check for scheme later for target_type.
        original_target = target
        if "://" not in target:
            target = f"http://{target}"

        parsed = urlparse(target)
        hostname = parsed.hostname
        scheme = parsed.scheme  # noqa: F841

        # Determine if the extracted hostname is an IP address
        is_ip_in_hostname = False
        try:
            ipaddress.ip_address(hostname)
            is_ip_in_hostname = True
        except ValueError:
            pass  # It's a domain name, not an IP

        #    We only make sure a Host object exists for this IP.
        if is_ip_in_hostname:
            logger.debug(
                f"Skipping Application creation for IP-based URL: '{original_target}'"
            )
            # Ensure Host object is created for this IP.
            # This covers cases like http://192.168.1.1 or https://[::1]/
            await parse_single_ip(
                target=hostname, unique_hosts_by_ip=unique_hosts_by_ip
            )
            return

        # If hostname is still None after pre-pending, or if it's an empty string, skip.
        if not hostname:
            logger.warning(
                f"Could not extract a valid hostname from '{original_target}'. Skipping."
            )
            return

        # Resolve IPs for the valid hostname
        resolved_ips_for_domain = await get_all_ips(hostname)

        # Determine target type for the Application based on the ORIGINAL target
        app_target_type: TargetType
        if "://" in original_target:  # Check original string for scheme
            app_target_type = TargetType.url
        else:
            app_target_type = TargetType.domain

        # Normalize URL/domain for the unique key in unique_applications_by_url
        # If original_target had a scheme, use its canonical form (rstrip('/')).
        # Otherwise, use just the hostname (which is the domain itself).
        canonical_url = (
            original_target.rstrip("/") if "://" in original_target else hostname
        )

        if canonical_url not in unique_applications_by_url:
            app_obj = Application(
                target=canonical_url,
                target_type=app_target_type.value,
                resolved_ips=list(set(resolved_ips_for_domain)),
            )
            unique_applications_by_url[canonical_url] = app_obj
            logger.info(
                f"Added application '{canonical_url}' (type: {app_target_type.value}) "
                f"with resolved IP(s): {', '.join(resolved_ips_for_domain) if resolved_ips_for_domain else 'None'}"
            )
        else:
            app_obj = unique_applications_by_url[canonical_url]
            existing_ips_set = set(app_obj.resolved_ips)
            new_ips = [
                ip for ip in resolved_ips_for_domain if ip not in existing_ips_set
            ]
            if new_ips:
                app_obj.resolved_ips.extend(new_ips)
                logger.debug(
                    f"Updated application '{canonical_url}' with new IP(s): {', '.join(new_ips)}"
                )

        # For each resolved IP, create or update a Host object
        if resolved_ips_for_domain:
            for ip_addr in resolved_ips_for_domain:
                if ip_addr not in unique_hosts_by_ip:
                    # Host target_type reflects the original input type
                    host_original_target_type = (
                        TargetType.url.value
                        if "://" in original_target
                        else TargetType.domain.value
                    )

                    unique_hosts_by_ip[ip_addr] = Host(
                        target=original_target,  # Store the original input string
                        target_type=host_original_target_type,
                        ip_address=ip_addr,
                    )
                    logger.debug(
                        f"Added host for original target '{original_target}' "
                        f"with resolved IP: {ip_addr}"
                    )

    except socket.gaierror as e:
        logger.warning(f"Could not resolve domain/URL '{original_target}': {e}")
    except Exception as e:
        logger.error(f"Error processing URL/domain '{original_target}': {e}. Skipping.")
