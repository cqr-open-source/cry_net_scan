import logging
import pathlib
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse

from app.models.application_config import Application
from app.models.host_config import Host
from app.models.target_type_config import TargetType


async def write_hosts_to_file(
    applications: Optional[List[Application]],
    hosts: List[Host],
    file: pathlib.Path,
    need_http: bool = True,
    need_ports: bool = False,  # If a specific webanalyze variant needs explicit ports
    need_ips: bool = False,
) -> None:
    logger = logging.getLogger(__name__)

    unique_targets_for_file: Set[str] = set()

    # Create a quick lookup for hosts by IP for efficient access when processing applications
    hosts_by_ip: Dict[str, Host] = {host.ip_address: host for host in hosts}

    # --- Phase 1: Process Application objects (URLs/Domains) ---
    # This phase runs ONLY if 'need_ips' is False, as it's primarily for web-focused tools
    # that prefer domain/URL inputs.
    if not need_ips:
        for app in applications:
            target_str = app.target
            parsed_url = urlparse(target_str)

            # Determine the base hostname/IP for URL construction.
            # Use 'netloc' (e.g., "example.com:8080") or the original string for plain domains/IPs.
            hostname_or_ip = parsed_url.netloc or target_str

            if not hostname_or_ip:
                logger.warning(
                    f"Could not extract valid host from application target: {target_str}. Skipping."
                )
                continue

            # Handle scheme based on 'need_http' parameter
            if need_http:
                # If scheme is missing or is HTTP, default to HTTPS for consistency and security
                if not parsed_url.scheme or parsed_url.scheme.lower() == "http":
                    final_target = f"http://{hostname_or_ip}"
                else:  # Already HTTPS or another supported scheme, use as is
                    final_target = target_str
            else:
                # If no HTTP scheme is needed, just use the hostname/domain part (strip any existing scheme)
                final_target = hostname_or_ip

            # Handle ports based on 'need_ports'
            if need_ports:
                # Iterate through resolved IPs for this application to find associated open ports
                for ip_addr in app.resolved_ips:
                    host = hosts_by_ip.get(ip_addr)
                    if host:
                        for (
                            port_obj
                        ) in (
                            host.ports
                        ):  # Use port_obj to avoid name conflict with 'port' field
                            # Only consider HTTP/HTTPS services or common web ports
                            if (
                                port_obj.service and port_obj.service.startswith("http")
                            ) or (
                                port_obj.port in [80, 443, 8080, 8443]
                            ):  # Common web ports

                                # Check if port is already explicitly in the URL (e.g., example.com:8080)
                                if parsed_url.port == port_obj.port:
                                    # Port is already there, use the current 'final_target'
                                    unique_targets_for_file.add(final_target)
                                elif (
                                    port_obj.port == 80
                                    and final_target.startswith("http://")
                                ) or (
                                    port_obj.port == 443
                                    and final_target.startswith("https://")
                                ):
                                    # Standard port for the current scheme, usually implied by web scanners.
                                    # Do not add explicitly unless explicitly requested by the tool.
                                    unique_targets_for_file.add(final_target)
                                else:
                                    # Non-standard port or standard port for a different scheme, add it explicitly
                                    # Reconstruct URL with the explicit port, preserving path, query, fragment
                                    scheme_to_use = (
                                        "https"
                                        if need_http
                                        else parsed_url.scheme or "http"
                                    )

                                    path = parsed_url.path
                                    query = (
                                        f"?{parsed_url.query}"
                                        if parsed_url.query
                                        else ""
                                    )
                                    fragment = (
                                        f"#{parsed_url.fragment}"
                                        if parsed_url.fragment
                                        else ""
                                    )

                                    # Construct the base part (scheme://hostname:port)
                                    base_url_part = f"{scheme_to_use}://{hostname_or_ip}:{port_obj.port}"

                                    target_with_port = (
                                        f"{base_url_part}{path}{query}{fragment}"
                                    )
                                    unique_targets_for_file.add(target_with_port)
                    else:
                        # If no host found for a resolved IP, just add the base target for the app
                        unique_targets_for_file.add(final_target)
            else:  # 'need_ports' is False, just add the scheme-adjusted target
                unique_targets_for_file.add(final_target)

    # --- Phase 2: Process Host objects (IP-based targets) ---
    # This phase always iterates through all hosts, but conditionally adds their IPs
    for host in hosts:
        # Determine if this host's IP should be included:
        # 1. If 'need_ips' is True (requesting all discovered IPs).
        # 2. OR if 'need_ips' is False, but this host originated from a direct IP input.
        #    This covers cases where a raw IP was provided by the user and needs to be included.

        include_host_ip = False
        if need_ips:
            include_host_ip = True
        else:
            # Check if any of the source targets for this host was an explicit IP
            if any(st.type == TargetType.ip for st in host.source_targets):
                include_host_ip = True

        if include_host_ip:
            base_ip_target = host.ip_address

            if need_ports:
                # Add each open port to the IP, creating targets like "192.168.1.1:22"
                for port_obj in host.ports:
                    unique_targets_for_file.add(f"{base_ip_target}:{port_obj.port}")
            else:
                # Just add the raw IP address (e.g., "192.168.1.1")
                unique_targets_for_file.add(base_ip_target)

    # --- Final checks and file writing ---
    if not unique_targets_for_file:
        logger.warning(
            "No targets generated for file. Check input parameters (applications, hosts, need_ips, need_http, need_ports)."
        )
        return None

    try:
        file.write_text("\n".join(unique_targets_for_file), encoding="utf-8")
        logger.debug(f"Targets written to file: {file.resolve()}")
    except Exception as e:
        logger.error(f"Failed to write targets to file {file}: {e}", exc_info=True)

    return None
