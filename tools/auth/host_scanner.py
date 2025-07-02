import logging
from typing import List

from tools.auth.banner_grabber import grab_banner
from tools.auth.constants import FINDINGS
from tools.auth.finding_config import Finding
from tools.auth.port_checker import check_port
from tools.auth.service_identificator import identify_service_by_banner
from tools.auth.service_validator import validate_service


def scan_host(ip, ports, services_filter=None, timeout=2, grab_banners=True):
    """Scan a single host focusing on unauthorized access."""
    findings: List[Finding | None] = []

    logging.info(f"Scanning {ip} for unauthorized access ({len(ports)} ports)...")

    for port in ports:
        if check_port(ip, port, timeout):
            logging.debug(f"Open port found: {ip}:{port}")

            # Grab banner for service identification
            banner = grab_banner(ip, port, timeout) if grab_banners else ""

            # Try to identify service from banner first
            identified_service = identify_service_by_banner(banner, port)

            # Check against known vulnerable services
            services_to_check = []

            if identified_service and identified_service in FINDINGS:
                services_to_check.append(identified_service)

            # Also check services that commonly run on this port
            for name, details in FINDINGS.items():
                if services_filter and name not in services_filter:
                    continue
                if port == details["port"] and name not in services_to_check:
                    services_to_check.append(name)

            # Validate each potential service
            for service_name in services_to_check:
                if validate_service(ip, port, service_name, timeout):
                    details = FINDINGS[service_name]

                    finding = Finding(
                        host=ip,
                        name=details["name"],
                        service=service_name,
                        port=port,
                        severity=details["severity"],
                        description=details["description"],
                        remediation=details["remediation"],
                        cve=details["cve"],
                        banner=banner[:300] if banner else "",
                        detection_method=f"Banner: {identified_service}" if identified_service == service_name else "Port + Validation",
                    )

                    findings.append(finding)
                    logging.warning(f"UNAUTHORIZED ACCESS: {service_name} on {ip}:{port}")
                    break

    return findings
