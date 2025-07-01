import logging
import re

from tools.auth.constants import BANNER_PATTERNS


def identify_service_by_banner(banner, port):
    """Identify service based on banner patterns."""
    if not banner:
        return None

    banner_lower = banner.lower()

    # Check against known patterns
    for service, patterns in BANNER_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, banner_lower, re.IGNORECASE):
                logging.debug(f"Service {service} identified by pattern: {pattern}")
                return service

    return None
