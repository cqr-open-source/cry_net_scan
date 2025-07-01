import argparse
import ipaddress
from typing import List


def parse_ip_range(ip_range) -> List:
    """Parse IP range into a list of IPs."""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
    except ValueError:
        try:
            ipaddress.ip_address(ip_range)
            return [ip_range]
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid IP or IP range: {ip_range}")
