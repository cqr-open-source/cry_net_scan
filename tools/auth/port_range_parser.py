from typing import List


def parse_port_range(port_range) -> List:
    """Parse port range string into a list of ports."""
    ports = []
    for part in port_range.split(","):
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))
