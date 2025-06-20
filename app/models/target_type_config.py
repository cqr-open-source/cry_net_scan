from enum import Enum


class TargetType(str, Enum):
    ip = "IP"
    ip_cidr = "IP_CIDR"
    ip_range = "IP_RANGE"
    domain = "DOMAIN"
    url = "URL"
    host = "HOST"
