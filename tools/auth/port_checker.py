import socket


def check_port(ip, port, timeout=2) -> bool:
    """Check if a port is open on the given IP."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return False
