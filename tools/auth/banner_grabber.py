import socket

import requests


def grab_banner(ip, port, timeout=2):
    """Enhanced banner grabbing with multiple techniques."""
    banners = []

    # HTTP banner grabbing
    if port in [80, 443, 8080, 8443, 3000, 5601, 8000, 8081, 8888, 9000, 9090]:
        try:
            protocol = "https" if port in [443, 8443] else "http"
            r = requests.get(f"{protocol}://{ip}:{port}", timeout=timeout, verify=False)
            banners.append(f"HTTP: {r.text[:500]}")
            if "Server" in r.headers:
                banners.append(f"Server: {r.headers['Server']}")
        except requests.exceptions.RequestException:
            pass

    # Raw socket banner
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Try different protocols
            if port == 21:  # FTP
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                banners.append(f"FTP: {banner}")
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                banners.append(f"SSH: {banner}")
            elif port == 23:  # Telnet
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                banners.append(f"Telnet: {banner}")
            elif port in [25, 110, 143]:  # Mail
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                banners.append(f"Mail: {banner}")
            else:  # Generic HTTP request
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                banners.append(f"Raw: {banner}")
    except (socket.timeout, socket.error):
        pass

    return " | ".join(banners)
