import argparse


def parse_args() -> argparse.Namespace:
    """Main function to parse arguments and run the scan."""
    parser = argparse.ArgumentParser(description="Unauthorized Access Vulnerability Scanner")

    parser.add_argument("-t", "--target", help="Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)")

    parser.add_argument("-p", "--ports", default="1-65535",
                        help="Ports to scan (e.g., 80,443,8080 or 1-1024)")

    parser.add_argument("-T", "--threads", type=int, default=10,

                        help="Number of concurrent threads for scanning (default: 10)")

    parser.add_argument("-o", "--output", help="Output filename for results (CSV or JSON format)")

    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv",

                        help="Output format (csv or json, default: csv)")

    parser.add_argument("-s", "--services", help="Comma-separated list of services to scan (e.g., MongoDB,Redis). "
                                                  "Use --list-services to see available services.")

    parser.add_argument("-nb", "--no-banner-grab", action="store_true",
                        help="Disable banner grabbing for faster scans.")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (debug level).")

    parser.add_argument("--list-services", action="store_true", help="List all available services for scanning.")

    return parser.parse_args()
