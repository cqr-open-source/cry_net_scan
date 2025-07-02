#!/usr/bin/env python3
"""
Unauthorized Access Vulnerability Scanner
Focused on detecting services commonly exposed without proper authentication.
"""

import argparse
import logging
import pathlib
import sys
import time
from typing import List

import urllib3

ROOT_PATH = pathlib.Path(__file__).parents[2].absolute()
sys.path.append(str(ROOT_PATH))

from tools.auth.args_parser import parse_args  # noqa: E402
from tools.auth.ip_range_parser import parse_ip_range  # noqa: E402
from tools.auth.list_services import list_services  # noqa: E402
from tools.auth.multiple_hosts_scanner import scan_multiple_hosts  # noqa: E402
from tools.auth.port_range_parser import parse_port_range  # noqa: E402
from tools.auth.report_generator import generate_report  # noqa: E402
from tools.auth.results_saver import save_results  # noqa: E402

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def main():
    args: argparse.Namespace = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_services:
        list_services()
        sys.exit(0)

    if not args.target:
        logging.error(
            "A target IP address or CIDR range is required unless --list-services is used."
        )

    ip_list: List = parse_ip_range(args.target)
    ports_to_scan = parse_port_range(args.ports)
    services_filter = args.services.split(",") if args.services else None

    logging.info(
        f"Starting unauthorized access scan on {len(ip_list)} hosts and {len(ports_to_scan)} ports..."
    )

    start_time = time.time()
    results = scan_multiple_hosts(
        ip_list,
        ports_to_scan,
        args.threads,
        services_filter,
        grab_banners=not args.no_banner_grab,
    )
    end_time = time.time()

    logging.info(f"Scan finished in {end_time - start_time:.2f} seconds.")

    generate_report(results)

    if args.output or args.format == "json":
        save_results(results, args.output, args.format)

    sys.exit(0)


if __name__ == "__main__":
    main()
