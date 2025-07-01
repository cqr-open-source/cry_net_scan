import csv
import json
import logging


def save_results(findings, filename, format_type="csv") -> None:
    """Save findings to file."""
    if not findings:
        logging.info("No findings to save.")
        return

    if format_type.lower() == "csv":
        fieldnames = ["Host", "Service", "Port", "Severity", "Description", "Remediation", "CVE", "Banner",
                      "Detection_Method", "Timestamp"]
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                writer.writerow(finding)

    elif format_type.lower() == "json":
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(findings, jsonfile, indent=2, default=str)

        # logging.info("RESULTS START")
        # logging.info(json.dumps(findings, indent=2, default=str))
        print(json.dumps(findings, indent=2, default=str))
#         logging.info("RESULTS END")

    logging.info(f"Results saved to {filename}")
