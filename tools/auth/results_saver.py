import csv
import json
import logging
from typing import List

from tools.auth.finding_config import Finding


def save_results(findings, filename=None, format_type="csv") -> None:
    """Save findings to file or just print it."""
    if not findings:
        logging.info("No findings to save.")
        return

    if format_type.lower() == "csv":
        fieldnames: List[str] = list(Finding.model_fields.keys())

        if filename:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for finding in findings:
                    writer.writerow(finding.model_dump())  # Use model_dump() for CSV
            logging.info(f"Findings successfully saved to {filename} in CSV format.")

        else:
            logging.info("CSV output not written to file. Printing dict representations:")
            for finding in findings:
                print(finding.model_dump())

    elif format_type.lower() == "json":
        # Convert a list of Pydantic models to a list of dictionaries
        findings_dicts = [finding.model_dump() for finding in findings]

        if filename:
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(findings, jsonfile, indent=2, default=str)
            logging.info(f"Findings successfully saved to {filename} in JSON format.")

        print(json.dumps(findings_dicts, indent=2))
