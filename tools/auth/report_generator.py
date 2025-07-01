import logging
from datetime import datetime


def generate_report(findings, show_details=True) -> None:
    """Generate a detailed unauthorized access report."""
    if not findings:
        logging.info("No unauthorized access vulnerabilities found!")
        return

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    unique_hosts = set()

    for finding in findings:
        severity_counts[finding["Severity"]] += 1
        unique_hosts.add(finding["Host"])

    logging.info("UNAUTHORIZED ACCESS VULNERABILITY REPORT")
    logging.info(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info(f"Total hosts scanned: {len(unique_hosts)}")
    logging.info(f"Total unauthorized access issues found: {len(findings)}")
    logging.info("Severity breakdown:")
    for severity, count in severity_counts.items():
        if count > 0:
            logging.info(f"  {severity}: {count}")

    if show_details:
        logging.info("Detailed findings by host:")
        host_findings = {}
        for finding in findings:
            host = finding["Host"]
            if host not in host_findings:
                host_findings[host] = []
            host_findings[host].append(finding)

        for host, host_vulns in host_findings.items():
            logging.info(f"Host: {host}")
            for vuln in host_vulns:
                cve_info = f"({vuln['CVE']})" if vuln['CVE'] else ""
                logging.info(f"{vuln['Service']} (Port {vuln['Port']}) - {vuln['Severity']}{cve_info}")
                logging.info(f"Description: {vuln['Description']}")
                logging.info(f"Remediation: {vuln['Remediation']}")
                logging.info(f"Detection: {vuln['Detection_Method']}")
