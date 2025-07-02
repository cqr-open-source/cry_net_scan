import logging
import threading
from queue import Queue
from typing import List

from tools.auth.host_scanner import scan_host


def scan_multiple_hosts(
    ip_list, ports, threads=10, services_filter=None, timeout=2, grab_banners=True
) -> List:
    """Scan multiple hosts using threading."""
    all_findings = []

    def worker(q):
        while True:
            ip = q.get()
            if ip is None:
                break
            try:
                findings = scan_host(ip, ports, services_filter, timeout, grab_banners)
                all_findings.extend(findings)
            except Exception as e:
                logging.error(f"Error scanning {ip}: {e}")
            finally:
                q.task_done()

    # Create queue and add IPs
    q = Queue()
    for ip in ip_list:
        q.put(ip)

    # Start worker threads
    workers = []
    for i in range(threads):
        t = threading.Thread(target=worker, args=(q,))
        t.start()
        workers.append(t)

    # Wait for all tasks to complete
    q.join()

    # Stop worker threads
    for i in range(threads):
        q.put(None)
    for t in workers:
        t.join()

    return all_findings
