import ftplib
import logging
import socket

import pymongo
import redis
import requests
import telnetlib
from pymemcache.client import base as memcache_client

from tools.auth.constants import WEB_PATHS
from tools.auth.port_checker import check_port


def validate_service(ip, port, service, timeout=2):
    """Enhanced service validation with specific checks for unauthorized access."""
    try:
        # Database validations
        if service == "Elasticsearch":
            r = requests.get(f"http://{ip}:{port}", timeout=timeout)
            if r.status_code == 200 and ('cluster_name' in r.text or 'elasticsearch' in r.text.lower()):
                # Check if authentication is required
                try:
                    search_r = requests.get(f"http://{ip}:{port}/_search", timeout=timeout)
                    return search_r.status_code == 200  # No auth_scan required
                except requests.exceptions.RequestException:
                    return True  # Assume open if _search fails but initial connection works (e.g. security enabled but no data)

        elif service == "MongoDB":
            try:
                client = pymongo.MongoClient(ip, port, serverSelectionTimeoutMS=timeout * 1000)
                client.server_info()  # This will fail if auth_scan is required
                return True
            except pymongo.errors.OperationFailure:
                return False  # Auth required
            except Exception:
                return False

        elif service == "Redis":
            try:
                r = redis.Redis(host=ip, port=port, socket_timeout=timeout)
                return r.ping()  # Will work if no auth_scan required
            except redis.exceptions.ResponseError:
                return False  # Auth required
            except Exception:
                return False

        elif service == "Memcached":
            try:
                client = memcache_client.Client((ip, port), connect_timeout=timeout)
                client.get("test")  # Will work if no auth_scan
                return True
            except Exception:
                return False

        elif service == "CouchDB":
            r = requests.get(f"http://{ip}:{port}/_all_dbs", timeout=timeout)
            return r.status_code == 200  # Should require auth_scan

        elif service == "InfluxDB":
            r = requests.get(f"http://{ip}:{port}/query?q=SHOW DATABASES", timeout=timeout)
            return r.status_code == 200

        elif service == "Cassandra":
            # Try connecting without auth_scan
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                sock.close()
                return True
            except socket.error:
                return False

        # Web application validations
        elif service in WEB_PATHS:
            for path in WEB_PATHS[service]:
                try:
                    protocol = "https" if port in [443, 8443] else "http"
                    r = requests.get(f"{protocol}://{ip}:{port}{path}", timeout=timeout, verify=False,
                                     allow_redirects=False)

                    # Check for successful access without auth_scan
                    if r.status_code in [200, 301, 302]:
                        # Additional checks for specific services
                        if service == "Jenkins" and "jenkins" in r.text.lower():
                            return "login" not in r.text.lower()  # No login required
                        elif service == "Grafana" and r.status_code == 200 and path == "/":
                            return "login" not in r.text.lower()
                        elif service == "RabbitMQ" and path == "/api/overview":
                            return r.status_code == 200  # Should require auth_scan
                        elif service == "Git Repository" and path == "/.git/config":
                            return "[core]" in r.text or "repositoryformatversion" in r.text
                        elif service == "Directory Listing" and "Index of" in r.text:
                            return True
                        elif service == "phpinfo()" and "PHP Version" in r.text:
                            return True
                        elif service == "Server Status" and "Server Status" in r.text:
                            return True
                        else:
                            return True
                except requests.exceptions.RequestException:
                    continue
            return False

        # Infrastructure service validations
        elif service == "Docker API":
            r = requests.get(f"http://{ip}:{port}/containers/json", timeout=timeout)
            return r.status_code == 200

        elif service == "Kubernetes API":
            r = requests.get(f"http://{ip}:{port}/api", timeout=timeout, verify=False)
            return r.status_code == 200

        elif service == "Consul":
            r = requests.get(f"http://{ip}:{port}/v1/catalog/nodes", timeout=timeout)
            return r.status_code == 200

        elif service == "Etcd":
            r = requests.get(f"http://{ip}:{port}/v2/keys", timeout=timeout)
            return r.status_code == 200

        elif service == "Zookeeper":
            sock = socket.create_connection((ip, port), timeout=timeout)
            sock.sendall(b'stat\n')
            response = sock.recv(1024)
            sock.close()
            return b'Mode' in response or b'Zookeeper' in response

        # Network service validations
        elif service == "FTP Anonymous":
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=timeout)
                ftp.login()  # Anonymous login
                ftp.quit()
                return True
            except ftplib.all_errors:
                return False

        elif service == "Telnet":
            try:
                tn = telnetlib.Telnet(ip, port, timeout=timeout)
                tn.close()
                return True
            except ConnectionRefusedError:
                return False

        elif service == "SNMP":
            # Check for default community strings
            return check_port(ip, 161, timeout)

        elif service == "VNC No Auth":
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                data = sock.recv(12)  # RFB version
                sock.close()
                return b'RFB' in data
            except socket.error:
                return False

        else:
            return check_port(ip, port, timeout)

    except Exception as e:
        logging.debug(f"Service validation failed for {service} on {ip}:{port} - {e}")
        return False
