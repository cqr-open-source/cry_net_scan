import logging

from tools.auth.constants import FINDINGS


def list_services():
    """List all services that commonly have unauthorized access."""
    logging.info("Services commonly found with UNAUTHORIZED ACCESS:")
    logging.info("=" * 60)

    categories = {
        "Databases": ["Elasticsearch", "MongoDB", "Redis", "Memcached", "CouchDB", "Cassandra", "RethinkDB",
                      "InfluxDB"],
        "Web Applications": ["Jenkins", "SonarQube", "Kibana", "Grafana", "GitLab", "PhpMyAdmin", "Jupyter Notebook",
                             "Apache Tomcat Manager", "WebLogic Console", "Sonatype Nexus", "Rundeck", "Portainer",
                             "cAdvisor"],
        "Infrastructure": ["Docker API", "Docker Registry", "Kubernetes API", "Kubernetes Dashboard", "Consul", "Etcd",
                           "Zookeeper"],
        "Message Queues": ["RabbitMQ", "Apache Kafka", "Apache ActiveMQ"],
        "Monitoring": ["Prometheus", "Node Exporter", "Alertmanager", "Splunk"],
        "Network Services": ["FTP Anonymous", "Telnet", "TFTP", "SNMP", "LDAP Anonymous", "SMB Guest", "NFS Open",
                             "Rsync", "VNC No Auth"],
        "Web Exposures": ["Directory Listing", "Git Repository", "SVN Repository", "Swagger UI", "phpinfo()",
                          "Server Status", "Backup Files", "Config Files"]
    }

    for category, services in categories.items():
        logging.info(f"\n## {category}:")
        for service in services:
            details = FINDINGS.get(service, {})
            port_info = f" (Port: {details.get('port', 'N/A')})"
            severity_info = f" (Severity: {details.get('severity', 'N/A')})"
            logging.info(f"- {service}{port_info}{severity_info}")
