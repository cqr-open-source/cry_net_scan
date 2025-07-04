system_message_nse = """You are a highly skilled cybersecurity expert specializing in network scanning and Nmap Scripting Engine (NSE). Your primary goal is to analyze provided scan data (in JSON format) for **a single target** and identify the **top 3 most relevant findings (vulnerabilities or technologies)** that warrant deeper analysis using Nmap NSE scripts.

For each of these top 3 findings, you must:
1. Provide its `type` (either "technology" or "vulnerability").
2. State its `name` as it appeared in the original report.
3. Recommend **specific, existing Nmap NSE script name(s)** (e.g., 'ssl-enum-ciphers', 'smb-vuln-ms17-010', 'http-headers') or relevant script categories (e.g., 'http-*', 'smb-vuln-*') that would provide further insight or confirm the finding.
4. Ensure the recommended scripts are generally safe for routine scanning (avoid 'intrusive' or 'dos' categories unless explicitly requested).

Your final output **must be a JSON list of dictionaries**, with each dictionary containing 'type', 'name', and 'nse' (a list of strings for scripts). Do not include any additional text or formatting outside this JSON array.
"""

# TODO: JSON.dumps!!!
user_message_nse = """  {
    "source_targets": [
      {
        "value": "192.0.0.0",
        "type": "IP"
      }
    ],
    "ip_address": "192.0.0.0",
    "is_alive": true,
    "associated_applications": [],
    "ports": [
      {
        "port": 22,
        "service": "ssh",
        "technology": "OpenSSH 9.9p1 Ubuntu 3ubuntu3.1 (Ubuntu Linux; protocol 2.0)",
        "vulnerabilities": [],
        "smb_enumeration_data": null
      },
      {
        "port": 139,
        "service": "netbios-ssn",
        "technology": "Samba smbd 3.X - 4.X (workgroup: WORKGROUP)",
        "vulnerabilities": [],
        "smb_enumeration_data": null
      },
      {
        "port": 445,
        "service": "netbios-ssn",
        "technology": "Samba smbd 4.21.4-Ubuntu-4.21.4+dfsg-1ubuntu3.2 (workgroup: WORKGROUP)",
        "vulnerabilities": [],
        "smb_enumeration_data": [
          {
            "name": "smb_connection",
            "result": "SMB connection established with dialect NT LM 0.12",
            "remark": null,
            "permission_status": null,
            "contents": []
          },
          {
            "name": "print$",
            "result": null,
            "remark": "Printer Drivers",
            "permission_status": "NoRead/NoWrite",
            "contents": []
          },
          {
            "name": "public",
            "result": null,
            "remark": "",
            "permission_status": "Read/NoWrite",
            "contents": [
              {
                "type": "file",
                "name": "\\\\readme.md",
                "size": 18
              },
              {
                "type": "file",
                "name": "\\\\secret_info.txt",
                "size": 20
              }
            ]
          },
          {
            "name": "IPC$",
            "result": null,
            "remark": "IPC Service (prokann-pc server (Samba, Ubuntu))",
            "permission_status": "NoRead/NoWrite",
            "contents": []
          }
        ]
      },
      {
        "port": 37522,
        "service": "",
        "technology": "",
        "vulnerabilities": [],
        "smb_enumeration_data": null
      },
      {
        "port": 38848,
        "service": "",
        "technology": "",
        "vulnerabilities": [],
        "smb_enumeration_data": null
      }
    ],
    "technologies": [],
    "vulnerabilities": [],
    "smb_enumeration_data": null
  }
"""

assistant_message_nse = """[
  {
    "type": "vulnerability",
    "name": "Public SMB Share Content",
    "nse": ["smb-enum-shares", "smb-ls"]
  },
  {
    "type": "technology",
    "name": "Samba smbd 4.21.4-Ubuntu-4.21.4+dfsg-1ubuntu3.2",
    "nse": ["smb-vuln-ms17-010", "smb-vuln-cve-2009-3103", "smb-vuln-regsvc-dos", "smb-security-mode"]
  },
  {
    "type": "technology",
    "name": "OpenSSH 9.9p1 Ubuntu 3ubuntu3.1",
    "nse": ["ssh-hostkey", "ssh-auth-methods", "ssh-brute", "ssh-enum-users"]
  }
]"""
