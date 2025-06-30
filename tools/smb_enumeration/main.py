import sys

from tools.smb_enumeration.run_smb_enumeration import run_smb_enumeration


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python3 smb_enum_module.py <target_IP_address>\n")
        sys.stderr.write("Example: python3 smb_enum_module.py 8.8.8.8\n")
        sys.exit(1)

    for target_ip in sys.argv[1:]:
        json_output = run_smb_enumeration(target_ip)
        print(json_output)


if __name__ == "__main__":
    main()
