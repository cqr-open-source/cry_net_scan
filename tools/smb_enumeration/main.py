import pathlib
import sys

ROOT_PATH = pathlib.Path(__file__).parents[2].absolute()
sys.path.append(str(ROOT_PATH))

from tools.smb_enumeration.run_smb_enumeration import run_smb_enumeration  # noqa: E402


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
