import json

from tools.smb_enumeration.enum4_class import Enum4LinuxNGScanner


def run_smb_enumeration(target_ip):
    """
    Main function to run SMB enumeration and return results in JSON format.
    :param target_ip: The IP address of the target host.
    :return: A JSON string with enumeration results.
    """
    scanner = Enum4LinuxNGScanner(target_ip)
    scanner.perform_enumeration()
    return json.dumps(scanner.get_results(), indent=4, ensure_ascii=False)
