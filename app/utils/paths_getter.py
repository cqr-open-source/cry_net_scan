from app.core.paths import TOOLS_MACOS_PATH, TOOLS_WINDOWS_PATH, TOOLS_LINUX_PATH
from app.models.scanner_config import ScannerName
from app.models.system_config import SystemName

TOOLS_PATHS = {}


def get_paths(system_name: SystemName):
    if system_name == SystemName.LINUX:
        tools_system_path = TOOLS_LINUX_PATH
    elif system_name == SystemName.WINDOWS:
        tools_system_path = TOOLS_WINDOWS_PATH
    else:
        tools_system_path = TOOLS_MACOS_PATH

    global TOOLS_PATHS
    TOOLS_PATHS = {
        "rustscan": tools_system_path.joinpath(
            ScannerName.RUSTSCAN.value.lower(), ScannerName.RUSTSCAN.value.lower()
        ),
        # "nmap": tools_system_path.joinpath(ScannerName.NMAP.value.lower(), ScannerName.NMAP.value.lower()),
        "webanalyze": tools_system_path.joinpath(
            ScannerName.WEBANALYZE.value.lower(), ScannerName.WEBANALYZE.value.lower()
        ),
        "nuclei": tools_system_path.joinpath(
            ScannerName.NUCLEI.value.lower(), ScannerName.NUCLEI.value.lower()
        ),
        "afrog": tools_system_path.joinpath(
            ScannerName.AFROG.value.lower(), ScannerName.AFROG.value.lower()
        ),
    }
