import pathlib
from datetime import datetime

from app.core.constants import APP_NAME_SNAKE_CASE

# Home directory. Like ~/
# In home directory, we'll have permission to create files.
HOME_PATH = pathlib.Path.home()

ROOT_PATH = pathlib.Path(__file__).parent.parent.parent.absolute()
APP_PATH = ROOT_PATH.joinpath("app")
CORE_PATH = APP_PATH.joinpath("core")

TESTS_PATH = ROOT_PATH.joinpath("tests")

TOOLS_PATH = ROOT_PATH.joinpath("tools")

TOOLS_LINUX_PATH = TOOLS_PATH.joinpath("linux")
TOOLS_WINDOWS_PATH = TOOLS_PATH.joinpath("windows")
TOOLS_MACOS_PATH = TOOLS_PATH.joinpath("macos")

TOOLS_SMB_PATH = TOOLS_PATH.joinpath("smb_enumeration", "main.py")

# TOOLS_RUSTSCAN_PATH = TOOLS_LINUX_PATH.joinpath("rustscan", "rustscan")
# TOOLS_NMAP_PATH = TOOLS_LINUX_PATH.joinpath("nmap", "nmap")
# TOOLS_WEBANALYZE_PATH = TOOLS_LINUX_PATH.joinpath("webanalyze", "webanalyze")
# TOOLS_NUCLEI_PATH = TOOLS_LINUX_PATH.joinpath("nuclei", "nuclei")
# TOOLS_AFROG_PATH = TOOLS_LINUX_PATH.joinpath("afrog", "afrog")

WEBANALYZE_PATH = HOME_PATH.joinpath("webanalyze.txt")
HOSTS_PATH = HOME_PATH.joinpath("hosts.txt")
NUCLEI_PATH = HOME_PATH.joinpath("nuclei.txt")  # full host
# AFROG_TEMP_PATH = ROOT_PATH.joinpath("afrog.json")
AFROG_TEMP_PATH = HOME_PATH.joinpath("afrog.json")

LOG_PATH = ROOT_PATH.joinpath("logs")
LOG_FILE_PATH = LOG_PATH.joinpath(
    f"{APP_NAME_SNAKE_CASE}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

REPORT_PATH = ROOT_PATH.joinpath("reports")
