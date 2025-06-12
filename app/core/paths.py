import pathlib
from datetime import datetime

from app.core.constants import APP_NAME_SNAKE_CASE

ROOT_PATH = pathlib.Path(__file__).parent.parent.parent.absolute()
APP_PATH = ROOT_PATH.joinpath("app")
CORE_PATH = APP_PATH.joinpath("core")

TESTS_PATH = ROOT_PATH.joinpath("tests")

TOOLS_PATH = ROOT_PATH.joinpath("tools")
TOOLS_LINUX_PATH = TOOLS_PATH.joinpath("linux")
TOOLS_WINDOWS_PATH = TOOLS_PATH.joinpath("windows")
TOOLS_MACOS_PATH = TOOLS_PATH.joinpath("macos")

LOG_PATH = ROOT_PATH.joinpath("logs")
LOG_FILE_PATH = LOG_PATH.joinpath(
    f"{APP_NAME_SNAKE_CASE}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

REPORT_PATH = ROOT_PATH.joinpath("reports")
