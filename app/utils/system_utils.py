import sys
from typing import List


async def is_frozen() -> bool:
    """
    Checks if the application is running as a frozen (compiled) executable
    (e.g., created by PyInstaller).
    """
    return getattr(sys, "frozen", False)


async def get_raw_cli_args() -> List[str]:
    """
    Returns the raw command-line arguments, excluding the script/executable name.
    """
    return sys.argv[1:]
