import sys

from app.models.system_config import SystemName


async def get_system_name() -> SystemName:
    """Detect current system and return matching SystemName enum value."""
    platform_name = sys.platform
    if platform_name.startswith("linux"):
        return SystemName.LINUX
    elif platform_name == "darwin":
        return SystemName.MACOS
    elif platform_name in ("win32", "cygwin"):
        return SystemName.WINDOWS
    else:
        raise ValueError(f"Unsupported platform: {platform_name}")