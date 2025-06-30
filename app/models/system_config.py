from enum import Enum


class SystemName(str, Enum):
    LINUX = "Linux"
    WINDOWS = "Windows"
    MACOS = "MacOS"