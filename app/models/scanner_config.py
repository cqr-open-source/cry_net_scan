from enum import Enum


class ScannerName(str, Enum):
    RUSTSCAN = "RustScan"
    WEBANALYZE = "Webanalyze"

    AFROG = "Afrog"
    NUCLEI = "Nuclei"

    SMB_ENUMERATION = "SMB Enumeration"
    # NULLINUX = "NullLinux"
