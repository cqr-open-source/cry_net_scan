from enum import Enum


class ScannerName(str, Enum):
    RUSTSCAN = "RustScan"
    WEBANALYZE = "Webanalyze"

    AFROG = "Afrog"
    NUCLEI = "Nuclei"
    # NULLINUX = "NullLinux"
