from typing import Optional, List

from pydantic import BaseModel, Field

from app.models.smb_enumeration_config import SmbEnumeration
from app.models.vulnerability_config import Vulnerability


class Port(BaseModel):
    """
    Represents detailed information about a single discovered port.
    """

    port: int = Field(..., description="The port number.")

    service: Optional[str] = Field(
        default_factory=str,
        description="The name of the service running on the port (e.g., 'http', 'ssh').",
    )

    technology: Optional[str] = Field(
        default_factory=str,
        description="Technology of the service if detected by Nmap.",
    )

    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list,
        description="List of vulnerabilities.",
    )

    smb_enumeration_data: List[SmbEnumeration] = Field(
        default=None,
        description="Detailed SMB enumeration findings (shares, users, groups, policies, etc.).",
    )
