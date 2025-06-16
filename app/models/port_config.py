from typing import Optional

from pydantic import BaseModel, Field


class PortInfo(BaseModel):
    """
    Represents detailed information about a single discovered port.
    """

    port: int = Field(..., description="The port number.")

    service: Optional[str] = Field(
        default_factory=str,
        description="The name of the service running on the port (e.g., 'http', 'ssh').",
    )

    version: Optional[str] = Field(
        default_factory=str, description="Version of the service if detected by Nmap."
    )
