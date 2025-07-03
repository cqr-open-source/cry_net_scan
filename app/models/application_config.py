from typing import List

from pydantic import BaseModel, Field

from app.models.target_type_config import TargetType
from app.models.technology_config import Technology
from app.models.vulnerability_config import Vulnerability


class Application(BaseModel):
    """
    Represents a web application or service, identified by a URL or domain.
    This model will aggregate web-specific information and vulnerabilities.
    """

    target: str = Field(
        ..., description="The canonical URL or domain of the application."
    )

    # TargetType.domain, TargetType.url.
    target_type: TargetType = Field(..., description="Type of the original target.")

    resolved_ips: List[str] = Field(
        default_factory=list,
        description="List of IP addresses resolved for this application's domain/URL.",
    )

    is_alive: bool = Field(
        default=False, description="True if the application/service was reachable."
    )

    # --- Technologies (from Wappalyzer) ---
    technologies: List[Technology] = Field(
        default_factory=list, description="List of identified web technologies."
    )

    # --- Vulnerabilities (from Afrog, Nuclei HTTP templates etc.) ---
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="List of application-level vulnerabilities."
    )
