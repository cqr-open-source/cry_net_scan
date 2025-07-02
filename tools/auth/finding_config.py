from pydantic import BaseModel, Field


class Finding(BaseModel):
    host: str = Field(
        ...,
        description="The hostname or IP address of the target where the finding was identified.",
    )
    name: str = Field(..., description="Name of the vulnerability.")
    service: str = Field(
        ..., description="The database or smth associated with the finding."
    )
    port: int = Field(
        ..., description="The port number on which the vulnerable service is running."
    )
    severity: str = Field(..., description="The severity level of the finding.")
    description: str = Field(..., description="A detailed explanation of the finding.")
    remediation: str = Field(
        ..., description="Steps or recommendations to remediate the identified finding."
    )
    cve: str = Field(
        ..., description="The Common Vulnerabilities and Exposures (CVE) identifier."
    )
    banner: str = Field(
        ...,
        description="The banner or version information of the service, if available, which might indicate the specific vulnerable software.",
    )
    detection_method: str = Field(
        ..., description="The method or tool used to detect this finding."
    )
