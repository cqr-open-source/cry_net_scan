from typing import Optional, List

from pydantic import BaseModel, Field


class Technology(BaseModel):
    """
    Represents detailed information about a single discovered technology.
    """

    name: str = Field(..., description="Name of the technology.")

    version: Optional[str] = Field(
        default_factory=str,
        description="Version of the technology.",
    )

    categories: List[str] = Field(
        default_factory=list, description="List of categories."
    )
