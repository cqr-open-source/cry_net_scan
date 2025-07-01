from typing import List, Optional

from pydantic import BaseModel, Field


class SmbContent(BaseModel):
    type: str = Field(..., description="Type of the content.")
    name: str = Field(..., description="The name or path of the file/directory relative to its parent.")

    size: Optional[int] = Field(None, description="Size of the file in bytes. Applicable only when 'type' is 'file'.")


class SmbEnumeration(BaseModel):
    name: str = Field(..., description="The name of the SMB share (e.g., 'public', 'IPC$', 'print$').")
    result: str | None = Field(default=None, description="Result of the scan.")

    remark: Optional[str] = Field(default=None, description="The human-readable description or remark for the share.")
    permission_status: Optional[str] = Field(
        default=None, description="Access status for the share (e.g., 'Read/Write', 'NoRead/NoWrite')."
    )

    contents: List[SmbContent | None] = Field(
        default_factory=list,
        description="List of files, directories, or informational messages found within the share if readable."
    )
