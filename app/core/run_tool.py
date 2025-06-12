from app.models.scan_config import ScanConfig
from app.utils.target_parser import parse_targets


async def run_tool(scan_config: ScanConfig):
    parsed_targets = await parse_targets(raw_targets=scan_config.target)  # noqa: F841
    # TODO: continue...
