import logging
from typing import List, Literal
import json
import pathlib

from app.models.host_config import Host


async def save_data(
    all_hosts: List[Host],
    report_format: Literal["json", "pdf"],
    report_base_dir: pathlib.Path,
    report_file: pathlib.Path,
    report_zip: bool,
):
    logger = logging.getLogger(__name__)

    # TODO: report_format, report_zip

    json_data = json.dumps([host.model_dump() for host in all_hosts])
    output_file = pathlib.Path(f"{report_base_dir}/{report_file}")
    output_file.write_text(json_data)

    logger.info(f"Final results save to {output_file.absolute().as_uri()}")
