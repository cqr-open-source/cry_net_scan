import json
import logging
import os
import pathlib
from typing import List

import app.utils.paths_getter as paths_getter
from app.core.paths import HOSTS_PATH, AFROG_TEMP_PATH
from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.modules.afrog.afrog_parser import parse_afrog
from app.utils.hosts_to_file import write_hosts_to_file
from app.utils.subprocess_runner import subprocess_run


async def afrog_scan(
    hosts: List[Host],
    applications: List[Application],
) -> None:
    """
    Executes an `afrog` vulnerability scan against provided hosts.

    Prepares a target file, runs the tool via subprocess, then parses and processes the JSON output.

    Target: prefers domain, url, but IP cover also.
    """
    logger = logging.getLogger(__name__)

    # Save urls, domains, IPs
    await write_hosts_to_file(
        hosts=hosts,
        applications=applications,
        file=HOSTS_PATH,
    )

    afrog_path: pathlib.Path = paths_getter.TOOLS_PATHS[ScannerName.AFROG.value.lower()]

    command = [
        str(afrog_path),
        "-target-file",
        str(HOSTS_PATH),
        "-concurrency",
        "50",
        "-silent",
        # JSON result saves only into the file.
        "-json-all",
        str(AFROG_TEMP_PATH),
    ]

    await subprocess_run(
        command=command,
        module_name=ScannerName.AFROG.value,
    )

    # If the command was successful, the results should be in the temp file
    result: List = []
    if os.path.exists(AFROG_TEMP_PATH):
        try:
            with open(AFROG_TEMP_PATH) as f:
                result = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {ScannerName.AFROG.value} JSON output: {e}")

    else:
        logger.error(
            f"File {AFROG_TEMP_PATH} with {ScannerName.AFROG.value} results does not exist!"
        )

    if result:
        await parse_afrog(
            json_result=result,
            hosts=hosts,
        )

    return None
