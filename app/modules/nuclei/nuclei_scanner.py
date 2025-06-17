import asyncio
import logging
from typing import List

from app.core.paths import NUCLEI_HOSTS_PATH
from app.core.paths import TOOLS_LINUX_NUCLEI_PATH
from app.models.host_config import Host
from app.modules.nuclei.http_hosts_to_file_writer import write_http_hosts_to_file
from app.modules.nuclei.nuclei_parser import parse_nuclei


async def nuclei_scan(
    hosts: List[Host],
) -> None:
    """Executes a vulnerability scan on the provided list of hosts using the Nuclei scanner.

    This function performs the following steps:
    1. Writes the HTTP-enabled hosts from the input 'hosts' list to a temporary file,
       which serves as Nuclei's target list.
    2. Constructs and executes the Nuclei command with JSON output enabled.
    3. Captures the standard output (stdout) and standard error (stderr) from the Nuclei process.
    4. Parses the JSON output from Nuclei's stdout and updates the 'hosts' list in-place
       with any discovered vulnerabilities and additional port information.
    """
    logger = logging.getLogger(__name__)

    # [START] If we need to fast check!
    # from app.core.paths import ROOT_PATH
    #
    # with open(ROOT_PATH.joinpath("nuclei.json"), "r") as f:
    #     stdout = f.read()
    # await parse_nuclei(nuclei_result=stdout, hosts=hosts)
    # return None
    # [END] If we need to fast check!

    await write_http_hosts_to_file(
        hosts=hosts,
        file=NUCLEI_HOSTS_PATH,
    )

    command = [
        str(TOOLS_LINUX_NUCLEI_PATH),
        "-l",
        str(NUCLEI_HOSTS_PATH),
        "-jsonl",
    ]
    logger.info(f"Running NUCLEI command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout_bytes, stderr_bytes = await process.communicate()

        stdout = stdout_bytes.decode("utf-8").strip()
        stderr = stderr_bytes.decode("utf-8").strip()

        if stderr:
            logger.warning(f"NUCLEI stderr: {stderr}")

        await parse_nuclei(nuclei_result=stdout, hosts=hosts)

    except Exception as e:
        logger.error(f"Error running RUSTSCAN or parsing output: {e}", exc_info=True)

    return None
