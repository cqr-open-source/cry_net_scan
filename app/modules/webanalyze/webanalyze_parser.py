import logging
from typing import List

from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.models.technology_config import Technology
from app.modules.webanalyze.duplicate_finder import search_duplicate_technologies
from app.utils.host_getter import get_host
from app.utils.jsonl_parser import parse_jsonl


async def parse_webanalyze(result: str, hosts: List[Host]) -> None:
    logger = logging.getLogger(__name__)

    # Parse the JSONL content into a list of dictionaries
    parsed_objects: List[dict] | List[None] = await parse_jsonl(jsonl_content=result)

    for host_data in parsed_objects:
        if host_data["matches"]:
            host = await get_host(
                hosts=hosts,
                data=host_data["hostname"],
            )
            if host:
                logger.debug(
                    f"{host.ip_address}: discover {ScannerName.WEBANALYZE.value} technologies"
                )

                for technology_data in host_data["matches"]:
                    technology = technology_data.get("app_name", None)
                    version = technology_data.get("version", "")

                    if await search_duplicate_technologies(
                        host=host, technology=technology
                    ):
                        continue

                    categories = technology_data["app"].get("category_names", [])

                    if technology:
                        logger.debug(
                            f"Found technology: {technology} {version} and categories: {categories}"
                        )
                        host.technologies.append(
                            Technology(
                                name=technology,
                                version=version,
                                categories=categories,
                            )
                        )

    return None
