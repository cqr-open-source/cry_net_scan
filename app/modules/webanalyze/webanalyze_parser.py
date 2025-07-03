import logging
from typing import List, Optional, Union

from app.models.application_config import Application
from app.models.host_config import Host
from app.models.scanner_config import ScannerName
from app.models.technology_config import Technology
from app.modules.webanalyze.duplicate_finder import search_duplicate_technologies
from app.utils.jsonl_parser import parse_jsonl
from app.utils.target_getter.target_getter import get_target


async def parse_webanalyze(
    result: str,
    hosts: List[Host],
) -> None:
    logger = logging.getLogger(__name__)

    # Parse the JSONL content into a list of dictionaries
    parsed_objects: List[dict] | List[None] = await parse_jsonl(jsonl_content=result)

    for host_data in parsed_objects:
        if host_data["matches"]:
            target: Optional[Union[Application, Host]] = await get_target(
                hosts=hosts,
                data=host_data["hostname"],
                scanner_name=ScannerName.WEBANALYZE.value,
            )

            if target:
                for technology_data in host_data["matches"]:
                    technology = technology_data.get("app_name", None)
                    version = technology_data.get("version", "")

                    if await search_duplicate_technologies(
                        host=target,
                        technology_name=technology,
                        hosts=hosts,
                    ):
                        continue

                    categories = technology_data["app"].get("category_names", [])

                    if technology:
                        logger.debug(
                            f"Found technology: {technology} {version} and categories: {categories}"
                        )
                        target.technologies.append(
                            Technology(
                                name=technology,
                                version=version,
                                categories=categories,
                            )
                        )

    return None
