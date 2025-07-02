import re

from rapidfuzz import fuzz


async def is_substring(str1: str, str2: str) -> bool:
    """Checks if str1 is a substring of str2 or vice versa."""
    return str1 in str2 or str2 in str1


async def cut_before_first_letter(host_name: str) -> str:
    """If IP has letters, e.g. '244.29.238.44.in-addr.arpa' - cut until the first letter."""
    match = re.search(r"[A-Za-z]", host_name)
    if match:
        return host_name[: match.start() - 1]

    return host_name


async def is_similar_vuln(
    name_1: str,
    name_2: str,
    template_id_1: str,
    template_id_2: str,
    threshold: int = 70,
) -> bool:
    """
    Checks if two vulnerabilities are similar by comparing their names and template IDs using fuzzy matching.
    Returns True if either the name or template ID similarity score exceeds the threshold, False otherwise.
    """
    score_name = fuzz.token_sort_ratio(name_1 or "", name_2 or "")
    score_template = fuzz.ratio(template_id_1 or "", template_id_2 or "")

    return score_name > threshold or score_template > threshold
