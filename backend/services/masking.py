"""Destination numbers are stored in full but returned masked unless explicitly unmasked (audited)."""
from __future__ import annotations


def mask_msisdn(number: str) -> str:
    if len(number) <= 7:
        return "*" * len(number)
    return number[:5] + "*" * (len(number) - 7) + number[-2:]


def mask_entity(entity_type: str, entity_key: str) -> str:
    if entity_type == "destination":
        return mask_msisdn(entity_key)
    if entity_type == "sender_destination":
        sender, _, dest = entity_key.partition(">")
        return f"{sender}>{mask_msisdn(dest)}"
    return entity_key


def contains_number(entity_type: str) -> int:
    """How many destination numbers an entity key exposes when unmasked."""
    return 1 if entity_type in {"destination", "sender_destination"} else 0
