"""A harmless fixture file that is inspected but never imported by the auditor."""


def normalize(value: str) -> str:
    return " ".join(value.split())
