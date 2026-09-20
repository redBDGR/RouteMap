"""Reading the plain-text targets file."""

from __future__ import annotations


def read_targets(path: str) -> list[str]:
    """Load one hostname/IP per line, ignoring blanks and '#' comments."""
    targets: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets
