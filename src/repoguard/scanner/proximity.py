"""Helper for the pairing rules: 'is there a hit within N lines of this line?'"""
from __future__ import annotations

from bisect import bisect_left


def near(line: int, targets: list[int], window: int) -> bool:
    """True if any number in the ASCENDING list `targets` is within `window` of `line`.

    Binary search, so it stays fast on files with tens of thousands of hits.
    """
    i = bisect_left(targets, line - window)
    return i < len(targets) and targets[i] <= line + window
