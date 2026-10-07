from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Iterable


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def tally(reasons: Iterable[str], top: int = 5) -> str:
    """The most frequent reasons as "3x HTTPError 410; 1x TimeoutError"."""
    return "; ".join(f"{n}x {reason}" for reason, n in Counter(reasons).most_common(top))
