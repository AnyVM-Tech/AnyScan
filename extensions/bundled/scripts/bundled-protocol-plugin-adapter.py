#!/usr/bin/env python3
from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        invocation = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 1

    # This scaffold intentionally emits no endpoints by default. It exists so
    # the repo ships a stable adapter contract that can later be enabled and
    # extended without changing the worker or manifest format.
    _ = invocation
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
