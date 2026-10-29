#!/usr/bin/env python3
"""OHS fixture stub for the P11 gating tests.

Stands in for the real hybrid search binary. Contract it emulates:
- it is invoked directly (list args, never a shell) with "--db" pointing at
  a vault side SQLite path plus the query
- it prints exactly one JSON object on stdout: {"results": [absolute paths]}

The result paths come from the OHS_STUB_RESULTS environment variable (a JSON
list) so a test can hand back one path inside its tempdir vault and one
outside. When OHS_STUB_ARGV_FILE is set, the exact argv received is written
there as JSON so the test can verify the "--db" and query arguments.
"""

import json
import os
import sys


def main() -> int:
    argv_file = os.environ.get("OHS_STUB_ARGV_FILE")
    if argv_file:
        with open(argv_file, "w") as f:
            json.dump(sys.argv, f)
    results = json.loads(os.environ.get("OHS_STUB_RESULTS", "[]"))
    json.dump({"results": results}, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
