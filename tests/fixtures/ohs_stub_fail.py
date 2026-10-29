#!/usr/bin/env python3
"""OHS fixture stub that fails: prints nothing parseable and exits 1.

Used by the P11 gating tests to prove search_notes falls back to the pure
substring scan when the hybrid backend errors out.
"""

import sys

sys.stderr.write("stub failure: hybrid backend unavailable\n")
sys.exit(1)
