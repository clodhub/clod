import os
import tempfile

# Tests keep clod's per-user state (ledger, locks, reservations, seeds) in a temporary folder, never the user's.
if "CLOD_STATE_HOME" not in os.environ:
    os.environ["CLOD_STATE_HOME"] = tempfile.mkdtemp(prefix="clod-test-state-")
