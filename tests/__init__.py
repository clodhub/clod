import os
import tempfile

# Tests keep aepm's per-user state (ledger, locks, reservations, seeds) in a temporary folder, never the user's.
if "AEPM_STATE_HOME" not in os.environ:
    os.environ["AEPM_STATE_HOME"] = tempfile.mkdtemp(prefix="aepm-test-state-")
