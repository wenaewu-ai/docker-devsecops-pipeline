import sys
from pathlib import Path

# The CI helper scripts are plain files, not a package; make them importable for the tests.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / ".github" / "scripts"))
