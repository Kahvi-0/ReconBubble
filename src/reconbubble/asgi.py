import os
from pathlib import Path
from .webapp import create_app
_db = os.environ.get("RECONBUBBLE_DB") or str(Path(__file__).parent.parent.parent / "workspace.sqlite")
app = create_app(Path(_db))
