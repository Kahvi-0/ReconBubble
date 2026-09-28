import os
from pathlib import Path
from .webapp import create_app
from .workspace import Workspace
_db = os.environ.get("RECONBUBBLE_DB") or str(Path(__file__).parent.parent.parent / "workspace.sqlite")
_ws = Workspace.from_db(Path(_db))
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", os.environ.get("RECONBUBBLE_BROWSER_DIR") or str(_ws.browser_dir))
if not os.environ.get("RECONBUBBLE_BROWSER_MODE"):
    _browser_target = Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"]).expanduser().resolve()
    os.environ["RECONBUBBLE_BROWSER_MODE"] = "workspace" if _browser_target == _ws.browser_dir else "custom"
app = create_app(Path(_db), _ws.root, os.environ.get("RECONBUBBLE_PROJECT", ""))
