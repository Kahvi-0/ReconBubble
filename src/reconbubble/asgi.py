from pathlib import Path
from .webapp import create_app
app = create_app(Path(__file__).parent.parent.parent / "reconbubble.db")
