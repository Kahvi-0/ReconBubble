from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import shutil
import time

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

@dataclass
class Workspace:
    db_path: Path
    root: Path
    uploads_dir: Path
    exports_dir: Path
    logs_dir: Path

    @classmethod
    def from_db(cls, db_path: Path, workspace: Path | None = None) -> "Workspace":
        db_path = db_path.expanduser().resolve()
        root = (workspace.expanduser().resolve() if workspace else db_path.parent)
        uploads_dir = root / "uploads"
        exports_dir = root / "exports"
        logs_dir = root / "logs"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        exports_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        return cls(db_path=db_path, root=root, uploads_dir=uploads_dir, exports_dir=exports_dir, logs_dir=logs_dir)

    def store_upload(self, src: Path, prefix: str = "upload") -> Path:
        src = src.expanduser().resolve()
        ts = time.strftime("%Y-%m-%d_%H%M%S")
        safe_name = src.name.replace(" ", "_")
        dst = self.uploads_dir / f"{ts}_{prefix}_{safe_name}"
        shutil.copy2(src, dst)
        return dst

    def store_text(self, text: str, filename: str, prefix: str) -> Path:
        ts = time.strftime("%Y-%m-%d_%H%M%S")
        safe_name = filename.replace(" ", "_") if filename else f"{prefix}.txt"
        dst = self.uploads_dir / f"{ts}_{prefix}_{safe_name}"
        dst.write_text(text, encoding="utf-8", errors="ignore")
        return dst
