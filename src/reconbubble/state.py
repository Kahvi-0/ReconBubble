from __future__ import annotations


class AppState:
    """Shared per-app state passed to router build() factories."""

    def __init__(self, app, ws, templates, SessionLocal, project_name: str = ""):
        self.app = app
        self.ws = ws
        self.templates = templates
        self.SessionLocal = SessionLocal
        self.project_name = project_name

    def db(self):
        return self.SessionLocal()
