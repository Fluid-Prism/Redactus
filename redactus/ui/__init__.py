"""ui — the desktop interface, kept apart from the engine.

Nothing in here decides what counts as a finding, and nothing outside here
knows Qt exists. The CLI and the GUI both sit on the same scanner, rules and
store, which is what keeps `python3 -m redactus.audit` honest: it isn't a
cut-down version of the app, it's the same engine with a different surface.
"""
from .window import MainWindow

__all__ = ["MainWindow"]
