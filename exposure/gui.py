"""gui.py — entry point for the desktop app.

The interface itself lives in `exposure/ui/`. This stays as the entry point
so `python3 -m exposure`, `python3 -m exposure.gui` and the packaged
gui-script all keep working.
"""
import sys

from PySide6.QtWidgets import QApplication

from . import warn_if_root
from .ui import MainWindow


def main():
    warn_if_root()
    app = QApplication(sys.argv)
    app.setApplicationName("Exposure Auditor")
    app.setOrganizationName("Fluid-Prism")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
