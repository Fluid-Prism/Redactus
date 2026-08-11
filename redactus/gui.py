"""gui.py — entry point for the desktop app.

The interface itself lives in `redactus/ui/`. This stays as the entry point
so `python3 -m redactus`, `python3 -m redactus.gui` and the packaged
gui-script all keep working.
"""
import sys

from PySide6.QtWidgets import QApplication

from . import warn_if_root
from .ui import MainWindow


def main():
    warn_if_root()
    app = QApplication(sys.argv)
    app.setApplicationName("Redactus")
    app.setOrganizationName("Fluid-Prism")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
