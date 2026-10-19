"""Application controller: unlock flow, auto-lock on idle, clipboard cleanup."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QTimer
from PySide6.QtWidgets import QApplication, QDialog

from .clipboard import SecureClipboard
from .main_window import MainWindow
from .unlock import UnlockDialog

AUTO_LOCK_MS = 5 * 60 * 1000

_ACTIVITY_EVENTS = {
    QEvent.Type.KeyPress,
    QEvent.Type.MouseButtonPress,
    QEvent.Type.MouseMove,
    QEvent.Type.Wheel,
}


class Controller(QObject):
    def __init__(self, app: QApplication, vault_path: Path):
        super().__init__()
        self.app = app
        self.vault_path = vault_path
        self.window: MainWindow | None = None
        self.clipboard = SecureClipboard(self)

        self.idle_timer = QTimer(self, singleShot=True, interval=AUTO_LOCK_MS)
        self.idle_timer.timeout.connect(self.lock)
        app.installEventFilter(self)
        app.aboutToQuit.connect(self.clipboard.clear)

    def eventFilter(self, obj, event) -> bool:
        if self.window is not None and event.type() in _ACTIVITY_EVENTS:
            self.idle_timer.start()
        return False

    def unlock(self) -> bool:
        dialog = UnlockDialog(self.vault_path)
        if not dialog.exec() or dialog.vault is None:
            return False
        self.window = MainWindow(dialog.vault, self.clipboard)
        self.window.lock_requested.connect(self.lock)
        self.window.closed.connect(self.app.quit)
        self.window.show()
        self.idle_timer.start()
        return True

    def lock(self) -> None:
        self.idle_timer.stop()
        self.clipboard.clear()
        if self.window is not None:
            # Close any open dialogs belonging to the window before dropping it.
            for dialog in self.window.findChildren(QDialog):
                dialog.reject()
            window, self.window = self.window, None
            window.vault = None
            window.hide()
            window.deleteLater()
        # Defer so any nested dialog event loops unwind before we prompt again.
        QTimer.singleShot(0, self._relock_prompt)

    def _relock_prompt(self) -> None:
        if self.window is None and not self.unlock():
            self.app.quit()


def run(vault_path: Path) -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Password Manager")
    app.setDesktopFileName("pwmanager")
    app.setQuitOnLastWindowClosed(False)

    controller = Controller(app, vault_path)
    if not controller.unlock():
        return 0
    return app.exec()
