"""Copy secrets to the clipboard and clear them again after a timeout."""

from __future__ import annotations

import os
import shutil
import subprocess

from PySide6.QtCore import QMimeData, QObject, QTimer
from PySide6.QtGui import QGuiApplication

CLEAR_AFTER_MS = 20_000

# Clipboard managers (KDE Klipper, GNOME extensions, ...) honour this hint
# and keep the value out of their history.
_SECRET_HINT = "x-kde-passwordManagerHint"


def _on_wayland() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY")) and shutil.which("wl-copy") is not None


class SecureClipboard(QObject):
    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._copied: str | None = None
        self._timer = QTimer(self, singleShot=True, interval=CLEAR_AFTER_MS)
        self._timer.timeout.connect(self.clear)

    def copy(self, text: str) -> None:
        mime = QMimeData()
        mime.setText(text)
        mime.setData(_SECRET_HINT, b"secret")
        QGuiApplication.clipboard().setMimeData(mime)
        self._copied = text
        self._timer.start()

    def clear(self) -> None:
        """Clear the clipboard, but only if it still holds what we copied."""
        self._timer.stop()
        if self._copied is None:
            return
        copied, self._copied = self._copied, None
        clipboard = QGuiApplication.clipboard()
        # If another app has copied something since, ownership moved away and
        # we leave it alone. (Don't read the clipboard back via an external
        # tool here: it would ask this blocked process for the data.)
        if not clipboard.ownsClipboard() or clipboard.text() != copied:
            return
        if _on_wayland():
            # Qt can't reliably set the selection on Wayland while unfocused,
            # so go through wl-clipboard instead.
            try:
                subprocess.run(["wl-copy", "--clear"], timeout=2, check=True)
                return
            except (OSError, subprocess.SubprocessError):
                pass
        clipboard.clear()
