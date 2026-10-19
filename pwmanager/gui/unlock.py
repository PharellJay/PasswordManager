"""Dialog for creating a new vault or unlocking an existing one."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

from ..crypto import DecryptionError
from ..vault import Vault

MIN_MASTER_LENGTH = 8


def password_field() -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    return field


class UnlockDialog(QDialog):
    def __init__(self, path: Path, parent=None):
        super().__init__(parent)
        self.path = path
        self.vault: Vault | None = None
        self.creating = not path.exists()

        self.setWindowTitle("Create Vault" if self.creating else "Unlock Vault")
        self.setMinimumWidth(420)

        heading = QLabel(
            "Choose a master password for your new vault.\n"
            "It cannot be recovered if you forget it."
            if self.creating
            else "Enter your master password."
        )
        location = QLabel(f"<small>{path}</small>")
        location.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.password = password_field()
        self.confirm = password_field()
        self.error = QLabel()
        self.error.setStyleSheet("color: #c0392b")
        self.error.hide()

        form = QFormLayout()
        form.addRow("Master password:", self.password)
        if self.creating:
            form.addRow("Confirm:", self.confirm)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create" if self.creating else "Unlock")
        buttons.accepted.connect(self._submit)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(location)
        layout.addLayout(form)
        layout.addWidget(self.error)
        layout.addWidget(buttons)

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        self.password.selectAll()
        self.password.setFocus()

    def _submit(self) -> None:
        password = self.password.text()
        if not password:
            return self._fail("Please enter a password.")

        if self.creating:
            if password != self.confirm.text():
                return self._fail("Passwords do not match.")
            if len(password) < MIN_MASTER_LENGTH:
                answer = QMessageBox.warning(
                    self,
                    "Weak master password",
                    f"Your master password is shorter than {MIN_MASTER_LENGTH} characters. Use it anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return

        self.setEnabled(False)
        self.setCursor(Qt.CursorShape.WaitCursor)
        try:
            self.vault = Vault.create(self.path, password) if self.creating else Vault.open(self.path, password)
        except (DecryptionError, OSError) as exc:
            return self._fail(str(exc))
        finally:
            self.unsetCursor()
            self.setEnabled(True)
            self.password.clear()
            self.confirm.clear()
        self.accept()
