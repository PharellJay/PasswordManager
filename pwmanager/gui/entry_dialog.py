"""Add / edit form for a single entry."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from ..generator import estimate_entropy, strength_label
from ..vault import Entry
from .generator_dialog import GeneratorDialog


class EntryDialog(QDialog):
    def __init__(self, clipboard, entry: Entry | None = None, parent=None):
        super().__init__(parent)
        self.clipboard = clipboard
        self.setWindowTitle("Edit Entry" if entry else "New Entry")
        self.setMinimumWidth(480)

        self.title = QLineEdit(entry.title if entry else "")
        self.username = QLineEdit(entry.username if entry else "")
        self.password = QLineEdit(entry.password if entry else "")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.url = QLineEdit(entry.url if entry else "")
        self.url.setPlaceholderText("https://")
        self.notes = QPlainTextEdit(entry.notes if entry else "")

        show = QPushButton("Show", checkable=True)
        show.toggled.connect(
            lambda on: (
                self.password.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password),
                show.setText("Hide" if on else "Show"),
            )
        )
        generate = QPushButton("Generate…")
        generate.clicked.connect(self._generate)
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(show)
        pw_row.addWidget(generate)

        self.strength = QLabel()
        self.password.textChanged.connect(self._update_strength)
        self._update_strength(self.password.text())

        form = QFormLayout()
        form.addRow("Title:", self.title)
        form.addRow("Username:", self.username)
        form.addRow("Password:", pw_row)
        form.addRow("", self.strength)
        form.addRow("URL:", self.url)
        form.addRow("Notes:", self.notes)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _update_strength(self, text: str) -> None:
        if text:
            bits = estimate_entropy(text)
            self.strength.setText(f"<small>{strength_label(bits)} (~{bits:.0f} bits)</small>")
        else:
            self.strength.clear()

    def _generate(self) -> None:
        dialog = GeneratorDialog(self.clipboard, self)
        if dialog.exec():
            self.password.setText(dialog.result)

    def _accept(self) -> None:
        if not self.title.text().strip():
            QMessageBox.warning(self, "Missing title", "Please give the entry a title.")
            return
        self.accept()

    def values(self) -> dict:
        return {
            "title": self.title.text().strip(),
            "username": self.username.text(),
            "password": self.password.text(),
            "url": self.url.text().strip(),
            "notes": self.notes.toPlainText(),
        }
