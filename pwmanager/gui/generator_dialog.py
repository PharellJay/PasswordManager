"""Password / passphrase generator dialog."""

from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from ..generator import estimate_entropy, generate_passphrase, generate_password, passphrase_entropy, strength_label


class GeneratorDialog(QDialog):
    """Generates a value; `result` holds it after the dialog is accepted.

    With `use_button=False` the dialog is standalone (copy + close only).
    """

    def __init__(self, clipboard, parent=None, use_button: bool = True):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.setMinimumWidth(480)
        self.clipboard = clipboard
        self.result = ""

        self.output = QLineEdit()
        self.output.setReadOnly(True)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(mono.pointSize() + 2)
        self.output.setFont(mono)
        regenerate = QPushButton("Regenerate")
        regenerate.clicked.connect(self.regenerate)
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda: self.clipboard.copy(self.output.text()))
        out_row = QHBoxLayout()
        out_row.addWidget(self.output, 1)
        out_row.addWidget(regenerate)
        out_row.addWidget(copy)
        self.strength = QLabel()

        self.mode = QTabBar()
        self.mode.addTab("Password")
        self.mode.addTab("Passphrase")

        # Password options
        self.length = QSpinBox(minimum=4, maximum=128, value=20)
        self.lower = QCheckBox("a-z", checked=True)
        self.upper = QCheckBox("A-Z", checked=True)
        self.digits = QCheckBox("0-9", checked=True)
        self.symbols = QCheckBox("!@#$…", checked=True)
        self.ambiguous = QCheckBox("Avoid ambiguous characters (I, l, 1, O, 0)")
        classes = QHBoxLayout()
        for box in (self.lower, self.upper, self.digits, self.symbols):
            classes.addWidget(box)
        pw_page = QWidget()
        pw_form = QFormLayout(pw_page)
        pw_form.addRow("Length:", self.length)
        pw_form.addRow("Characters:", classes)
        pw_form.addRow("", self.ambiguous)

        # Passphrase options
        self.words = QSpinBox(minimum=3, maximum=20, value=6)
        self.separator = QLineEdit("-", maxLength=3)
        self.capitalize = QCheckBox("Capitalize words")
        pp_page = QWidget()
        pp_form = QFormLayout(pp_page)
        pp_form.addRow("Words:", self.words)
        pp_form.addRow("Separator:", self.separator)
        pp_form.addRow("", self.capitalize)

        self.pages = QStackedWidget()
        self.pages.addWidget(pw_page)
        self.pages.addWidget(pp_page)
        self.mode.currentChanged.connect(self.pages.setCurrentIndex)
        self.mode.currentChanged.connect(self.regenerate)

        for widget in (self.length, self.words):
            widget.valueChanged.connect(self.regenerate)
        for widget in (self.lower, self.upper, self.digits, self.symbols, self.ambiguous, self.capitalize):
            widget.toggled.connect(self.regenerate)
        self.separator.textChanged.connect(self.regenerate)

        if use_button:
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
            buttons.addButton("Use Password", QDialogButtonBox.ButtonRole.AcceptRole)
        else:
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(out_row)
        layout.addWidget(self.strength)
        layout.addWidget(self.mode)
        layout.addWidget(self.pages)
        layout.addWidget(buttons)

        self.regenerate()

    def regenerate(self) -> None:
        try:
            if self.mode.currentIndex() == 0:
                value = generate_password(
                    self.length.value(),
                    lower=self.lower.isChecked(),
                    upper=self.upper.isChecked(),
                    digits=self.digits.isChecked(),
                    symbols=self.symbols.isChecked(),
                    avoid_ambiguous=self.ambiguous.isChecked(),
                )
                bits = estimate_entropy(value)
            else:
                value = generate_passphrase(self.words.value(), self.separator.text(), self.capitalize.isChecked())
                bits = passphrase_entropy(self.words.value())
        except ValueError as exc:
            self.output.clear()
            self.strength.setText(str(exc))
            return
        self.output.setText(value)
        self.strength.setText(f"Strength: {strength_label(bits)} (~{bits:.0f} bits)")

    def _accept(self) -> None:
        self.result = self.output.text()
        if self.result:
            self.accept()
