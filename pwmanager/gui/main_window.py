"""Main vault window: searchable entry list plus a detail pane."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..crypto import DecryptionError
from ..vault import Entry, Vault
from .entry_dialog import EntryDialog
from .generator_dialog import GeneratorDialog
from .unlock import password_field

MASKED = "•" * 10


class PasswordPrompt(QDialog):
    """Asks for one or more passwords; `fields` maps label -> QLineEdit."""

    def __init__(self, title: str, message: str, labels: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(400)
        self.fields = {label: password_field() for label in labels}
        form = QFormLayout()
        for label, field in self.fields.items():
            form.addRow(label, field)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(message, wordWrap=True))
        layout.addLayout(form)
        layout.addWidget(buttons)

    def value(self, label: str) -> str:
        return self.fields[label].text()


class DetailPane(QWidget):
    def __init__(self, clipboard, parent=None):
        super().__init__(parent)
        self.clipboard = clipboard
        self.entry: Entry | None = None
        self._revealed = False

        self.title = QLabel()
        font = self.title.font()
        font.setPointSize(font.pointSize() + 4)
        font.setBold(True)
        self.title.setFont(font)

        selectable = Qt.TextInteractionFlag.TextSelectableByMouse
        self.username = QLabel(textInteractionFlags=selectable)
        self.password = QLabel(textInteractionFlags=selectable)
        self.url = QLabel(textInteractionFlags=selectable)
        self.notes = QPlainTextEdit(readOnly=True)

        self.copy_user = QPushButton("Copy")
        self.copy_user.clicked.connect(lambda: self.entry and self.clipboard.copy(self.entry.username))
        self.copy_pw = QPushButton("Copy")
        self.copy_pw.clicked.connect(lambda: self.entry and self.clipboard.copy(self.entry.password))
        self.reveal = QPushButton("Show")
        self.reveal.clicked.connect(self._toggle_reveal)
        self.open_url = QPushButton("Open")
        self.open_url.clicked.connect(self._open_url)

        grid = QGridLayout()
        grid.addWidget(QLabel("Username:"), 0, 0)
        grid.addWidget(self.username, 0, 1)
        grid.addWidget(self.copy_user, 0, 2)
        grid.addWidget(QLabel("Password:"), 1, 0)
        grid.addWidget(self.password, 1, 1)
        grid.addWidget(self.copy_pw, 1, 2)
        grid.addWidget(self.reveal, 1, 3)
        grid.addWidget(QLabel("URL:"), 2, 0)
        grid.addWidget(self.url, 2, 1)
        grid.addWidget(self.open_url, 2, 2)
        grid.setColumnStretch(1, 1)

        self.empty = QLabel("Select an entry, or press Ctrl+N to add one.", alignment=Qt.AlignmentFlag.AlignCenter)

        self.content = QWidget()
        content_layout = QVBoxLayout(self.content)
        content_layout.addWidget(self.title)
        content_layout.addLayout(grid)
        content_layout.addWidget(QLabel("Notes:"))
        content_layout.addWidget(self.notes, 1)

        layout = QVBoxLayout(self)
        layout.addWidget(self.empty, 1)
        layout.addWidget(self.content, 1)
        self.show_entry(None)

    def show_entry(self, entry: Entry | None) -> None:
        self.entry = entry
        self._revealed = False
        self.empty.setVisible(entry is None)
        self.content.setVisible(entry is not None)
        if entry is None:
            self.notes.clear()
            self.password.clear()
            return
        self.title.setText(entry.title)
        self.username.setText(entry.username)
        self.url.setText(entry.url)
        self.notes.setPlainText(entry.notes)
        self.copy_user.setEnabled(bool(entry.username))
        self.copy_pw.setEnabled(bool(entry.password))
        self.reveal.setEnabled(bool(entry.password))
        self.open_url.setEnabled(bool(entry.url))
        self._render_password()

    def _render_password(self) -> None:
        if self.entry is None or not self.entry.password:
            self.password.setText("")
        else:
            self.password.setText(self.entry.password if self._revealed else MASKED)
        self.reveal.setText("Hide" if self._revealed else "Show")

    def _toggle_reveal(self) -> None:
        self._revealed = not self._revealed
        self._render_password()

    def _open_url(self) -> None:
        if not self.entry:
            return
        url = self.entry.url if "://" in self.entry.url else f"https://{self.entry.url}"
        QDesktopServices.openUrl(QUrl(url))


class MainWindow(QMainWindow):
    lock_requested = Signal()
    closed = Signal()

    def __init__(self, vault: Vault, clipboard, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.clipboard = clipboard
        self.setWindowTitle(f"Password Manager — {vault.path.name}")
        self.resize(900, 560)

        self.search = QLineEdit(placeholderText="Search…", clearButtonEnabled=True)
        self.search.textChanged.connect(self.refresh)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._selection_changed)
        self.list.itemDoubleClicked.connect(lambda _: self.edit_entry())

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(self.search)
        left_layout.addWidget(self.list)

        self.detail = DetailPane(clipboard)
        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 620])
        self.setCentralWidget(splitter)

        self._build_actions()
        self.refresh()
        self.search.setFocus()

    def closeEvent(self, event) -> None:
        super().closeEvent(event)
        self.closed.emit()

    # --- setup -----------------------------------------------------------

    def _action(self, text: str, slot, shortcut=None) -> QAction:
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(slot)
        return action

    def _build_actions(self) -> None:
        self.new_action = self._action("New Entry", self.new_entry, QKeySequence.StandardKey.New)
        self.edit_action = self._action("Edit Entry", self.edit_entry, "Ctrl+E")
        self.delete_action = self._action("Delete Entry", self.delete_entry, QKeySequence.StandardKey.Delete)
        copy_user = self._action("Copy Username", lambda: self._copy("username"), "Ctrl+B")
        copy_pw = self._action("Copy Password", lambda: self._copy("password"), "Ctrl+C")
        generate = self._action("Generate Password…", self.open_generator, "Ctrl+G")
        lock = self._action("Lock", self.lock_requested.emit, "Ctrl+L")
        export = self._action("Export…", self.export_vault)
        import_ = self._action("Import…", self.import_vault)
        change_pw = self._action("Change Master Password…", self.change_master_password)
        quit_ = self._action("Quit", self.close, QKeySequence.StandardKey.Quit)
        find = self._action("Find", lambda: (self.search.setFocus(), self.search.selectAll()), QKeySequence.StandardKey.Find)

        vault_menu = self.menuBar().addMenu("&Vault")
        for a in (lock, None, export, import_, None, change_pw, None, quit_):
            vault_menu.addSeparator() if a is None else vault_menu.addAction(a)
        entry_menu = self.menuBar().addMenu("&Entry")
        for a in (self.new_action, self.edit_action, self.delete_action, None, copy_user, copy_pw, None, find):
            entry_menu.addSeparator() if a is None else entry_menu.addAction(a)
        tools_menu = self.menuBar().addMenu("&Tools")
        tools_menu.addAction(generate)

        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        for a in (self.new_action, self.edit_action, self.delete_action, None, copy_user, copy_pw, None, generate, lock):
            toolbar.addSeparator() if a is None else toolbar.addAction(a)

    # --- list ------------------------------------------------------------

    def refresh(self, select_id: str | None = None) -> None:
        if select_id is None and self.detail.entry is not None:
            select_id = self.detail.entry.id
        self.list.blockSignals(True)
        self.list.clear()
        entries = sorted(self.vault.search(self.search.text()), key=lambda e: e.title.casefold())
        for entry in entries:
            item = QListWidgetItem(entry.title)
            item.setData(Qt.ItemDataRole.UserRole, entry.id)
            if entry.username:
                item.setToolTip(entry.username)
            self.list.addItem(item)
            if entry.id == select_id:
                self.list.setCurrentItem(item)
        if self.list.currentItem() is None and self.list.count():
            self.list.setCurrentRow(0)
        self.list.blockSignals(False)
        self._selection_changed(self.list.currentItem())

    def _selection_changed(self, item: QListWidgetItem | None, _previous=None) -> None:
        entry = self.vault.get(item.data(Qt.ItemDataRole.UserRole)) if item else None
        self.detail.show_entry(entry)
        self.edit_action.setEnabled(entry is not None)
        self.delete_action.setEnabled(entry is not None)

    def current_entry(self) -> Entry | None:
        return self.detail.entry

    # --- entry actions ---------------------------------------------------

    def _save_failed(self, exc: Exception) -> None:
        QMessageBox.critical(self, "Save failed", f"Could not save the vault:\n{exc}")

    def new_entry(self) -> None:
        dialog = EntryDialog(self.clipboard, parent=self)
        if dialog.exec() and self.vault is not None:
            try:
                entry = self.vault.add(Entry(**dialog.values()))
            except OSError as exc:
                return self._save_failed(exc)
            self.search.clear()
            self.refresh(entry.id)

    def edit_entry(self) -> None:
        entry = self.current_entry()
        if entry is None:
            return
        dialog = EntryDialog(self.clipboard, entry, self)
        if dialog.exec() and self.vault is not None:
            try:
                self.vault.update(entry.id, **dialog.values())
            except OSError as exc:
                return self._save_failed(exc)
            self.refresh(entry.id)

    def delete_entry(self) -> None:
        entry = self.current_entry()
        if entry is None:
            return
        answer = QMessageBox.question(self, "Delete entry", f"Delete “{entry.title}”? This cannot be undone.")
        if answer == QMessageBox.StandardButton.Yes and self.vault is not None:
            try:
                self.vault.delete(entry.id)
            except OSError as exc:
                return self._save_failed(exc)
            self.detail.show_entry(None)
            self.refresh()

    def _copy(self, field: str) -> None:
        entry = self.current_entry()
        if entry and getattr(entry, field):
            self.clipboard.copy(getattr(entry, field))
            self.statusBar().showMessage(f"{field.capitalize()} copied — clipboard clears in 20 seconds", 5000)

    def open_generator(self) -> None:
        GeneratorDialog(self.clipboard, self, use_button=False).exec()

    # --- vault actions ---------------------------------------------------

    def export_vault(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Vault", str(Path.home() / "vault-backup.pmv"), "Vault files (*.pmv)"
        )
        if not path or self.vault is None:
            return
        prompt = PasswordPrompt(
            "Export Password",
            "Choose a password for the exported file. You will need it to import the backup.",
            ["Export password:", "Confirm:"],
            self,
        )
        if not prompt.exec() or self.vault is None:
            return
        password = prompt.value("Export password:")
        if not password or password != prompt.value("Confirm:"):
            QMessageBox.warning(self, "Export", "Passwords are empty or do not match.")
            return
        try:
            self.vault.export_to(Path(path), password)
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export", f"Exported {len(self.vault.entries)} entries to\n{path}")

    def import_vault(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Vault", str(Path.home()), "Vault files (*.pmv)")
        if not path or self.vault is None:
            return
        prompt = PasswordPrompt("Import", "Enter the password of the file to import.", ["Password:"], self)
        if not prompt.exec() or self.vault is None:
            return
        try:
            added, updated = self.vault.import_from(Path(path), prompt.value("Password:"))
        except (DecryptionError, OSError) as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self.refresh()
        QMessageBox.information(self, "Import", f"Added {added} and updated {updated} entries.")

    def change_master_password(self) -> None:
        prompt = PasswordPrompt(
            "Change Master Password",
            "Enter your current master password and choose a new one.",
            ["Current:", "New:", "Confirm new:"],
            self,
        )
        if not prompt.exec() or self.vault is None:
            return
        if not self.vault.verify_password(prompt.value("Current:")):
            QMessageBox.warning(self, "Change Master Password", "The current password is incorrect.")
            return
        new = prompt.value("New:")
        if not new or new != prompt.value("Confirm new:"):
            QMessageBox.warning(self, "Change Master Password", "New passwords are empty or do not match.")
            return
        try:
            self.vault.change_password(new)
        except OSError as exc:
            return self._save_failed(exc)
        QMessageBox.information(self, "Change Master Password", "Master password changed.")
