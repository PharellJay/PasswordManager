"""Vault model: entries held in memory, persisted as one encrypted file."""

from __future__ import annotations

import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .crypto import DecryptionError, KdfParams, decrypt_with_password, derive_key, encrypt_blob


def default_vault_path() -> Path:
    data_home = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(data_home) / "pwmanager" / "vault.pmv"


@dataclass
class Entry:
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: float = field(default_factory=time.time)
    modified: float = field(default_factory=time.time)

    @classmethod
    def from_dict(cls, data: dict) -> Entry:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def matches(self, query: str) -> bool:
        q = query.casefold()
        return any(q in s.casefold() for s in (self.title, self.username, self.url, self.notes))


def _serialize(entries: list[Entry]) -> bytes:
    return json.dumps({"entries": [asdict(e) for e in entries]}).encode("utf-8")


def _deserialize(data: bytes) -> list[Entry]:
    try:
        payload = json.loads(data)
        return [Entry.from_dict(e) for e in payload["entries"]]
    except (ValueError, KeyError, TypeError) as exc:
        raise DecryptionError("Vault contents are malformed") from exc


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class Vault:
    def __init__(self, path: Path, key: bytes, params: KdfParams, entries: list[Entry]):
        self.path = path
        self._key = key
        self._params = params
        self.entries = entries

    # --- lifecycle -------------------------------------------------------

    @classmethod
    def create(cls, path: Path, password: str) -> Vault:
        if path.exists():
            raise FileExistsError(f"A vault already exists at {path}")
        params = KdfParams.new()
        vault = cls(path, derive_key(password, params), params, [])
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> Vault:
        plaintext, key, params = decrypt_with_password(path.read_bytes(), password)
        return cls(path, key, params, _deserialize(plaintext))

    def save(self) -> None:
        _atomic_write(self.path, encrypt_blob(_serialize(self.entries), self._key, self._params))

    def change_password(self, new_password: str) -> None:
        params = KdfParams.new()
        self._key = derive_key(new_password, params)
        self._params = params
        self.save()

    def verify_password(self, password: str) -> bool:
        return hmac.compare_digest(derive_key(password, self._params), self._key)

    # --- entries ---------------------------------------------------------

    def get(self, entry_id: str) -> Entry | None:
        return next((e for e in self.entries if e.id == entry_id), None)

    def add(self, entry: Entry) -> Entry:
        self.entries.append(entry)
        self.save()
        return entry

    def update(self, entry_id: str, **changes) -> Entry:
        entry = self.get(entry_id)
        if entry is None:
            raise KeyError(entry_id)
        for name, value in changes.items():
            setattr(entry, name, value)
        entry.modified = time.time()
        self.save()
        return entry

    def delete(self, entry_id: str) -> None:
        self.entries = [e for e in self.entries if e.id != entry_id]
        self.save()

    def search(self, query: str) -> list[Entry]:
        return [e for e in self.entries if e.matches(query)] if query else list(self.entries)

    # --- export / import -------------------------------------------------

    def export_to(self, path: Path, password: str) -> None:
        params = KdfParams.new()
        _atomic_write(path, encrypt_blob(_serialize(self.entries), derive_key(password, params), params))

    def import_from(self, path: Path, password: str) -> tuple[int, int]:
        """Merge entries from an exported file. Returns (added, updated)."""
        plaintext, _, _ = decrypt_with_password(path.read_bytes(), password)
        added = updated = 0
        for incoming in _deserialize(plaintext):
            existing = self.get(incoming.id)
            if existing is None:
                self.entries.append(incoming)
                added += 1
            elif incoming.modified > existing.modified:
                self.entries[self.entries.index(existing)] = incoming
                updated += 1
        if added or updated:
            self.save()
        return added, updated
