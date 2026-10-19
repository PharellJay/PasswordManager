import stat
import time

import pytest

from pwmanager.crypto import DecryptionError
from pwmanager.vault import Entry, Vault


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "sub" / "vault.pmv"


def test_create_and_reopen(vault_path):
    vault = Vault.create(vault_path, "master")
    vault.add(Entry(title="GitHub", username="me", password="hunter2", url="https://github.com", notes="2FA on"))

    assert stat.S_IMODE(vault_path.stat().st_mode) == 0o600
    assert b"hunter2" not in vault_path.read_bytes()
    assert b"GitHub" not in vault_path.read_bytes()

    reopened = Vault.open(vault_path, "master")
    assert len(reopened.entries) == 1
    e = reopened.entries[0]
    assert (e.title, e.username, e.password, e.url, e.notes) == ("GitHub", "me", "hunter2", "https://github.com", "2FA on")


def test_create_refuses_overwrite(vault_path):
    Vault.create(vault_path, "a")
    with pytest.raises(FileExistsError):
        Vault.create(vault_path, "b")


def test_wrong_password(vault_path):
    Vault.create(vault_path, "master")
    with pytest.raises(DecryptionError):
        Vault.open(vault_path, "nope")


def test_update_delete_search(vault_path):
    vault = Vault.create(vault_path, "m")
    a = vault.add(Entry(title="Email", username="alice@example.com"))
    b = vault.add(Entry(title="Bank", notes="savings"))
    before = a.modified
    time.sleep(0.01)
    vault.update(a.id, password="new")
    assert vault.get(a.id).password == "new"
    assert vault.get(a.id).modified > before

    assert [e.id for e in vault.search("example")] == [a.id]
    assert [e.id for e in vault.search("SAVINGS")] == [b.id]
    assert len(vault.search("")) == 2

    vault.delete(b.id)
    assert [e.id for e in Vault.open(vault_path, "m").entries] == [a.id]


def test_change_password(vault_path):
    vault = Vault.create(vault_path, "old")
    vault.add(Entry(title="x"))
    assert vault.verify_password("old")
    vault.change_password("new")
    with pytest.raises(DecryptionError):
        Vault.open(vault_path, "old")
    assert Vault.open(vault_path, "new").entries[0].title == "x"


def test_export_import_merge(tmp_path):
    src = Vault.create(tmp_path / "src.pmv", "m1")
    shared = src.add(Entry(title="Shared", password="v1"))
    src.add(Entry(title="OnlyInSrc"))
    export = tmp_path / "backup.pmv"
    src.export_to(export, "export-pw")

    dst = Vault.create(tmp_path / "dst.pmv", "m2")
    assert dst.import_from(export, "export-pw") == (2, 0)
    assert dst.import_from(export, "export-pw") == (0, 0)  # idempotent

    time.sleep(0.01)
    src.update(shared.id, password="v2")
    src.export_to(export, "export-pw")
    assert dst.import_from(export, "export-pw") == (0, 1)
    assert Vault.open(tmp_path / "dst.pmv", "m2").get(shared.id).password == "v2"

    with pytest.raises(DecryptionError):
        dst.import_from(export, "m2")
