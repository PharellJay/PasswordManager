import os

import pytest

from pwmanager import crypto


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Use a cheap scrypt cost in tests; real vaults use the default."""
    monkeypatch.setattr(
        crypto.KdfParams, "new", classmethod(lambda cls: cls(salt=os.urandom(crypto.SALT_LEN), log2_n=10))
    )
