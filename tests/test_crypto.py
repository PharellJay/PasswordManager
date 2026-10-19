import pytest

from pwmanager.crypto import (
    DecryptionError,
    KdfParams,
    decrypt_blob,
    decrypt_with_password,
    derive_key,
    encrypt_blob,
    read_params,
)


def test_roundtrip():
    params = KdfParams.new()
    key = derive_key("correct horse", params)
    blob = encrypt_blob(b"secret data", key, params)
    assert b"secret data" not in blob
    plaintext, key2, params2 = decrypt_with_password(blob, "correct horse")
    assert plaintext == b"secret data"
    assert key2 == key
    assert params2 == params


def test_fresh_nonce_each_encrypt():
    params = KdfParams.new()
    key = derive_key("pw", params)
    assert encrypt_blob(b"x", key, params) != encrypt_blob(b"x", key, params)


def test_wrong_password():
    params = KdfParams.new()
    blob = encrypt_blob(b"data", derive_key("right", params), params)
    with pytest.raises(DecryptionError):
        decrypt_with_password(blob, "wrong")


@pytest.mark.parametrize("offset", [10, 30, -1])
def test_tampering_detected(offset):
    params = KdfParams.new()
    key = derive_key("pw", params)
    blob = bytearray(encrypt_blob(b"data" * 10, key, params))
    blob[offset] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_blob(bytes(blob), key)


def test_rejects_non_vault():
    with pytest.raises(DecryptionError):
        read_params(b"not a vault file at all, definitely not")
    with pytest.raises(DecryptionError):
        read_params(b"short")
