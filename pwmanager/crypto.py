"""Encryption primitives for the vault file format.

File layout (all integers big-endian):

    magic      4 bytes   b"PMV1"
    version    1 byte    1
    log2_n     1 byte    scrypt cost parameter N = 2**log2_n
    r          1 byte    scrypt block size
    p          1 byte    scrypt parallelism
    salt      16 bytes   random, per vault
    nonce     12 bytes   random, per save
    ciphertext ...       AES-256-GCM(plaintext), tag appended

The header (everything before the nonce) is authenticated as AAD, so
tampering with KDF parameters or the salt is detected on decrypt.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"PMV1"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
_HEADER = struct.Struct(">4sBBBB16s")

DEFAULT_LOG2_N = 17
DEFAULT_R = 8
DEFAULT_P = 1


class DecryptionError(Exception):
    """Raised when a blob cannot be decrypted (wrong password or corrupted)."""


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    log2_n: int = DEFAULT_LOG2_N
    r: int = DEFAULT_R
    p: int = DEFAULT_P

    @classmethod
    def new(cls) -> KdfParams:
        return cls(salt=os.urandom(SALT_LEN))

    def header(self) -> bytes:
        return _HEADER.pack(MAGIC, VERSION, self.log2_n, self.r, self.p, self.salt)


def derive_key(password: str, params: KdfParams) -> bytes:
    kdf = Scrypt(salt=params.salt, length=KEY_LEN, n=2**params.log2_n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))


def encrypt_blob(plaintext: bytes, key: bytes, params: KdfParams) -> bytes:
    header = params.header()
    nonce = os.urandom(NONCE_LEN)
    return header + nonce + AESGCM(key).encrypt(nonce, plaintext, header)


def read_params(blob: bytes) -> KdfParams:
    if len(blob) < _HEADER.size + NONCE_LEN:
        raise DecryptionError("File is too short to be a vault")
    magic, version, log2_n, r, p, salt = _HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise DecryptionError("Not a vault file")
    if version != VERSION:
        raise DecryptionError(f"Unsupported vault version {version}")
    if not (10 <= log2_n <= 22 and 1 <= r <= 32 and 1 <= p <= 16):
        raise DecryptionError("Invalid key derivation parameters")
    return KdfParams(salt=salt, log2_n=log2_n, r=r, p=p)


def decrypt_blob(blob: bytes, key: bytes) -> bytes:
    header = blob[: _HEADER.size]
    nonce = blob[_HEADER.size : _HEADER.size + NONCE_LEN]
    ciphertext = blob[_HEADER.size + NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise DecryptionError("Wrong password or corrupted vault") from None


def decrypt_with_password(blob: bytes, password: str) -> tuple[bytes, bytes, KdfParams]:
    """Decrypt a blob from scratch; returns (plaintext, key, params)."""
    params = read_params(blob)
    key = derive_key(password, params)
    return decrypt_blob(blob, key), key, params
