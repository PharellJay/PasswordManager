"""Cryptographically secure password and passphrase generation."""

from __future__ import annotations

import math
import secrets
import string

from .wordlist import WORDS

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"
AMBIGUOUS = set("Il1O0o|`'\"")


def generate_password(
    length: int = 20,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """Return a random password containing at least one char of each enabled class."""
    classes = [c for c, on in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols)) if on]
    if not classes:
        raise ValueError("Select at least one character class")
    if avoid_ambiguous:
        classes = ["".join(ch for ch in c if ch not in AMBIGUOUS) for c in classes]
    if length < len(classes):
        raise ValueError(f"Length must be at least {len(classes)}")

    alphabet = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # Fisher-Yates shuffle with a CSPRNG so the guaranteed chars aren't at the front.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def generate_passphrase(words: int = 6, separator: str = "-", capitalize: bool = False) -> str:
    if words < 1:
        raise ValueError("Use at least one word")
    picked = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    return separator.join(picked)


def password_entropy(length: int, alphabet_size: int) -> float:
    return length * math.log2(alphabet_size) if alphabet_size > 1 else 0.0


def passphrase_entropy(words: int) -> float:
    return words * math.log2(len(WORDS))


def estimate_entropy(password: str) -> float:
    """Rough entropy estimate based on the character classes present."""
    size = 0
    if any(c in LOWER for c in password):
        size += len(LOWER)
    if any(c in UPPER for c in password):
        size += len(UPPER)
    if any(c in DIGITS for c in password):
        size += len(DIGITS)
    if any(not c.isalnum() for c in password):
        size += len(SYMBOLS)
    return password_entropy(len(password), size)


def strength_label(bits: float) -> str:
    if bits < 40:
        return "Weak"
    if bits < 60:
        return "Fair"
    if bits < 80:
        return "Strong"
    return "Very strong"
