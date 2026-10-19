import pytest

from pwmanager.generator import (
    DIGITS,
    LOWER,
    SYMBOLS,
    UPPER,
    estimate_entropy,
    generate_passphrase,
    generate_password,
    passphrase_entropy,
)
from pwmanager.wordlist import WORDS


@pytest.mark.parametrize("length", [4, 12, 64])
def test_length_and_all_classes(length):
    for _ in range(50):
        pw = generate_password(length)
        assert len(pw) == length
        for cls in (LOWER, UPPER, DIGITS, SYMBOLS):
            assert any(c in cls for c in pw)


def test_restricted_classes():
    pw = generate_password(30, lower=False, upper=False, symbols=False)
    assert set(pw) <= set(DIGITS)


def test_avoid_ambiguous():
    for _ in range(50):
        assert not set(generate_password(40, avoid_ambiguous=True)) & set("Il1O0o")


def test_invalid_options():
    with pytest.raises(ValueError):
        generate_password(10, lower=False, upper=False, digits=False, symbols=False)
    with pytest.raises(ValueError):
        generate_password(3)


def test_uniqueness():
    assert len({generate_password(16) for _ in range(200)}) == 200


def test_passphrase():
    phrase = generate_passphrase(5, separator=" ")
    words = phrase.split(" ")
    assert len(words) == 5
    assert all(w in WORDS for w in words)
    assert len(set(WORDS)) == len(WORDS) == 4096
    assert passphrase_entropy(6) == pytest.approx(72)


def test_entropy_estimate():
    assert estimate_entropy("") == 0
    assert estimate_entropy("aaaa") < estimate_entropy("aA1!")
