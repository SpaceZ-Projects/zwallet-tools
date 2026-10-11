"""Native BitcoinZ encodings for stored Sprout and Sapling wallet data."""

from __future__ import annotations

import hashlib


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def base58check(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    checked = data + checksum
    number = int.from_bytes(checked, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    zeroes = len(checked) - len(checked.lstrip(b"\x00"))
    return "1" * zeroes + (encoded or "1")


def _convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bit_count = 0
    result = []
    mask = (1 << to_bits) - 1
    for value in data:
        if value >> from_bits:
            raise ValueError("Input symbol exceeds its bit width.")
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & mask)
    if bit_count:
        result.append((accumulator << (to_bits - bit_count)) & mask)
    return result


def _bech32_polymod(values: list[int]) -> int:
    generators = (
        0x3B6A57B2,
        0x26508E6D,
        0x1EA119FA,
        0x3D4233DD,
        0x2A1462B3,
    )
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def bech32_encode(hrp: str, payload: bytes) -> str:
    if not hrp or any(ord(char) < 33 or ord(char) > 126 for char in hrp):
        raise ValueError("Invalid Bech32 human-readable prefix.")
    hrp = hrp.lower()
    data = _convert_bits(payload, 8, 5)
    expanded_hrp = [ord(char) >> 5 for char in hrp] + [0]
    expanded_hrp += [ord(char) & 31 for char in hrp]
    polymod = _bech32_polymod(expanded_hrp + data + [0] * 6) ^ 1
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(
        BECH32_ALPHABET[value] for value in data + checksum
    )


def sprout_payment_address(serialized: bytes) -> str:
    if len(serialized) != 64:
        raise ValueError("Sprout payment address must be exactly 64 bytes.")
    return base58check(bytes.fromhex("169a"), serialized)


def sapling_payment_address(serialized: bytes) -> str:
    if len(serialized) != 43:
        raise ValueError("Sapling payment address must be exactly 43 bytes.")
    return bech32_encode("zs", serialized)


def sprout_spending_key(serialized: bytes) -> str:
    if len(serialized) != 32 or serialized[0] & 0xF0:
        raise ValueError("Sprout spending key must be a valid 252-bit value.")
    return base58check(bytes.fromhex("ab36"), serialized)


def sapling_extended_spending_key(serialized: bytes) -> str:
    if len(serialized) != 169:
        raise ValueError("Sapling extended spending key must be exactly 169 bytes.")
    return bech32_encode("secret-extended-key-main", serialized)
