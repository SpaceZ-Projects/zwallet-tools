"""Pure-Python Sapling ZIP32 key validation and default-address derivation.

This is an offline decoder feature, not a constant-time signing implementation.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from shielded import bech32_encode


_FIELD = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
_SCALAR = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
_EDWARDS_D = (-10240 * pow(10241, -1, _FIELD)) % _FIELD
_IDENTITY = (0, 1, 1, 0)
_GROUP_HASH_PREFIX = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"
_GH_Q, _GH_S = _FIELD - 1, 0
while _GH_Q % 2 == 0:
    _GH_Q //= 2
    _GH_S += 1
_NONRESIDUE = 2
while pow(_NONRESIDUE, (_FIELD - 1) // 2, _FIELD) != _FIELD - 1:
    _NONRESIDUE += 1


def _sqrt(value: int) -> int | None:
    value %= _FIELD
    if value == 0:
        return 0
    if pow(value, (_FIELD - 1) // 2, _FIELD) != 1:
        return None
    c = pow(_NONRESIDUE, _GH_Q, _FIELD)
    x = pow(value, (_GH_Q + 1) // 2, _FIELD)
    t = pow(value, _GH_Q, _FIELD)
    m = _GH_S
    while t != 1:
        i = 1
        t2 = t * t % _FIELD
        while t2 != 1:
            t2 = t2 * t2 % _FIELD
            i += 1
            if i >= m:
                return None
        b = pow(c, 1 << (m - i - 1), _FIELD)
        x = x * b % _FIELD
        t = t * b * b % _FIELD
        c = b * b % _FIELD
        m = i
    return x


def _decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    raw = bytearray(encoded)
    sign = raw[31] >> 7
    raw[31] &= 0x7F
    v = int.from_bytes(raw, "little")
    if v >= _FIELD:
        return None
    v2 = v * v % _FIELD
    denominator = (1 + _EDWARDS_D * v2) % _FIELD
    u2 = (v2 - 1) * pow(denominator, -1, _FIELD) % _FIELD
    u = _sqrt(u2)
    if u is None or (u == 0 and sign):
        return None
    if (u & 1) != sign:
        u = _FIELD - u
    return u, v, 1, u * v % _FIELD


def _add(
    p: tuple[int, int, int, int],
    q: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _FIELD
    b = (y1 + x1) * (y2 + x2) % _FIELD
    c = 2 * _EDWARDS_D * t1 * t2 % _FIELD
    d = 2 * z1 * z2 % _FIELD
    e, f, g, h = (b - a) % _FIELD, (d - c) % _FIELD, (d + c) % _FIELD, (b + a) % _FIELD
    return e * f % _FIELD, g * h % _FIELD, f * g % _FIELD, e * h % _FIELD


def _multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse_z = pow(z, -1, _FIELD)
    u = x * inverse_z % _FIELD
    v = y * inverse_z % _FIELD
    encoded = bytearray(v.to_bytes(32, "little"))
    encoded[31] |= (u & 1) << 7
    return bytes(encoded)


@lru_cache(maxsize=8)
def _group_hash(tag: bytes, personalization: bytes) -> tuple[int, int, int, int] | None:
    digest = hashlib.blake2s(
        _GROUP_HASH_PREFIX + tag,
        digest_size=32,
        person=personalization,
    ).digest()
    point = _decode_point(digest)
    if point is None:
        return None
    point = _multiply(point, 8)
    if point == _IDENTITY:
        return None
    return point


@lru_cache(maxsize=1)
def _generators() -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
    def fixed_generator(personalization: bytes) -> tuple[int, int, int, int]:
        for counter in range(256):
            point = _group_hash(bytes((counter,)), personalization)
            if point is not None:
                return point
        raise ValueError("Sapling generator derivation failed.")

    spend = fixed_generator(b"Zcash_G_")
    proof = fixed_generator(b"Zcash_H_")
    return spend, proof


def _ivk(ak: bytes, nk: bytes) -> int:
    digest = hashlib.blake2s(
        ak + nk,
        digest_size=32,
        person=b"Zcashivk",
    ).digest()
    return int.from_bytes(digest[:-1] + bytes((digest[-1] & 0x07,)), "little")


def _aes_gf_mul(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def _aes_sbox(value: int) -> int:
    inverse = 0
    if value:
        inverse = 1
        base = value
        exponent = 254
        while exponent:
            if exponent & 1:
                inverse = _aes_gf_mul(inverse, base)
            base = _aes_gf_mul(base, base)
            exponent >>= 1
    rotate = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF
    return inverse ^ rotate(inverse, 1) ^ rotate(inverse, 2) ^ rotate(inverse, 3) ^ rotate(inverse, 4) ^ 0x63


_AES_SBOX = tuple(_aes_sbox(value) for value in range(256))


def _aes256_round_keys(key: bytes) -> tuple[bytes, ...]:
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    rcon = 1
    for index in range(8, 60):
        temp = words[index - 1].copy()
        if index % 8 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = _aes_gf_mul(rcon, 2)
        elif index % 8 == 4:
            temp = [_AES_SBOX[b] for b in temp]
        words.append([words[index - 8][i] ^ temp[i] for i in range(4)])
    return tuple(
        bytes(sum(words[start:start + 4], []))
        for start in range(0, 60, 4)
    )


def _aes256_encrypt(block: bytes, round_keys: tuple[bytes, ...]) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes.")
    state = list(block)
    state = [value ^ round_keys[0][i] for i, value in enumerate(state)]
    for round_number in range(1, 15):
        state = [_AES_SBOX[value] for value in state]
        shifted = state.copy()
        for row in range(4):
            values = [state[4 * column + row] for column in range(4)]
            values = values[row:] + values[:row]
            for column in range(4):
                shifted[4 * column + row] = values[column]
        state = shifted
        if round_number != 14:
            for column in range(4):
                start = 4 * column
                a0, a1, a2, a3 = state[start:start + 4]
                state[start:start + 4] = [
                    _aes_gf_mul(a0, 2) ^ _aes_gf_mul(a1, 3) ^ a2 ^ a3,
                    a0 ^ _aes_gf_mul(a1, 2) ^ _aes_gf_mul(a2, 3) ^ a3,
                    a0 ^ a1 ^ _aes_gf_mul(a2, 2) ^ _aes_gf_mul(a3, 3),
                    _aes_gf_mul(a0, 3) ^ a1 ^ a2 ^ _aes_gf_mul(a3, 2),
                ]
        state = [value ^ round_keys[round_number][i] for i, value in enumerate(state)]
    return bytes(state)


def _ff1_diversifier(dk: bytes, index: int) -> bytes:
    """ZIP 32 FF1-AES256 diversification for an 88-bit little-endian index."""
    if len(dk) != 32 or not 0 <= index < 1 << 88:
        raise ValueError("Invalid Sapling diversifier key or index.")
    n, u, v, b, d = 88, 44, 44, 6, 12
    p = (
        b"\x01\x02\x01"
        + (2).to_bytes(3, "big")
        + bytes((10, u))
        + n.to_bytes(4, "big")
        + bytes(4)
    )
    round_keys = _aes256_round_keys(dk)
    bits = f"{index:0{n}b}"[::-1]
    a, block_b = bits[:u], bits[u:]

    for round_number in range(10):
        q = bytes(9) + bytes((round_number,)) + int(block_b, 2).to_bytes(b, "big")
        message = p + q
        state = bytes(16)
        for offset in range(0, len(message), 16):
            state = _aes256_encrypt(
                bytes(left ^ right for left, right in zip(state, message[offset:offset + 16])),
                round_keys,
            )
        y = int.from_bytes(state[:d], "big")
        c = (int(a, 2) + y) % (1 << u)
        a, block_b = block_b, f"{c:0{u}b}"

    return int((a + block_b)[::-1], 2).to_bytes(11, "little")


def _derive_internal_ivk(
    ak: bytes,
    nk_point: tuple[int, int, int, int],
    ovk: bytes,
    dk: bytes,
) -> int:
    fvk = ak + _encode_point(nk_point) + ovk
    seed = hashlib.blake2b(
        fvk + dk,
        digest_size=32,
        person=b"Zcash_SaplingInt",
    ).digest()
    nsk_bytes = hashlib.blake2b(
        seed + b"\x17",
        digest_size=64,
        person=b"Zcash_ExpandSeed",
    ).digest()
    internal_nsk = int.from_bytes(nsk_bytes, "little") % _SCALAR
    _, proof_generator = _generators()
    internal_nk = _add(nk_point, _multiply(proof_generator, internal_nsk))
    return _ivk(ak, _encode_point(internal_nk))


def validate_and_derive_sapling(
    serialized: bytes,
    expected_ivk: bytes,
    *,
    search_limit: int = 4096,
) -> dict[str, str | int]:
    """Validate an extended Sapling spending key and derive its default receiver."""
    if len(serialized) != 169:
        raise ValueError("Sapling extended spending key must be exactly 169 bytes.")
    if len(expected_ivk) != 32:
        raise ValueError("Sapling wallet incoming viewing key must be 32 bytes.")

    depth = serialized[0]
    parent_tag = serialized[1:5]
    child_index = int.from_bytes(serialized[5:9], "little")
    if depth == 0 and (child_index != 0 or parent_tag != bytes(4)):
        raise ValueError("Sapling master-key metadata is inconsistent.")

    ask_bytes, nsk_bytes, ovk, dk = (
        serialized[41:73],
        serialized[73:105],
        serialized[105:137],
        serialized[137:169],
    )
    ask = int.from_bytes(ask_bytes, "little")
    nsk = int.from_bytes(nsk_bytes, "little")
    if not 0 < ask < _SCALAR or not 0 <= nsk < _SCALAR:
        raise ValueError("Sapling expanded spending-key scalar encoding is invalid.")

    spend_generator, proof_generator = _generators()
    ak = _encode_point(_multiply(spend_generator, ask))
    nk_point = _multiply(proof_generator, nsk)
    derived_ivk = _ivk(ak, _encode_point(nk_point))
    if derived_ivk == 0 or derived_ivk >= 1 << 251:
        raise ValueError("Sapling extended spending key derives an invalid incoming viewing key.")
    if derived_ivk.to_bytes(32, "little") != expected_ivk:
        raise ValueError("Sapling spending key does not match its wallet incoming viewing key.")

    internal_ivk = _derive_internal_ivk(ak, nk_point, ovk, dk)
    if internal_ivk == 0 or internal_ivk >= 1 << 251:
        raise ValueError("Sapling extended spending key derives an invalid internal viewing key.")

    for diversifier_index in range(search_limit):
        diversifier = _ff1_diversifier(dk, diversifier_index)
        gd = _group_hash(diversifier, b"Zcash_gd")
        if gd is None:
            continue
        pk_d = _encode_point(_multiply(gd, derived_ivk))
        if pk_d == _encode_point(_IDENTITY):
            continue
        address = bech32_encode("zs", diversifier + pk_d)
        return {
            "address": address,
            "diversifier_index": diversifier_index,
            "validation": "Sapling ZIP32 scalars, viewing keys, and wallet IVK validated",
        }
    raise ValueError("No valid Sapling default diversifier found within the search limit.")
