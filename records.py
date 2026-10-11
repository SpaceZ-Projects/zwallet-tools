"""BitcoinZ Core wallet record identification and safe field decoding."""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from reader import BDBRecord
from serialization import Reader, SerializationError
from shielded import (
    sapling_extended_spending_key,
    sapling_payment_address,
    sprout_payment_address,
    sprout_spending_key,
)
from sapling import validate_and_derive_sapling


KNOWN_RECORDS = {
    "key", "wkey", "ckey", "mkey", "keymeta", "pool", "tx", "name",
    "purpose", "defaultkey", "version", "minversion", "bestblock",
    "bestblock_nomerkle", "hdchain", "hdseed", "chdseed", "cscript",
    "watchs", "watchmeta", "setting", "flags", "acc", "acentry",
    "orderposnext", "destdata", "activeexternalspk", "activeinternalspk",
    "activeexternalchain", "activeinternalchain", "witnesscachesize",
    "zkey", "czkey", "zkeymeta", "sapzkey", "csapzkey", "sapzkeymeta",
    "sapzaddr", "sproutfvk", "saplingfvk", "sapextfvk", "vkey",
}

P2PKH_PREFIX = bytes((0x1C, 0xB8))
P2SH_PREFIX = bytes((0x1C, 0xBD))
WIF_PREFIX = b"\x80"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check(prefix: bytes, payload: bytes) -> str:
    value = prefix + payload
    checksum = hashlib.sha256(hashlib.sha256(value).digest()).digest()[:4]
    number = int.from_bytes(value + checksum, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    zeros = len(value + checksum) - len((value + checksum).lstrip(b"\0"))
    return "1" * zeros + (encoded or "1")


def _hash160(data: bytes) -> bytes | None:
    try:
        sha = hashlib.sha256(data).digest()
        return hashlib.new("ripemd160", sha).digest()
    except (ValueError, TypeError):
        return None


def _decode_key_name(raw: bytes) -> tuple[str, bytes]:
    reader = Reader(raw)
    try:
        name = reader.string()
    except SerializationError:
        return "unparsed", b""
    return name, raw[reader.offset:]


def _pubkey_metadata(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"public_key_length": len(data), "public_key_valid": False}
    field_prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    curve_valid = False
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        if x < field_prime:
            y_squared = (pow(x, 3, field_prime) + 7) % field_prime
            curve_valid = pow(y_squared, (field_prime - 1) // 2, field_prime) == 1
    elif len(data) == 65 and data[0] == 4:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        curve_valid = (
            x < field_prime and y < field_prime
            and pow(y, 2, field_prime) == (pow(x, 3, field_prime) + 7) % field_prime
        )
    result["public_key_valid"] = curve_valid
    result["public_key_curve"] = "secp256k1" if curve_valid else None
    if curve_valid:
        digest = _hash160(data)
        if digest is None:
            result["address_derivation"] = "unavailable (RIPEMD-160 is not provided by this Python build)"
        else:
            result["address"] = _base58check(P2PKH_PREFIX, digest)
    return result


def _valid_sec1_private_key(der: bytes) -> bool:
    """Validate the DER envelope and scalar range without returning secret bytes."""
    if len(der) < 8 or der[0] != 0x30:
        return False

    def der_length(data: bytes, offset: int) -> tuple[int, int] | None:
        if offset >= len(data):
            return None
        first = data[offset]
        if first < 0x80:
            return first, offset + 1
        width = first & 0x7f
        if width == 0 or width > 4 or offset + 1 + width > len(data):
            return None
        length = int.from_bytes(data[offset + 1:offset + 1 + width], "big")
        if length < 0x80 or (width > 1 and data[offset + 1] == 0):
            return None
        return length, offset + 1 + width

    def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
        if offset + 2 > len(data):
            return None
        tag = data[offset]
        length_info = der_length(data, offset + 1)
        if length_info is None:
            return None
        size, content_start = length_info
        end = content_start + size
        if end > len(data):
            return None
        return tag, data[content_start:end], end

    def children(data: bytes) -> list[tuple[int, bytes]] | None:
        result = []
        offset = 0
        while offset < len(data):
            field = read_tlv(data, offset)
            if field is None:
                return None
            tag, content, offset = field
            result.append((tag, content))
        return result

    sequence_tlv = read_tlv(der, 0)
    if sequence_tlv is None or sequence_tlv[0] != 0x30 or sequence_tlv[2] != len(der):
        return False
    fields = children(sequence_tlv[1])
    if fields is None or len(fields) < 2:
        return False
    if fields[0] != (0x02, b"\x01") or fields[1][0] != 0x04:
        return False
    scalar_bytes = fields[1][1]
    if not 1 <= len(scalar_bytes) <= 32:
        return False
    scalar = int.from_bytes(scalar_bytes, "big")
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if not 1 <= scalar < secp256k1_order:
        return False
    for tag, content in fields[2:]:
        if tag == 0xa0:
            params_tlv = read_tlv(content, 0)
            if params_tlv is None or params_tlv[0] != 0x30 or params_tlv[2] != len(content):
                return False
            if params_tlv[1] == bytes.fromhex("06052b8104000a"):
                continue
            params = children(params_tlv[1])
            if params is None or len(params) != 6:
                return False
            if params[0] != (0x02, b"\x01") or params[1][0] != 0x30:
                return False
            field_id = children(params[1][1])
            if field_id is None or len(field_id) != 2:
                return False
            if field_id[0] != (0x06, bytes.fromhex("2a8648ce3d0101")) or field_id[1][0] != 0x02:
                return False
            prime = int.from_bytes(field_id[1][1].lstrip(b"\x00"), "big")
            if prime != 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F:
                return False
            if params[2][0] != 0x30:
                return False
            curve = children(params[2][1])
            if curve is None or len(curve) not in (2, 3):
                return False
            if curve[0] != (0x04, b"\x00") or curve[1] != (0x04, b"\x07"):
                return False
            if len(curve) == 3 and curve[2][0] != 0x03:
                return False
            if params[3][0] != 0x04 or not _pubkey_metadata(params[3][1])["public_key_valid"]:
                return False
            if params[4][0] != 0x02 or int.from_bytes(params[4][1].lstrip(b"\x00"), "big") != secp256k1_order:
                return False
            if params[5] != (0x02, b"\x01"):
                return False
        elif tag == 0xa1:
            bit_string = read_tlv(content, 0)
            if bit_string is None or bit_string[0] != 0x03 or bit_string[2] != len(content):
                return False
            if not bit_string[1] or bit_string[1][0] != 0:
                return False
            if not _pubkey_metadata(bit_string[1][1:])["public_key_valid"]:
                return False
        else:
            return False
    return True


def _sec1_private_scalar(der: bytes) -> bytes | None:
    """Extract a validated SEC1 scalar, left-padded to the WIF 32-byte form."""
    def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
        if offset + 2 > len(data):
            return None
        tag = data[offset]
        first = data[offset + 1]
        if first < 0x80:
            length, content_start = first, offset + 2
        else:
            width = first & 0x7f
            if width == 0 or width > 4 or offset + 2 + width > len(data):
                return None
            length = int.from_bytes(data[offset + 2:offset + 2 + width], "big")
            content_start = offset + 2 + width
        end = content_start + length
        if end > len(data):
            return None
        return tag, data[content_start:end], end

    sequence = read_tlv(der, 0)
    if sequence is None or sequence[0] != 0x30 or sequence[2] != len(der):
        return None
    version = read_tlv(sequence[1], 0)
    if version is None or version[0] != 0x02 or version[1] != b"\x01":
        return None
    scalar = read_tlv(sequence[1], version[2])
    if scalar is None or scalar[0] != 0x04 or scalar[2] > len(sequence[1]):
        return None
    if not 1 <= len(scalar[1]) <= 32:
        return None
    return scalar[1].rjust(32, b"\x00")


def _public_key_for_scalar(scalar_bytes: bytes, compressed: bool) -> bytes:
    prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    generator = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    scalar = int.from_bytes(scalar_bytes, "big")
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = generator

    def add_points(
        left: tuple[int, int] | None, right: tuple[int, int] | None
    ) -> tuple[int, int] | None:
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        if x1 == x2 and (y1 != y2 or y1 == 0):
            return None
        if left == right:
            slope = (3 * x1 * x1) * pow(2 * y1, -1, prime) % prime
        else:
            slope = (y2 - y1) * pow((x2 - x1) % prime, -1, prime) % prime
        x3 = (slope * slope - x1 - x2) % prime
        y3 = (slope * (x1 - x3) - y1) % prime
        return x3, y3

    while scalar:
        if scalar & 1:
            result = add_points(result, addend)
        addend = add_points(addend, addend)
        scalar >>= 1
    if result is None:
        raise ValueError("Private-key scalar does not produce a public key.")
    x, y = result
    if compressed:
        return bytes((2 | (y & 1),)) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _sapling_xsk_metadata(serialized: bytes) -> dict[str, int]:
    reader = Reader(serialized)
    depth = reader.u8()
    reader.u32()  # Parent full-viewing-key tag.
    child_index = reader.u32()
    reader.take(32)  # Chain code.
    reader.take(96)  # Expanded spending key.
    reader.take(32)  # Diversifier key.
    reader.finish()
    return {"zip32_depth": depth, "zip32_child_index": child_index}


def _script_metadata(script: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"script_length": len(script), "script_hex": script.hex()}
    payload = None
    prefix = None
    if len(script) == 25 and script[:3] == bytes.fromhex("76a914") and script[-2:] == bytes.fromhex("88ac"):
        result["script_type"] = "pubkey_hash"
        payload, prefix = script[3:23], P2PKH_PREFIX
    elif len(script) == 23 and script[:2] == bytes.fromhex("a914") and script[-1:] == b"\x87":
        result["script_type"] = "script_hash"
        payload, prefix = script[2:22], P2SH_PREFIX
    elif len(script) in (35, 67) and script[-1] == 0xac and script[0] == len(script) - 2:
        result["script_type"] = "pubkey"
    elif script[:1] == b"\x6a":
        result["script_type"] = "nulldata"
    else:
        result["script_type"] = "unknown"
    if payload is not None and prefix is not None:
        result["address"] = _base58check(prefix, payload)
    return result


def _decode_transaction(data: bytes) -> dict[str, Any]:
    reader = Reader(data)
    header = reader.u32()
    overwintered = bool(header & 0x80000000)
    version = header & 0x7fffffff if overwintered else header
    version_group = reader.u32() if overwintered else None
    overwinter_group = 0x03C48270
    sapling_group = 0x892F2085
    is_overwinter_v3 = overwintered and version == 3 and version_group == overwinter_group
    is_sapling_v4 = overwintered and version == 4 and version_group == sapling_group
    if overwintered and not (is_overwinter_v3 or is_sapling_v4):
        raise SerializationError(
            f"Unsupported BitcoinZ transaction version/group {version}/{version_group!r}."
        )
    input_count = reader.compact_size()
    if input_count > 100_000:
        raise SerializationError("Transaction input count exceeds safety limit.")
    inputs = []
    for _ in range(input_count):
        txid = reader.take(32)[::-1].hex()
        index = reader.u32()
        script = reader.vector(10_000_000)
        sequence = reader.u32()
        inputs.append({
            "previous_txid": txid,
            "previous_output_index": index,
            "script_sig_length": len(script),
            "sequence": sequence,
        })
    output_count = reader.compact_size()
    if output_count > 100_000:
        raise SerializationError("Transaction output count exceeds safety limit.")
    outputs = []
    for index in range(output_count):
        value = reader.i64()
        script = reader.vector(10_000_000)
        outputs.append({
            "index": index,
            "value_zatoshi": value,
            **_script_metadata(script),
        })
    lock_time = reader.u32()
    expiry_height = reader.u32() if (is_overwinter_v3 or is_sapling_v4) else None
    sapling_spend_count = 0
    sapling_output_count = 0
    if is_sapling_v4:
        value_balance = reader.i64()
        sapling_spend_count = reader.compact_size()
        if sapling_spend_count > 100_000:
            raise SerializationError("Sapling spend count exceeds safety limit.")
        reader.take(sapling_spend_count * 384)
        sapling_output_count = reader.compact_size()
        if sapling_output_count > 100_000:
            raise SerializationError("Sapling output count exceeds safety limit.")
        reader.take(sapling_output_count * 948)
    else:
        value_balance = None

    joinsplit_count = reader.compact_size() if version >= 2 else 0
    if joinsplit_count > 100_000:
        raise SerializationError("JoinSplit count exceeds safety limit.")
    if joinsplit_count:
        reader.take(joinsplit_count * (1698 if version >= 4 else 1802))
        reader.take(32 + 64)  # JoinSplit public key and signature.
    if is_sapling_v4 and (sapling_spend_count or sapling_output_count):
        reader.take(64)  # Sapling binding signature.
    transaction_end = reader.offset
    txid = hashlib.sha256(hashlib.sha256(data[:transaction_end]).digest()).digest()[::-1].hex()
    return {
        "transaction_id": txid,
        "version": version,
        "overwintered": overwintered,
        "version_group_id": f"0x{version_group:08x}" if version_group is not None else None,
        "inputs": inputs,
        "outputs": outputs,
        "lock_time": lock_time,
        "expiry_height": expiry_height,
        "value_balance_zatoshi": value_balance,
        "sapling_spend_count": sapling_spend_count,
        "sapling_output_count": sapling_output_count,
        "joinsplit_count": joinsplit_count,
        "_consumed": transaction_end,
    }


def decode_wallet_record(
    record: BDBRecord,
    *,
    include_private_key: bool = False,
    include_shielded_private_key: bool = False,
    validate_shielded_crypto: bool = False,
) -> dict[str, Any]:
    record_type, suffix = _decode_key_name(record.key)
    decoded: dict[str, Any] = {
        "type": record_type,
        "known_type": record_type in KNOWN_RECORDS,
        "page": record.page,
        "slot": record.slot,
        "key_size": len(record.key),
        "value_size": len(record.value),
        "decode_status": "decoded",
    }
    try:
        value = Reader(record.value)
        key = Reader(suffix)

        if record_type == "zkey":
            address = sprout_payment_address(suffix)
            spending_key = value.take(32)
            value.finish()
            if spending_key[0] & 0xF0:
                raise SerializationError("Sprout spending key has invalid leading bits.")
            decoded.update({
                "shielded_type": "Sprout",
                "shielded_address": address,
                "shielded_addresses": [address],
                "key_material": "Sprout spending key; secret redacted",
                "key_format": "Base58Check Sprout spending key (SK...)",
                "key_validation": (
                    "252-bit storage form validated; spending-key/address "
                    "correspondence is not cryptographically re-derived"
                ),
                "secret_exported": include_shielded_private_key,
            })
            if include_shielded_private_key:
                decoded["shielded_spending_key"] = sprout_spending_key(spending_key)

        elif record_type == "sapzkey":
            if len(suffix) != 32:
                raise SerializationError("Sapling incoming viewing key must be 32 bytes.")
            extended_spending_key = value.take(169)
            value.finish()
            decoded.update({
                "shielded_type": "Sapling",
                "_sapling_ivk": suffix.hex(),
                **_sapling_xsk_metadata(extended_spending_key),
                "key_material": "Sapling extended spending key; secret redacted",
                "key_format": "Bech32 Sapling extended spending key",
                "key_validation": (
                    "not requested; enable --validate-shielded"
                    if not validate_shielded_crypto
                    else "validation failed"
                ),
                "secret_exported": include_shielded_private_key,
            })
            if validate_shielded_crypto:
                crypto_result = validate_and_derive_sapling(
                    extended_spending_key,
                    suffix,
                )
                decoded.update({
                    "key_validation": crypto_result["validation"],
                    "cryptographic_validation": "passed",
                    "derived_shielded_address": crypto_result["address"],
                    "derived_diversifier_index": crypto_result["diversifier_index"],
                    "shielded_address": crypto_result["address"],
                    "shielded_addresses": [crypto_result["address"]],
                })
            if include_shielded_private_key:
                decoded["shielded_spending_key"] = sapling_extended_spending_key(
                    extended_spending_key
                )

        elif record_type == "czkey":
            address = sprout_payment_address(suffix)
            value.take(32)  # Sprout receiving key, not a spending key.
            encrypted_secret = value.vector(1_000_000)
            value.finish()
            if not encrypted_secret or len(encrypted_secret) % 16:
                raise SerializationError("Encrypted Sprout key is not AES block-aligned.")
            decoded.update({
                "shielded_type": "Sprout",
                "shielded_address": address,
                "shielded_addresses": [address],
                "key_material": "encrypted Sprout spending key",
                "encrypted_secret_length": len(encrypted_secret),
                "secret_exported": False,
            })

        elif record_type == "csapzkey":
            if len(suffix) != 32:
                raise SerializationError("Sapling incoming viewing key must be 32 bytes.")
            value.take(169)  # Sapling extended full viewing key.
            encrypted_secret = value.vector(1_000_000)
            value.finish()
            if not encrypted_secret or len(encrypted_secret) % 16:
                raise SerializationError("Encrypted Sapling key is not AES block-aligned.")
            decoded.update({
                "shielded_type": "Sapling",
                "_sapling_ivk": suffix.hex(),
                "key_material": "encrypted Sapling extended spending key",
                "encrypted_secret_length": len(encrypted_secret),
                "secret_exported": False,
            })

        elif record_type == "sapzaddr":
            address = sapling_payment_address(suffix)
            incoming_viewing_key = value.take(32)
            value.finish()
            decoded.update({
                "shielded_type": "Sapling",
                "shielded_address": address,
                "shielded_addresses": [address],
                "_sapling_ivk": incoming_viewing_key.hex(),
            })

        elif record_type in {"zkeymeta", "sapzkeymeta"}:
            expected_key_length = 64 if record_type == "zkeymeta" else 32
            if len(suffix) != expected_key_length:
                raise SerializationError("Shielded key metadata has an invalid database key.")
            version = value.i32()
            created = value.i64()
            decoded.update({
                "shielded_type": "Sprout" if record_type == "zkeymeta" else "Sapling",
                "metadata_version": version,
                "creation_time_unix": created,
            })
            if version >= 10:
                decoded["hd_keypath"] = value.string()
                decoded["seed_fingerprint"] = value.take(32)[::-1].hex()
            value.finish()

        elif record_type in {"key", "ckey", "wkey"}:
            pubkey = key.vector(128)
            decoded.update(_pubkey_metadata(pubkey))
            if not decoded["public_key_valid"]:
                raise SerializationError("Serialized public key is not a valid secp256k1 point.")
            decoded["key_material"] = (
                "encrypted private key" if record_type == "ckey"
                else "private-key-bearing record; secret bytes redacted"
            )
            if record_type == "key":
                private_der = value.vector(4096)
                expected_hash = value.take(32)
                value.finish()
                actual_hash = hashlib.sha256(
                    hashlib.sha256(pubkey + private_der).digest()
                ).digest()
                decoded["private_key_encoding"] = "DER"
                decoded["private_key_der_valid"] = _valid_sec1_private_key(private_der)
                decoded["key_checksum_valid"] = expected_hash == actual_hash
                if not decoded["private_key_der_valid"] or not decoded["key_checksum_valid"]:
                    raise SerializationError("Private-key DER or record checksum validation failed.")
                decoded["secret_exported"] = include_private_key
                if include_private_key:
                    scalar = _sec1_private_scalar(private_der)
                    if scalar is None:
                        raise SerializationError("Validated private-key scalar could not be extracted.")
                    if _public_key_for_scalar(scalar, len(pubkey) == 33) != pubkey:
                        raise SerializationError(
                            "Private key does not match the serialized public key."
                        )
                    wif_payload = scalar + (b"\x01" if len(pubkey) == 33 else b"")
                    decoded["private_key_wif"] = _base58check(WIF_PREFIX, wif_payload)
            elif record_type == "ckey":
                encrypted_secret = value.vector(1_000_000)
                value.finish()
                if not encrypted_secret or len(encrypted_secret) % 16:
                    raise SerializationError("Encrypted private-key data is not AES block-aligned.")
                decoded["encrypted_secret_length"] = len(encrypted_secret)
                decoded["secret_exported"] = False
            elif record_type == "wkey":
                decoded["format"] = "legacy wallet key; version-specific serialization"
                decoded["decode_status"] = "partially_decoded"

        elif record_type == "mkey":
            decoded["master_key_id"] = key.u32()
            key.finish()
            encrypted_master = value.vector(1_000_000)
            salt = value.vector(1024)
            method = value.u32()
            iterations = value.u32()
            other = value.vector(1024)
            value.finish()
            if not encrypted_master or len(encrypted_master) % 16 or not salt or iterations == 0:
                raise SerializationError("Master-key encryption parameters are malformed.")
            decoded.update({
                "encrypted_master_key_length": len(encrypted_master),
                "salt_length": len(salt),
                "derivation_method": method,
                "derivation_iterations": iterations,
                "other_derivation_parameters_length": len(other),
                "password_decryption": "not implemented; no password attempted",
            })
            if method != 0:
                decoded["decode_status"] = "unsupported"
                decoded["unsupported_derivation_method"] = method

        elif record_type == "keymeta":
            pubkey = key.vector(128)
            key.finish()
            version = value.i32()
            created = value.i64()
            decoded.update({
                "metadata_version": version,
                "creation_time_unix": created,
                **_pubkey_metadata(pubkey),
            })
            if not decoded["public_key_valid"]:
                raise SerializationError("Key metadata references an invalid secp256k1 public key.")
            if version >= 10:
                decoded["hd_keypath"] = value.string()
                decoded["seed_fingerprint"] = value.take(32)[::-1].hex()
            value.finish()

        elif record_type == "pool":
            decoded["pool_index"] = key.i64()
            key.finish()
            decoded["serialization_version"] = value.i32()
            decoded["creation_time_unix"] = value.i64()
            pubkey = value.vector(128)
            value.finish()
            decoded.update(_pubkey_metadata(pubkey))
            if not decoded["public_key_valid"]:
                raise SerializationError("Keypool contains an invalid secp256k1 public key.")

        elif record_type in {"name", "purpose"}:
            address = key.string()
            key.finish()
            decoded["address"] = address
            decoded["label" if record_type == "name" else "purpose"] = value.string()
            value.finish()

        elif record_type == "cscript":
            script_hash = key.take(20)[::-1].hex()
            key.finish()
            script = value.vector(10_000_000)
            value.finish()
            decoded.update({"script_hash": script_hash, **_script_metadata(script)})

        elif record_type in {"watchs", "watchmeta"}:
            watch_script = key.vector(10_000_000)
            key.finish()
            decoded["script_length"] = len(watch_script)
            if record_type == "watchs":
                marker = value.u8()
                value.finish()
                decoded["watch_only_marker"] = marker
            else:
                metadata_version = value.i32()
                created = value.i64()
                decoded.update({
                    "metadata_version": metadata_version,
                    "creation_time_unix": created,
                })
                if metadata_version >= 10:
                    decoded["hd_keypath"] = value.string()
                    decoded["seed_fingerprint"] = value.take(32)[::-1].hex()
                value.finish()

        elif record_type in {"version", "minversion", "orderposnext", "flags", "witnesscachesize"}:
            if len(record.value) == 4:
                decoded["value"] = value.i32()
            elif len(record.value) == 8:
                decoded["value"] = value.i64()
            else:
                raise SerializationError("Numeric record has an unexpected serialized width.")
            value.finish()

        elif record_type == "defaultkey":
            pubkey = value.vector(128)
            value.finish()
            decoded.update(_pubkey_metadata(pubkey))
            if not decoded["public_key_valid"]:
                raise SerializationError("Default key is not a valid secp256k1 public key.")

        elif record_type in {"hdchain", "hdseed"}:
            if record_type == "hdchain":
                key.finish()
                decoded["chain_version"] = value.i32()
                decoded["seed_fingerprint"] = value.take(32)[::-1].hex()
                decoded["creation_time_unix"] = value.i64()
                decoded["sapling_account_counter"] = value.u32()
            else:
                fingerprint = key.take(32)[::-1].hex()
                key.finish()
                seed = value.vector(1024)
                if not seed:
                    raise SerializationError("HD seed record contains an empty seed.")
                value.finish()
                decoded["seed_material"] = "present; redacted"
                decoded["seed_fingerprint"] = fingerprint
                decoded["seed_length"] = len(seed)
            value.finish()

        elif record_type in {"bestblock", "bestblock_nomerkle"}:
            version = value.i32()
            hashes_count = value.compact_size()
            if hashes_count > 1_000_000:
                raise SerializationError("Block locator hash count exceeds safety limit.")
            hashes = [value.take(32)[::-1].hex() for _ in range(hashes_count)]
            value.finish()
            decoded.update({
                "locator_version": version,
                "block_hash_count": hashes_count,
                "last_block_hash": hashes[-1] if hashes else None,
            })

        elif record_type == "tx":
            tx_key = key.take(32)[::-1].hex()
            key.finish()
            tx = _decode_transaction(record.value)
            consumed = tx.pop("_consumed")
            decoded["key_transaction_id"] = tx_key
            decoded.update(tx)
            metadata = Reader(record.value[consumed:])
            if len(record.value) - consumed < 32:
                raise SerializationError("CWalletTx block association is truncated.")
            block_hash_raw = metadata.take(32)
            merkle_count = metadata.compact_size()
            if merkle_count > 1_000_000:
                raise SerializationError("Merkle branch count exceeds safety limit.")
            for _ in range(merkle_count):
                metadata.take(32)
            block_index = metadata.i32()
            unused_transactions = metadata.compact_size()
            if unused_transactions:
                decoded["decode_status"] = "partially_decoded"
                decoded["unsupported_unused_transactions"] = unused_transactions
            decoded.update({
                "block_hash": block_hash_raw[::-1].hex() if any(block_hash_raw) else None,
                "block_index": block_index,
                "merkle_branch_hashes": merkle_count,
            })
            if unused_transactions:
                decoded["wallet_metadata"] = "legacy embedded transactions are unsupported"
            else:
                map_count = metadata.compact_size()
                if map_count > 100_000:
                    raise SerializationError("Wallet transaction metadata map exceeds safety limit.")
                map_value = {}
                for _ in range(map_count):
                    map_value[metadata.string()] = metadata.string()
                decoded["wallet_map_keys"] = sorted(map_value)
                decoded["wallet_map_values_redacted"] = True
                # The next two maps contain Sprout/Sapling note witnesses.
                # Their nested tree serializers are not inferred from byte scanning.
                sprout_note_count = metadata.compact_size()
                if sprout_note_count:
                    decoded["decode_status"] = "partially_decoded"
                    decoded["sprout_note_metadata_count"] = sprout_note_count
                    decoded["wallet_metadata"] = "shielded note witness map is unsupported"
                else:
                    order_count = metadata.compact_size()
                    if order_count > 100_000:
                        raise SerializationError("Transaction order-form count exceeds safety limit.")
                    for _ in range(order_count):
                        metadata.string()
                        metadata.string()
                    received_is_tx_time = metadata.u32()
                    received_time = metadata.u32()
                    from_me = metadata.u8()
                    spent = metadata.u8()
                    decoded.update({
                        "order_form_count": order_count,
                        "order_form_values_redacted": True,
                        "time_received_is_tx_time": received_is_tx_time,
                        "time_received_unix": received_time,
                        "from_wallet": bool(from_me),
                        "spent_flag": bool(spent),
                    })
                    sapling_note_count = metadata.compact_size() if tx["overwintered"] and tx["version"] >= 4 else 0
                    if sapling_note_count:
                        decoded["decode_status"] = "partially_decoded"
                        decoded["sapling_note_metadata_count"] = sapling_note_count
                        decoded["wallet_metadata"] = "Sapling note witness map is unsupported"
                    elif metadata.offset < len(metadata.data):
                        decoded["decode_status"] = "partially_decoded"
                        decoded["wallet_metadata_bytes"] = len(metadata.data) - metadata.offset
                        decoded["wallet_metadata"] = "unparsed trailing wallet metadata"
                    else:
                        metadata.finish()
            if tx_key != tx["transaction_id"]:
                decoded["decode_status"] = "malformed"
                decoded["error"] = "Serialized transaction ID does not match its database key."

        elif record_type in {"setting", "flags"}:
            decoded["format"] = "versioned or type-tagged setting; raw value redacted"
            decoded["decode_status"] = "partially_decoded"

        elif record_type in {"chdseed", "zkeymeta", "sapzkeymeta", "sapzaddr", "sproutfvk", "saplingfvk", "acc", "acentry", "destdata"}:
            decoded["format"] = "BitcoinZ-specific or legacy record; exact serializer unsupported"
            decoded["decode_status"] = "unsupported"

        else:
            decoded["decode_status"] = "unsupported" if decoded["known_type"] else "unknown_record_type"
            decoded["format"] = "record bytes retained only for in-memory parsing; not exported"

    except (SerializationError, struct.error, IndexError, ValueError) as exc:
        decoded["decode_status"] = "malformed"
        decoded["error"] = str(exc)
    return decoded


def associate_shielded_addresses(records: list[dict[str, Any]]) -> None:
    addresses_by_ivk: dict[str, list[str]] = {}
    for item in records:
        ivk = item.get("_sapling_ivk")
        address = item.get("shielded_address")
        if item.get("type") == "sapzaddr" and isinstance(ivk, str) and isinstance(address, str):
            addresses_by_ivk.setdefault(ivk, []).append(address)

    for item in records:
        ivk = item.pop("_sapling_ivk", None)
        if item.get("type") not in {"sapzkey", "csapzkey"} or not isinstance(ivk, str):
            continue
        stored_addresses = sorted(set(addresses_by_ivk.get(ivk, [])))
        item["stored_shielded_addresses"] = stored_addresses
        addresses = sorted(set(
            stored_addresses
            + [
                address
                for address in item.get("shielded_addresses", [])
                if isinstance(address, str)
            ]
        ))
        if addresses:
            item["shielded_addresses"] = addresses
            if not item.get("derived_shielded_address"):
                item["shielded_address"] = addresses[0] if len(addresses) == 1 else None
