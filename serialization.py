"""Bitcoin/BitcoinZ serialization primitives with strict bounds checks."""

from __future__ import annotations

import struct


class SerializationError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise SerializationError("Serialized field is truncated.")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def compact_size(self) -> int:
        first = self.take(1)[0]
        if first < 253:
            return first
        width = {253: 2, 254: 4, 255: 8}[first]
        value = int.from_bytes(self.take(width), "little")
        minimum = {2: 253, 4: 0x10000, 8: 0x100000000}[width]
        if value < minimum:
            raise SerializationError("CompactSize integer is not canonically encoded.")
        return value

    def varint(self) -> int:
        start = self.offset
        value = 0
        for _ in range(10):
            byte = self.take(1)[0]
            if value > (0xFFFFFFFFFFFFFFFF >> 7):
                raise SerializationError("Variable-length integer overflows uint64.")
            value = (value << 7) | (byte & 0x7f)
            if byte & 0x80:
                if value == 0xFFFFFFFFFFFFFFFF:
                    raise SerializationError("Variable-length integer overflows uint64.")
                value += 1
            else:
                encoded = self.data[start:self.offset]
                if serialize_varint(value) != encoded:
                    raise SerializationError("Variable-length integer is not canonical.")
                return value
        raise SerializationError("Variable-length integer exceeds 10 bytes.")

    def vector(self, max_size: int = 64 * 1024 * 1024) -> bytes:
        length = self.compact_size()
        if length > max_size:
            raise SerializationError(f"Serialized vector length {length} exceeds limit.")
        return self.take(length)

    def string(self) -> str:
        raw = self.vector(1_000_000)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SerializationError("Serialized string is not valid UTF-8.") from exc

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise SerializationError(
                f"{len(self.data) - self.offset} unexplained trailing serialized bytes."
            )


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize cannot encode negative values.")
    if value < 253:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def serialize_varint(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Variable-length integer is outside uint64 range.")
    encoded = bytearray()
    while True:
        encoded.append((value & 0x7f) | (0x80 if encoded else 0))
        if value <= 0x7f:
            break
        value = (value >> 7) - 1
    encoded.reverse()
    return bytes(encoded)


def serialize_vector(data: bytes) -> bytes:
    return compact_size(len(data)) + data
