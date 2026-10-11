"""Read-only Berkeley DB B-tree reader for BitcoinZ wallet databases."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import struct


BDB_MAGIC = 0x00053162
PAGE_INVALID = 0
PAGE_INTERNAL_BTREE = 3
PAGE_LEAF_BTREE = 5
PAGE_OVERFLOW = 7
PAGE_BTREE_META = 9
PAGE_DUPLICATE_LEAF = 12
B_KEYDATA = 1
B_DUPLICATE = 2
B_OVERFLOW = 3
B_DELETE = 0x80
MAX_PAGE_SIZE = 65536


class BerkeleyDBError(ValueError):
    """Invalid or unsupported Berkeley DB structure."""


@dataclass(frozen=True)
class BDBRecord:
    key: bytes
    value: bytes
    page: int
    slot: int
    duplicate: int = 0


class BerkeleyDBReader:
    """Extracts records from the `main` named B-tree without opening for write."""

    def __init__(self, filename: str | Path):
        self.path = Path(filename)
        if not self.path.is_file():
            raise FileNotFoundError(f"Wallet file not found: {self.path}")
        with self.path.open("rb") as wallet:
            self.data = wallet.read()
        self.file_size = len(self.data)
        self.endian = "<"
        self.page_size = 0
        self.version = 0
        self.page_overhead = 26
        self.root_page = 0
        self.catalog_page = 0
        self.records: list[BDBRecord] = []
        self.page_types: Counter[str] = Counter()
        self.errors: list[dict[str, object]] = []
        self.warnings: list[str] = []
        self.pages_visited: set[int] = set()
        self.overflow_pages: set[int] = set()
        self.deleted_items = 0

    def _u16(self, data: bytes, offset: int) -> int:
        return struct.unpack_from(self.endian + "H", data, offset)[0]

    def _u32(self, data: bytes, offset: int) -> int:
        return struct.unpack_from(self.endian + "I", data, offset)[0]

    def inspect_header(self) -> dict[str, object]:
        if self.file_size < 512:
            raise BerkeleyDBError("File is too small to contain a BDB metadata page.")

        candidates = []
        for endian in ("<", ">"):
            magic = struct.unpack_from(endian + "I", self.data, 12)[0]
            version = struct.unpack_from(endian + "I", self.data, 16)[0]
            page_size = struct.unpack_from(endian + "I", self.data, 20)[0]
            if (
                magic == BDB_MAGIC
                and 512 <= page_size <= MAX_PAGE_SIZE
                and page_size & (page_size - 1) == 0
                and version > 0
            ):
                candidates.append((endian, version, page_size))
        if len(candidates) != 1:
            raise BerkeleyDBError(
                "Unable to uniquely identify Berkeley DB magic, version, "
                "byte order, and power-of-two page size."
            )

        self.endian, self.version, self.page_size = candidates[0]
        if self.data[24] != 0:
            raise BerkeleyDBError(
                "Berkeley DB page-level encryption is unsupported; no pages were decoded."
            )
        self.page_overhead = 32 if (self.data[26] & 0x01) else 26
        if self.file_size < self.page_size:
            raise BerkeleyDBError("File ends before the first complete BDB page.")
        trailing = self.file_size % self.page_size
        if trailing:
            self.errors.append({
                "kind": "incomplete_page",
                "message": f"{trailing} trailing bytes do not form a complete page.",
            })

        return {
            "file": self.path.name,
            "size_bytes": self.file_size,
            "bdb_magic": f"0x{BDB_MAGIC:08x}",
            "bdb_version": self.version,
            "byte_order": "little" if self.endian == "<" else "big",
            "page_size": self.page_size,
            "page_checksums_enabled": bool(self.data[26] & 0x01),
            "page_checksums_verified": False,
            "complete_pages": self.file_size // self.page_size,
            "trailing_bytes": trailing,
            "read_only": True,
        }

    def _page(self, number: int) -> bytes:
        if number < 0 or number >= self.file_size // self.page_size:
            raise BerkeleyDBError(f"Page reference {number} is outside the file.")
        start = number * self.page_size
        page = self.data[start:start + self.page_size]
        if len(page) != self.page_size:
            raise BerkeleyDBError(f"Page {number} is incomplete.")
        stored_pgno = self._u32(page, 8)
        if stored_pgno != number:
            raise BerkeleyDBError(
                f"Page {number} contains page number {stored_pgno}."
            )
        return page

    def _page_type(self, page: bytes) -> int:
        return page[25]

    def _page_offsets(self, page: bytes, page_number: int) -> list[int]:
        count = self._u16(page, 20)
        index_start = self.page_overhead
        index_end = index_start + count * 2
        high_free = self._u16(page, 22)
        if count > (self.page_size - index_start) // 2:
            raise BerkeleyDBError(f"Page {page_number} has an impossible item count.")
        if high_free and (high_free < index_end or high_free > self.page_size):
            raise BerkeleyDBError(f"Page {page_number} has an invalid free-space offset.")
        offsets = [
            self._u16(page, index_start + 2 * i)
            for i in range(count)
        ]
        if any(offset < index_end or offset >= self.page_size for offset in offsets):
            raise BerkeleyDBError(f"Page {page_number} has an item outside its bounds.")
        return offsets

    def _item(self, page: bytes, offset: int, page_number: int) -> tuple[int, bytes, int, int]:
        if offset + 3 > self.page_size:
            raise BerkeleyDBError(f"Page {page_number} item header is truncated.")
        length = self._u16(page, offset)
        raw_type = page[offset + 2]
        deleted = bool(raw_type & B_DELETE)
        item_type = raw_type & ~B_DELETE
        if item_type == B_KEYDATA:
            end = offset + 3 + length
            if end > self.page_size:
                raise BerkeleyDBError(f"Page {page_number} key/data item exceeds page bounds.")
            return item_type, page[offset + 3:end], 0, int(deleted)
        if item_type in (B_DUPLICATE, B_OVERFLOW):
            if offset + 12 > self.page_size:
                raise BerkeleyDBError(f"Page {page_number} overflow reference is truncated.")
            referenced_page = self._u32(page, offset + 4)
            total_length = self._u32(page, offset + 8)
            return item_type, b"", referenced_page, int(deleted) << 31 | total_length
        raise BerkeleyDBError(
            f"Page {page_number} contains unsupported B-tree item type {item_type}."
        )

    def _overflow(self, first_page: int, expected_length: int) -> bytes:
        if expected_length > self.file_size:
            raise BerkeleyDBError(
                f"Overflow record length {expected_length} exceeds the file size."
            )
        result = bytearray()
        current = first_page
        chain: set[int] = set()
        while current:
            if current in chain:
                raise BerkeleyDBError(f"Overflow chain loops at page {current}.")
            chain.add(current)
            self.overflow_pages.add(current)
            page = self._page(current)
            if self._page_type(page) != PAGE_OVERFLOW:
                raise BerkeleyDBError(f"Overflow reference points to non-overflow page {current}.")
            piece_length = self._u16(page, 22)
            start = self.page_overhead
            if start + piece_length > self.page_size:
                raise BerkeleyDBError(f"Overflow page {current} length exceeds page bounds.")
            result.extend(page[start:start + piece_length])
            if len(result) > expected_length:
                raise BerkeleyDBError(f"Overflow chain is longer than its declared length.")
            current = self._u32(page, 16)
            if len(result) == expected_length:
                if current:
                    raise BerkeleyDBError("Overflow chain continues after declared record length.")
                break
            if not current:
                raise BerkeleyDBError(
                    f"Overflow chain ended at {len(result)} of {expected_length} bytes."
                )
        if len(result) != expected_length:
            raise BerkeleyDBError(
                f"Overflow chain yielded {len(result)} of {expected_length} bytes."
            )
        return bytes(result)

    def _leaf_items(self, page: bytes, page_number: int) -> list[bytes | tuple[int, int] | None]:
        offsets = self._page_offsets(page, page_number)
        if len(offsets) % 2:
            raise BerkeleyDBError(f"Leaf page {page_number} has an odd key/data slot count.")
        items: list[bytes | tuple[int, int] | None] = []
        for slot, offset in enumerate(offsets):
            item_type, value, reference, metadata = self._item(page, offset, page_number)
            deleted = bool(metadata >> 31) if item_type != B_KEYDATA else bool(metadata)
            if deleted:
                self.deleted_items += 1
                items.append(None)
            elif item_type == B_KEYDATA:
                items.append(value)
            elif item_type == B_OVERFLOW:
                items.append((reference, metadata & 0x7fffffff))
            else:
                items.append((reference, metadata & 0x7fffffff))
        return items

    def _duplicate_values(self, first_page: int, expected_length: int) -> list[bytes]:
        values: list[bytes] = []
        current = first_page
        visited: set[int] = set()
        total = 0
        while current:
            if current in visited:
                raise BerkeleyDBError(f"Duplicate page chain loops at page {current}.")
            visited.add(current)
            page = self._page(current)
            if self._page_type(page) != PAGE_DUPLICATE_LEAF:
                raise BerkeleyDBError(f"Duplicate reference points to non-duplicate page {current}.")
            offsets = self._page_offsets(page, current)
            for offset in offsets:
                item_type, raw, reference, metadata = self._item(page, offset, current)
                if item_type == B_KEYDATA:
                    values.append(raw)
                    total += len(raw)
                elif item_type == B_OVERFLOW:
                    expanded = self._overflow(reference, metadata & 0x7fffffff)
                    values.append(expanded)
                    total += len(expanded)
                else:
                    raise BerkeleyDBError("Nested duplicate-page reference is unsupported.")
            current = self._u32(page, 16)
        if expected_length and total != expected_length:
            raise BerkeleyDBError(
                f"Duplicate values total {total} bytes, expected {expected_length}."
            )
        return values

    def _walk_tree(self, root: int) -> list[tuple[bytes, bytes, int, int]]:
        pending = [root]
        visited: set[int] = set()
        leaf_records: list[tuple[bytes, bytes, int, int]] = []
        leaf_links: dict[int, tuple[int, int]] = {}
        while pending:
            number = pending.pop()
            if number in visited:
                raise BerkeleyDBError(f"B-tree child graph revisits page {number}.")
            visited.add(number)
            page = self._page(number)
            page_type = self._page_type(page)
            if page_type == PAGE_INTERNAL_BTREE:
                offsets = self._page_offsets(page, number)
                for offset in offsets:
                    if offset + 8 > self.page_size:
                        raise BerkeleyDBError(f"Internal page {number} has a truncated child item.")
                    item_type = page[offset + 2] & ~B_DELETE
                    child = self._u32(page, offset + 4)
                    if item_type not in (B_KEYDATA, B_OVERFLOW):
                        raise BerkeleyDBError(
                            f"Internal page {number} contains unsupported item type {item_type}."
                        )
                    if child <= 0 or child >= self.file_size // self.page_size:
                        raise BerkeleyDBError(f"Internal page {number} references invalid child {child}.")
                    pending.append(child)
            elif page_type == PAGE_LEAF_BTREE:
                items = self._leaf_items(page, number)
                leaf_links[number] = (self._u32(page, 12), self._u32(page, 16))
                for slot in range(0, len(items), 2):
                    key = items[slot]
                    value = items[slot + 1]
                    if key is None or value is None:
                        continue
                    if not isinstance(key, bytes) or not isinstance(value, bytes):
                        if isinstance(key, tuple):
                            key = self._overflow(*key)
                        if isinstance(value, tuple):
                            first_page, declared_len = value
                            if not isinstance(key, bytes):
                                raise BerkeleyDBError("Invalid overflow key.")
                            # B_DUPLICATE stores the aggregate duplicate set.
                            if self._item_type_at(page, self._page_offsets(page, number)[slot + 1]) == B_DUPLICATE:
                                for duplicate_index, duplicate_value in enumerate(
                                    self._duplicate_values(first_page, declared_len)
                                ):
                                    leaf_records.append((
                                        key,
                                        duplicate_value,
                                        number,
                                        slot + 1 + duplicate_index,
                                    ))
                                continue
                            value = self._overflow(first_page, declared_len)
                    if isinstance(key, bytes) and isinstance(value, bytes):
                        leaf_records.append((key, value, number, slot))
                self.pages_visited.add(number)
            else:
                raise BerkeleyDBError(
                    f"B-tree child {number} has unsupported page type {page_type}."
                )
        for number, (previous, following) in leaf_links.items():
            if previous and previous not in leaf_links:
                raise BerkeleyDBError(f"Leaf page {number} points to unreachable previous page {previous}.")
            if following and following not in leaf_links:
                raise BerkeleyDBError(f"Leaf page {number} points to unreachable next page {following}.")
            if previous and leaf_links[previous][1] != number:
                raise BerkeleyDBError(f"Leaf-page links are not reciprocal at page {number}.")
            if following and leaf_links[following][0] != number:
                raise BerkeleyDBError(f"Leaf-page links are not reciprocal at page {number}.")
        return leaf_records

    def _item_type_at(self, page: bytes, offset: int) -> int:
        return page[offset + 2] & ~B_DELETE

    def _metadata_pages(self) -> list[tuple[int, int, int]]:
        result = []
        for number in range(self.file_size // self.page_size):
            start = number * self.page_size
            page = self.data[start:start + self.page_size]
            if len(page) < 92 or page[25] != PAGE_BTREE_META:
                continue
            if self._u32(page, 12) != BDB_MAGIC or self._u32(page, 20) != self.page_size:
                continue
            if self._u32(page, 8) != number:
                continue
            result.append((number, self._u32(page, 88), self._u32(page, 16)))
        return result

    def _find_wallet_root(self, metadata: list[tuple[int, int, int]]) -> tuple[int, int]:
        meta_by_page = {number: root for number, root, _ in metadata}
        catalog_root = meta_by_page.get(0)
        if catalog_root is None:
            raise BerkeleyDBError("The BDB file has no primary metadata page at page 0.")
        catalog_records = self._walk_tree(catalog_root)
        catalog_entries: dict[bytes, bytes] = {}
        for key, value, _, _ in catalog_records:
            catalog_entries[key] = value
        main_pointer = catalog_entries.get(b"main")
        if main_pointer and len(main_pointer) == 4:
            # BDB stores the catalog page number in its own fixed network order.
            for order in ("big", "little"):
                meta_page = int.from_bytes(main_pointer, order)
                root = meta_by_page.get(meta_page)
                if root is not None:
                    self.catalog_page = meta_page
                    return meta_page, root

        alternatives = [(number, root) for number, root, _ in metadata if number != 0 and root]
        if len(alternatives) == 1:
            self.warnings.append(
                "The database catalog did not identify a `main` subdatabase; "
                "the only non-catalog B-tree metadata page was used."
            )
            self.catalog_page, root = alternatives[0]
            return alternatives[0]
        raise BerkeleyDBError(
            "Could not resolve the wallet's `main` named database from the BDB catalog."
        )

    def scan(self) -> dict[str, object]:
        header = self.inspect_header()
        page_count = self.file_size // self.page_size
        for number in range(page_count):
            page = self.data[number * self.page_size:(number + 1) * self.page_size]
            page_type = page[25] if len(page) >= 26 else -1
            self.page_types[str(page_type)] += 1
            if len(page) < 26:
                self.errors.append({
                    "kind": "malformed_page",
                    "page": number,
                    "message": f"Page {number} is shorter than the Berkeley DB page header.",
                })
                continue
            stored_page = self._u32(page, 8)
            if stored_page != number:
                self.errors.append({
                    "kind": "malformed_page",
                    "page": number,
                    "message": f"Page header says page {stored_page}.",
                })
            if page_type in (PAGE_INTERNAL_BTREE, PAGE_LEAF_BTREE, PAGE_DUPLICATE_LEAF):
                try:
                    self._page_offsets(page, number)
                except BerkeleyDBError as exc:
                    self.errors.append({
                        "kind": "malformed_page",
                        "page": number,
                        "message": str(exc),
                    })
            elif page_type == PAGE_OVERFLOW:
                length = self._u16(page, 22)
                next_page = self._u32(page, 16)
                if self.page_overhead + length > self.page_size:
                    self.errors.append({
                        "kind": "malformed_page",
                        "page": number,
                        "message": "Overflow payload exceeds page bounds.",
                    })
                if next_page and next_page >= page_count:
                    self.errors.append({
                        "kind": "malformed_page",
                        "page": number,
                        "message": f"Overflow page references out-of-file page {next_page}.",
                    })

        metadata = self._metadata_pages()
        if not metadata:
            raise BerkeleyDBError("No valid Berkeley DB B-tree metadata pages were found.")
        meta_page, root = self._find_wallet_root(metadata)
        self.root_page = root
        try:
            rows = self._walk_tree(root)
        except BerkeleyDBError as exc:
            self.errors.append({"kind": "btree_decode_error", "message": str(exc)})
            rows = []
        self.records = [
            BDBRecord(key, value, page, slot)
            for key, value, page, slot in rows
        ]

        header.update({
            "metadata_pages": [
                {"page": page, "root_page": root, "version": ver}
                for page, root, ver in metadata
            ],
            "catalog_page": meta_page,
            "wallet_root_page": root,
            "reachable_tree_pages": len(self.pages_visited),
            "overflow_pages": len(self.overflow_pages),
            "deleted_items": self.deleted_items,
            "page_types": dict(self.page_types),
        })
        return header
