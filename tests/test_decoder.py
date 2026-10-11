import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from reader import (
    B_DUPLICATE,
    B_KEYDATA,
    B_OVERFLOW,
    BerkeleyDBError,
    BerkeleyDBReader,
    PAGE_DUPLICATE_LEAF,
    PAGE_INTERNAL_BTREE,
    PAGE_LEAF_BTREE,
    PAGE_OVERFLOW,
    PAGE_BTREE_META,
)
from reporter import (
    build_report,
    render_text,
    write_reports,
    write_shielded_export,
    write_wif_export,
)
from records import associate_shielded_addresses, decode_wallet_record
from shielded import (
    BECH32_ALPHABET,
    _bech32_polymod,
    sapling_extended_spending_key,
    sapling_payment_address,
    sprout_payment_address,
    sprout_spending_key,
)
from sapling import (
    _aes256_encrypt,
    _aes256_round_keys,
    _ff1_diversifier,
    _ivk,
    _multiply,
    _encode_point,
    _generators,
    validate_and_derive_sapling,
)
from serialization import (
    Reader,
    SerializationError,
    compact_size,
    serialize_varint,
    serialize_vector,
)


def bdb_file(page_size=8192, endian="<", overflow=False, internal=True,
             duplicate=False, checksummed=False):
    pages = [bytearray(page_size) for _ in range(5)]
    byteorder = "little" if endian == "<" else "big"

    def put16(buf, off, value):
        buf[off:off + 2] = value.to_bytes(2, byteorder)

    def put32(buf, off, value):
        buf[off:off + 4] = value.to_bytes(4, byteorder)

    def make_meta(number, root):
        page = pages[number]
        put32(page, 8, number)
        put32(page, 12, 0x00053162)
        put32(page, 16, 10)
        put32(page, 20, page_size)
        page[25] = PAGE_BTREE_META
        page[26] = 1 if checksummed else 0
        put32(page, 88, root)

    def make_page(number, page_type, items=(), level=1, next_page=0):
        page = pages[number]
        put32(page, 8, number)
        put32(page, 12, 0)
        put32(page, 16, next_page)
        put16(page, 20, len(items))
        page[24] = level
        page[25] = page_type
        index_start = 32 if checksummed else 26
        cursor = page_size
        offsets = []
        for item in items:
            packed_size = (len(item) + 3) & ~3
            cursor -= packed_size
            page[cursor:cursor + len(item)] = item
            offsets.append(cursor)
        put16(page, 22, cursor)
        for index, offset in enumerate(offsets):
            put16(page, index_start + index * 2, offset)
        return page

    def keydata(raw):
        return len(raw).to_bytes(2, byteorder) + bytes((B_KEYDATA,)) + raw

    def internal_child(child):
        return (
            b"\x00\x00" + bytes((B_KEYDATA, 0)) + child.to_bytes(4, byteorder)
            + b"\x00\x00\x00\x00"
        )

    make_meta(0, 1)
    make_page(1, PAGE_LEAF_BTREE, [keydata(b"main"), keydata(b"\x00\x00\x00\x02")])
    make_meta(2, 3)

    name = serialize_vector(b"version")
    record_key = name
    record_value = struct.pack("<i", 70015)
    leaf_key = keydata(record_key)
    if overflow:
        first = 5
        full_value = b"v" * (page_size + 101)
        record_value = full_value
        overflow_ref = (
            b"\x00\x00" + bytes((B_OVERFLOW, 0)) + first.to_bytes(4, byteorder)
            + len(full_value).to_bytes(4, byteorder)
        )
        value_item = overflow_ref
    elif duplicate:
        duplicate_ref = (
            b"\x00\x00" + bytes((B_DUPLICATE, 0)) + (5).to_bytes(4, byteorder)
            + len(record_value).to_bytes(4, byteorder)
        )
        value_item = duplicate_ref
    else:
        value_item = keydata(record_value)

    root = 3
    if internal:
        make_page(3, PAGE_INTERNAL_BTREE, [internal_child(4)], level=2)
        make_page(4, PAGE_LEAF_BTREE, [leaf_key, value_item])
    else:
        make_page(3, PAGE_LEAF_BTREE, [leaf_key, value_item])
        make_page(4, 0)

    if overflow:
        remaining = record_value
        current = first
        while remaining:
            overhead = 32 if checksummed else 26
            chunk = remaining[:page_size - overhead]
            remaining = remaining[len(chunk):]
            page = bytearray(page_size)
            put32(page, 8, current)
            put32(page, 16, current + 1 if remaining else 0)
            put16(page, 22, len(chunk))
            page[25] = PAGE_OVERFLOW
            page[overhead:overhead + len(chunk)] = chunk
            pages.append(page)
            current += 1
    elif duplicate:
        duplicate_value = keydata(record_value)
        pages.append(bytearray(page_size))
        make_page(5, PAGE_DUPLICATE_LEAF, [duplicate_value])

    return b"".join(bytes(page) for page in pages)


class SerializationTests(unittest.TestCase):
    def test_compactsize_boundaries_and_noncanonical_encoding(self):
        for value in (0, 252, 253, 65535, 65536, 0xFFFFFFFF, 0x100000000):
            data = compact_size(value)
            self.assertEqual(Reader(data).compact_size(), value)
        with self.assertRaises(SerializationError):
            Reader(b"\xfd\xfc\x00").compact_size()

    def test_serialized_vector_and_truncation(self):
        self.assertEqual(Reader(serialize_vector(b"abc")).vector(), b"abc")
        with self.assertRaises(SerializationError):
            Reader(b"\x04abc").vector()

    def test_variable_length_integer_boundaries_and_overflow(self):
        for value in (0, 127, 128, 255, 256, 65535, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            encoded = serialize_varint(value)
            self.assertEqual(Reader(encoded).varint(), value)
        with self.assertRaises(SerializationError):
            Reader(b"\x80" * 10).varint()


class BerkeleyDBTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.wallet = Path(self.temp.name) / "wallet.dat"

    def reader_for(self, **kwargs):
        self.wallet.write_bytes(bdb_file(**kwargs))
        reader = BerkeleyDBReader(self.wallet)
        reader.scan()
        return reader

    def test_named_main_database_and_internal_page(self):
        reader = self.reader_for()
        self.assertEqual(reader.page_size, 8192)
        self.assertEqual(reader.root_page, 3)
        self.assertEqual(len(reader.records), 1)
        self.assertEqual(reader.records[0].value, struct.pack("<i", 70015))
        self.assertEqual(reader.pages_visited, {1, 4})

    def test_actual_page_size_is_discovered(self):
        for page_size in (4096, 16384):
            with self.subTest(page_size=page_size):
                reader = self.reader_for(page_size=page_size, internal=False)
                self.assertEqual(reader.page_size, page_size)

    def test_big_endian_berkeley_db_metadata(self):
        reader = self.reader_for(page_size=4096, endian=">", internal=False)
        self.assertEqual(reader.endian, ">")
        self.assertEqual(reader.records[0].value, struct.pack("<i", 70015))

    def test_checksum_header_reserves_the_correct_page_prefix(self):
        reader = self.reader_for(checksummed=True, internal=False)
        self.assertEqual(reader.page_overhead, 32)
        self.assertEqual(reader.records[0].value, struct.pack("<i", 70015))

    def test_overflow_chain_reconstructs_value(self):
        reader = self.reader_for(overflow=True)
        self.assertEqual(len(reader.records[0].value), 8192 + 101)
        self.assertEqual(reader.records[0].value, b"v" * (8192 + 101))
        self.assertEqual(len(reader.overflow_pages), 2)

    def test_truncated_overflow_chain_is_reported(self):
        data = bytearray(bdb_file(overflow=True))
        first_overflow_page = 5
        next_pointer = first_overflow_page * 8192 + 16
        data[next_pointer:next_pointer + 4] = bytes(4)
        self.wallet.write_bytes(data)
        reader = BerkeleyDBReader(self.wallet)
        reader.scan()
        self.assertEqual(reader.records, [])
        self.assertTrue(any(
            issue["kind"] == "btree_decode_error"
            and "Overflow chain ended" in issue["message"]
            for issue in reader.errors
        ))

    def test_duplicate_page_extracts_data(self):
        reader = self.reader_for(duplicate=True, internal=False)
        self.assertEqual(reader.records[0].value, struct.pack("<i", 70015))

    def test_truncated_file_is_reported_without_mutation(self):
        data = bdb_file(internal=False) + b"\x00"
        self.wallet.write_bytes(data)
        before = self.wallet.read_bytes()
        reader = BerkeleyDBReader(self.wallet)
        header = reader.scan()
        self.assertEqual(header["trailing_bytes"], 1)
        self.assertTrue(any(issue["kind"] == "incomplete_page" for issue in reader.errors))
        self.assertEqual(self.wallet.read_bytes(), before)

    def test_bad_magic_is_rejected(self):
        self.wallet.write_bytes(b"\x00" * 8192)
        with self.assertRaises(BerkeleyDBError):
            BerkeleyDBReader(self.wallet).scan()

    def test_unreachable_page_number_mismatch_is_reported(self):
        data = bytearray(bdb_file(internal=False))
        data[4 * 8192 + 8:4 * 8192 + 12] = (99).to_bytes(4, "little")
        self.wallet.write_bytes(data)
        reader = BerkeleyDBReader(self.wallet)
        reader.scan()
        self.assertTrue(any(
            issue.get("page") == 4 and issue["kind"] == "malformed_page"
            for issue in reader.errors
        ))


class WalletRecordTests(unittest.TestCase):
    pubkey = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )

    def make_record(self, key, value):
        from reader import BDBRecord
        return BDBRecord(key, value, 1, 0)

    def test_unencrypted_key_checksum_valid_and_secret_redacted(self):
        private_der = bytes.fromhex("3006020101040101")
        expected = hashlib.sha256(
            hashlib.sha256(self.pubkey + private_der).digest()
        ).digest()
        key = serialize_vector(b"key") + serialize_vector(self.pubkey)
        value = serialize_vector(private_der) + expected
        report = decode_wallet_record(self.make_record(key, value))
        self.assertTrue(report["key_checksum_valid"])
        self.assertTrue(report["private_key_der_valid"])
        self.assertNotIn("private_key", report)
        self.assertNotIn("private_key_wif", report)
        self.assertFalse(report["secret_exported"])
        self.assertIn("address", report)

    def test_explicit_wif_decode_uses_bitcoinz_prefix_and_compression_flag(self):
        private_der = bytes.fromhex("3006020101040101")
        checksum = hashlib.sha256(
            hashlib.sha256(self.pubkey + private_der).digest()
        ).digest()
        key = serialize_vector(b"key") + serialize_vector(self.pubkey)
        value = serialize_vector(private_der) + checksum
        report = decode_wallet_record(
            self.make_record(key, value), include_private_key=True
        )
        wif = report["private_key_wif"]
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number = 0
        for character in wif:
            number = number * 58 + alphabet.index(character)
        decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
        decoded = b"\x00" * (len(wif) - len(wif.lstrip("1"))) + decoded
        payload, actual_checksum = decoded[:-4], decoded[-4:]
        expected_checksum = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]
        self.assertEqual(payload, b"\x80" + b"\x00" * 31 + b"\x01\x01")
        self.assertEqual(actual_checksum, expected_checksum)
        self.assertTrue(report["address"].startswith("t1"))
        self.assertTrue(report["secret_exported"])

    def test_explicit_wif_decode_preserves_uncompressed_public_key_format(self):
        uncompressed_pubkey = bytes.fromhex(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        private_der = bytes.fromhex("3006020101040101")
        checksum = hashlib.sha256(
            hashlib.sha256(uncompressed_pubkey + private_der).digest()
        ).digest()
        key = serialize_vector(b"key") + serialize_vector(uncompressed_pubkey)
        report = decode_wallet_record(
            self.make_record(key, serialize_vector(private_der) + checksum),
            include_private_key=True,
        )
        self.assertEqual(report["decode_status"], "decoded")
        self.assertEqual(len(report["private_key_wif"]), 51)
        self.assertTrue(report["private_key_wif"].startswith("5"))

    def test_wif_export_rejects_a_valid_scalar_for_the_wrong_public_key(self):
        private_der = bytes.fromhex("3006020101040102")
        checksum = hashlib.sha256(
            hashlib.sha256(self.pubkey + private_der).digest()
        ).digest()
        key = serialize_vector(b"key") + serialize_vector(self.pubkey)
        report = decode_wallet_record(
            self.make_record(key, serialize_vector(private_der) + checksum),
            include_private_key=True,
        )
        self.assertEqual(report["decode_status"], "malformed")
        self.assertNotIn("private_key_wif", report)
        self.assertEqual(
            report["error"],
            "Private key does not match the serialized public key.",
        )

    def test_wif_export_is_explicit_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            wallet = Path(temp) / "wallet.dat"
            export = Path(temp) / "keys.csv"
            wallet.write_bytes(b"wallet")
            write_wif_export(
                [("t1example", "WIFSECRET")],
                export,
                wallet,
                (Path(temp) / "report.json", Path(temp) / "report.txt"),
            )
            self.assertEqual(
                export.read_text(encoding="utf-8"),
                'address,private_key_wif\nt1example,WIFSECRET\n',
            )
            with self.assertRaises(FileExistsError):
                write_wif_export(
                    [("t1example", "NEWSECRET")],
                    export,
                    wallet,
                    (Path(temp) / "report.json", Path(temp) / "report.txt"),
                )
            self.assertIn("WIFSECRET", export.read_text(encoding="utf-8"))
            self.assertEqual(wallet.read_bytes(), b"wallet")

    def test_encrypted_key_is_identified_without_secret_bytes(self):
        key = serialize_vector(b"ckey") + serialize_vector(self.pubkey)
        value = serialize_vector(b"x" * 32)
        report = decode_wallet_record(self.make_record(key, value))
        self.assertEqual(report["key_material"], "encrypted private key")
        self.assertEqual(report["encrypted_secret_length"], 32)
        self.assertNotIn("encrypted_secret", report)

    def test_bitcoinz_shielded_keys_are_not_misparsed_as_secp256k1(self):
        key = serialize_vector(b"sapzkey") + bytes(32)
        report = decode_wallet_record(self.make_record(key, bytes(169)))
        self.assertEqual(report["decode_status"], "decoded")
        self.assertEqual(report["shielded_type"], "Sapling")
        self.assertEqual(report["key_material"], "Sapling extended spending key; secret redacted")
        self.assertNotIn("public_key_valid", report)

    def _valid_sapling_extended_key(self):
        spend_generator, proof_generator = _generators()
        ak = _encode_point(_multiply(spend_generator, 1))
        nk = _encode_point(_multiply(proof_generator, 2))
        ivk = _ivk(ak, nk).to_bytes(32, "little")
        extended_key = (
            bytes(41)
            + (1).to_bytes(32, "little")
            + (2).to_bytes(32, "little")
            + bytes(range(32))
            + bytes(range(32, 64))
        )
        self.assertEqual(len(extended_key), 169)
        return extended_key, ivk

    def test_sapling_pure_python_validation_derives_default_address(self):
        extended_key, ivk = self._valid_sapling_extended_key()
        result = validate_and_derive_sapling(extended_key, ivk)
        self.assertEqual(
            result["address"],
            "zs1sd7ym64jjecquyg2vl59myxyfsmkn2h783x2a6c2c8t9s8yp3ygcvh38rtlnral2xaw5gwtr7sx",
        )
        self.assertEqual(
            result["validation"],
            "Sapling ZIP32 scalars, viewing keys, and wallet IVK validated",
        )
        self.assertGreaterEqual(result["diversifier_index"], 0)

    def test_sapling_crypto_rejects_wallet_ivk_mismatch_per_record(self):
        extended_key, _ = self._valid_sapling_extended_key()
        report = decode_wallet_record(
            self.make_record(
                serialize_vector(b"sapzkey") + bytes(32),
                extended_key,
            ),
            validate_shielded_crypto=True,
        )
        self.assertEqual(report["decode_status"], "malformed")
        self.assertEqual(
            report["error"],
            "Sapling spending key does not match its wallet incoming viewing key.",
        )
        self.assertNotIn("derived_shielded_address", report)
        self.assertNotIn("shielded_spending_key", report)

    def test_sapling_crypto_is_opt_in_and_reports_stay_redacted(self):
        extended_key, ivk = self._valid_sapling_extended_key()
        record = self.make_record(serialize_vector(b"sapzkey") + ivk, extended_key)
        default_report = decode_wallet_record(record)
        self.assertEqual(default_report["key_validation"], "not requested; enable --validate-shielded")
        self.assertNotIn("derived_shielded_address", default_report)
        self.assertNotIn("shielded_spending_key", default_report)

        validated_report = decode_wallet_record(
            record,
            validate_shielded_crypto=True,
        )
        self.assertEqual(validated_report["decode_status"], "decoded")
        self.assertEqual(validated_report["cryptographic_validation"], "passed")
        self.assertTrue(validated_report["derived_shielded_address"].startswith("zs1"))
        self.assertNotIn("shielded_spending_key", validated_report)
        associate_shielded_addresses([validated_report])
        self.assertEqual(validated_report["stored_shielded_addresses"], [])

    def test_sapling_aes_and_ff1_known_answer_vectors(self):
        keys = _aes256_round_keys(bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        ))
        self.assertEqual(
            _aes256_encrypt(
                bytes.fromhex("00112233445566778899aabbccddeeff"),
                keys,
            ).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )
        self.assertEqual(
            _ff1_diversifier(bytes(32), 0).hex(),
            "dce77ebcec0a26afd6998c",
        )
        self.assertEqual(
            _ff1_diversifier(bytes(32), 3).hex(),
            "3cfdaa08ab93dc1f039022",
        )

    def test_sprout_record_decodes_z_address_and_redacts_spending_key(self):
        address_bytes = bytes(range(64))
        spending_key = b"\x01" + bytes(31)
        record = self.make_record(
            serialize_vector(b"zkey") + address_bytes,
            spending_key,
        )
        report = decode_wallet_record(record)
        self.assertEqual(report["decode_status"], "decoded")
        self.assertEqual(report["shielded_type"], "Sprout")
        self.assertEqual(report["shielded_address"], sprout_payment_address(address_bytes))
        self.assertTrue(report["shielded_address"].startswith("zc"))
        self.assertNotIn("shielded_spending_key", report)
        exported = decode_wallet_record(record, include_shielded_private_key=True)
        self.assertTrue(exported["shielded_spending_key"].startswith("SK"))
        self.assertEqual(
            exported["shielded_spending_key"],
            sprout_spending_key(spending_key),
        )

    def test_malformed_shielded_spending_key_serializations_are_rejected(self):
        invalid_sprout = decode_wallet_record(
            self.make_record(
                serialize_vector(b"zkey") + bytes(64),
                b"\xf0" + bytes(31),
            )
        )
        invalid_sapling = decode_wallet_record(
            self.make_record(
                serialize_vector(b"sapzkey") + bytes(32),
                bytes(168),
            )
        )
        self.assertEqual(invalid_sprout["decode_status"], "malformed")
        self.assertEqual(invalid_sapling["decode_status"], "malformed")

    def test_sapling_payment_address_encoding_and_bech32_checksum(self):
        serialized = bytes(range(43))
        address = sapling_payment_address(serialized)
        self.assertTrue(address.startswith("zs1"))
        values = [BECH32_ALPHABET.index(char) for char in address.split("1", 1)[1]]
        hrp = "zs"
        expanded = [ord(char) >> 5 for char in hrp] + [0]
        expanded += [ord(char) & 31 for char in hrp]
        self.assertEqual(_bech32_polymod(expanded + values), 1)

    def test_sapling_stored_address_links_to_spending_key_and_export(self):
        ivk = bytes(range(32))
        address_bytes = bytes(range(43))
        address_record = self.make_record(
            serialize_vector(b"sapzaddr") + address_bytes,
            ivk,
        )
        spending_key = bytes(range(169))
        key_record = self.make_record(
            serialize_vector(b"sapzkey") + ivk,
            spending_key,
        )
        address = decode_wallet_record(address_record)
        key = decode_wallet_record(key_record, include_shielded_private_key=True)
        combined = [address, key]
        associate_shielded_addresses(combined)
        expected_address = sapling_payment_address(address_bytes)
        self.assertEqual(combined[1]["shielded_addresses"], [expected_address])
        self.assertEqual(
            combined[1]["stored_shielded_addresses"],
            [expected_address],
        )
        self.assertEqual(
            combined[1]["shielded_spending_key"],
            sapling_extended_spending_key(spending_key),
        )
        self.assertTrue(
            combined[1]["shielded_spending_key"].startswith("secret-extended-key-main1")
        )
        self.assertNotIn("_sapling_ivk", combined[0])
        self.assertNotIn("_sapling_ivk", combined[1])

    def test_encrypted_sprout_record_reveals_address_but_not_key(self):
        address_bytes = bytes(range(64))
        value = bytes(32) + serialize_vector(bytes(32))
        report = decode_wallet_record(
            self.make_record(serialize_vector(b"czkey") + address_bytes, value)
        )
        self.assertEqual(report["decode_status"], "decoded")
        self.assertEqual(report["shielded_address"], sprout_payment_address(address_bytes))
        self.assertFalse(report["secret_exported"])
        self.assertNotIn("shielded_spending_key", report)

    def test_master_key_metadata_is_parsed_but_not_decrypted(self):
        key = serialize_vector(b"mkey") + struct.pack("<I", 7)
        value = (
            serialize_vector(b"x" * 16)
            + serialize_vector(b"salt")
            + struct.pack("<II", 0, 25000)
            + serialize_vector(b"")
        )
        report = decode_wallet_record(self.make_record(key, value))
        self.assertEqual(report["derivation_method"], 0)
        self.assertEqual(report["derivation_iterations"], 25000)
        self.assertEqual(report["password_decryption"], "not implemented; no password attempted")

    def test_keypool_includes_stream_serialization_version(self):
        key = serialize_vector(b"pool") + struct.pack("<q", 10)
        value = struct.pack("<Iq", 70015, 123456) + serialize_vector(self.pubkey)
        report = decode_wallet_record(self.make_record(key, value))
        self.assertEqual(report["serialization_version"], 70015)
        self.assertTrue(report["public_key_valid"])

    def test_bitcoinz_sapling_wallet_transaction(self):
        tx = (
            struct.pack("<II", 0x80000004, 0x892F2085)
            + b"\x00\x00"  # vin and vout
            + struct.pack("<IIq", 0, 0, 0)  # locktime, expiry, valueBalance
            + b"\x00\x00\x00"  # Sapling spends, outputs, JoinSplits
        )
        txid = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
        wallet_value = (
            tx + bytes(32) + b"\x00" + struct.pack("<i", -1)
            + b"\x00\x00\x00\x00"  # unused transactions, mapValue, Sprout notes
            + struct.pack("<II", 0, 123456) + b"\x00\x00\x00"
        )
        key = serialize_vector(b"tx") + txid
        report = decode_wallet_record(self.make_record(key, wallet_value))
        self.assertEqual(report["decode_status"], "decoded")
        self.assertEqual(report["transaction_id"], txid[::-1].hex())
        self.assertEqual(report["version"], 4)
        self.assertTrue(report["overwintered"])

    def test_report_writer_refuses_wallet_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            wallet = Path(temp) / "wallet.dat"
            wallet.write_bytes(b"wallet")
            report = build_report({}, {}, [], [], [])
            with self.assertRaises(ValueError):
                write_reports(report, wallet, Path(temp) / "out.txt", wallet)
            self.assertEqual(wallet.read_bytes(), b"wallet")

    def test_report_names_page_types_and_counts_incomplete_decodes(self):
        report = build_report(
            {
                "file": "test.dat",
                "size_bytes": 0,
                "bdb_version": 10,
                "byte_order": "little",
                "page_size": 8192,
                "wallet_root_page": 3,
            },
            {"3": 1, "5": 2, "99": 1},
            [
                {"type": "version", "decode_status": "decoded"},
                {"type": "zkey", "decode_status": "unsupported"},
            ],
            [],
            [],
        )
        text = render_text(report)
        self.assertEqual(report["failed_or_incomplete_record_decodes"], 1)
        self.assertEqual(report["page_type_names"]["3"], "B-tree internal")
        self.assertIn("type 5 (B-tree leaf): 2", text)
        self.assertIn("Failed or incomplete record decodes: 1", text)

    def test_report_lists_shielded_addresses_by_protocol(self):
        report = build_report(
            {
                "file": "test.dat",
                "size_bytes": 0,
                "bdb_version": 10,
                "byte_order": "little",
                "page_size": 8192,
                "wallet_root_page": 3,
            },
            {},
            [
                {
                    "type": "zkey",
                    "decode_status": "decoded",
                    "shielded_type": "Sprout",
                    "shielded_addresses": ["zcSprout"],
                },
                {
                    "type": "sapzaddr",
                    "decode_status": "decoded",
                    "shielded_type": "Sapling",
                    "shielded_addresses": ["zsSapling"],
                },
            ],
            [],
            [],
        )
        self.assertEqual(
            report["shielded_addresses_by_type"],
            {"Sprout": ["zcSprout"], "Sapling": ["zsSapling"]},
        )
        self.assertIn("zsSapling", render_text(report))

    def test_shielded_export_creates_secret_file_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            wallet = Path(temp) / "wallet.dat"
            export = Path(temp) / "shielded.csv"
            wallet.write_bytes(b"wallet")
            write_shielded_export(
                [("Sprout", "zcAddress", "", "SK format", "storage validated", "secret")],
                export,
                wallet,
                (Path(temp) / "report.json", Path(temp) / "report.txt"),
            )
            exported = export.read_text(encoding="utf-8")
            self.assertEqual(
                exported.splitlines()[0],
                "type,address,derived_address,key_format,key_validation,spending_key",
            )
            self.assertIn("secret", exported)
            with self.assertRaises(FileExistsError):
                write_shielded_export(
                    [("Sprout", "zcAddress", "", "SK format", "storage validated", "new-secret")],
                    export,
                    wallet,
                    (Path(temp) / "report.json", Path(temp) / "report.txt"),
                )
            self.assertNotIn("new-secret", export.read_text(encoding="utf-8"))
            self.assertEqual(wallet.read_bytes(), b"wallet")


if __name__ == "__main__":
    unittest.main()
