"""Read-only native-Python BitcoinZ wallet.dat decoder."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

from reader import BerkeleyDBError, BerkeleyDBReader
from reporter import (
    build_report,
    write_reports,
    write_shielded_export,
    write_wif_export,
)
from records import associate_shielded_addresses, decode_wallet_record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode BitcoinZ Core wallet.dat read-only; secrets are redacted by default."
    )
    parser.add_argument("wallet", nargs="?", default="wallet.dat", help="Input wallet file")
    parser.add_argument("--json", default="wallet_report.json", help="JSON report path")
    parser.add_argument("--text", default="wallet_report.txt", help="Text report path")
    parser.add_argument(
        "--export-wif",
        metavar="PATH",
        help=(
            "explicitly export validated unencrypted private keys as plaintext WIF "
            "to a new CSV file (existing files are never overwritten)"
        ),
    )
    parser.add_argument(
        "--export-shielded",
        metavar="PATH",
        help=(
            "explicitly export supported unencrypted Sprout/Sapling spending keys "
            "to a new plaintext CSV file; combine with --validate-shielded for "
            "Sapling cryptographic validation and a derived default address"
        ),
    )
    parser.add_argument(
        "--validate-shielded",
        action="store_true",
        help=(
            "opt in to pure-Python Sapling ZIP32 key validation, wallet-IVK "
            "matching, and default address derivation; no secrets are written"
        ),
    )
    args = parser.parse_args(argv)
    try:
        reader = BerkeleyDBReader(args.wallet)
        header = reader.scan()
        records = [
            decode_wallet_record(
                row,
                validate_shielded_crypto=args.validate_shielded,
            )
            for row in reader.records
        ]
        associate_shielded_addresses(records)
        wif_entries: list[tuple[str, str]] = []
        if args.export_wif:
            for row in reader.records:
                item = decode_wallet_record(row, include_private_key=True)
                wif = item.get("private_key_wif")
                if item["type"] == "key" and isinstance(wif, str):
                    wif_entries.append((item.get("address", ""), wif))

        shielded_entries: list[tuple[str, str, str, str, str, str]] = []
        if args.export_shielded:
            export_records = [
                decode_wallet_record(
                    row,
                    include_shielded_private_key=True,
                    validate_shielded_crypto=args.validate_shielded,
                )
                for row in reader.records
            ]
            associate_shielded_addresses(export_records)
            for item in export_records:
                secret = item.pop("shielded_spending_key", None)
                if (
                    args.validate_shielded
                    and item["type"] == "sapzkey"
                    and item.get("cryptographic_validation") != "passed"
                ):
                    secret = ""
                    continue
                if item["type"] not in {"zkey", "sapzkey"} or not isinstance(secret, str):
                    continue
                addresses = item.get(
                    "stored_shielded_addresses",
                    item.get("shielded_addresses", []),
                )
                shielded_entries.append((
                    item["shielded_type"],
                    "; ".join(addresses),
                    item.get("derived_shielded_address", ""),
                    item["key_format"],
                    item["key_validation"],
                    secret,
                ))
                secret = ""

        output_paths = [
            Path(args.wallet).resolve(),
            Path(args.json).resolve(),
            Path(args.text).resolve(),
        ]
        requested_exports = [
            Path(path).resolve()
            for path in (args.export_wif, args.export_shielded)
            if path
        ]
        if len(set(output_paths + requested_exports)) != len(output_paths + requested_exports):
            raise ValueError("Wallet, report, and export paths must all be different.")

        wif_export_count = len(wif_entries)
        shielded_export_count = len(shielded_entries)
        warnings = list(reader.warnings)
        if args.export_wif and not wif_export_count:
            warnings.append(
                "WIF export was requested, but no validated unencrypted key records are available."
            )
        if args.export_shielded and not shielded_export_count:
            warnings.append(
                "No shielded spending keys met the requested export and validation requirements."
            )
        report = build_report(
            header, dict(reader.page_types), records, reader.errors, warnings
        )
        report["security"]["wif_exported_to_separate_file"] = bool(
            args.export_wif and wif_export_count
        )
        report["security"]["wif_export_count"] = wif_export_count
        report["security"]["shielded_keys_exported_to_separate_file"] = bool(
            args.export_shielded and shielded_export_count
        )
        report["security"]["shielded_key_export_count"] = shielded_export_count
        report["security"]["sapling_crypto_validation_enabled"] = args.validate_shielded
        report["security"]["sapling_crypto_validated_count"] = sum(
            item.get("cryptographic_validation") == "passed"
            for item in records
        )
        if args.export_wif:
            if wif_entries:
                write_wif_export(
                    wif_entries,
                    args.export_wif,
                    args.wallet,
                    (args.json, args.text),
                )
                wif_entries.clear()
            elif Path(args.export_wif).resolve() in {
                Path(args.wallet).resolve(),
                Path(args.json).resolve(),
                Path(args.text).resolve(),
            }:
                raise ValueError(
                    "WIF export path must differ from the wallet and report files."
                )
        if args.export_shielded and shielded_export_count:
            write_shielded_export(
                shielded_entries,
                args.export_shielded,
                args.wallet,
                (args.json, args.text),
            )
            shielded_entries.clear()
        write_reports(report, args.json, args.text, args.wallet)
    except (BerkeleyDBError, OSError, ValueError) as exc:
        print(f"Decoder error: {exc}", file=sys.stderr)
        return 2

    counts = Counter(item["type"] for item in records)
    print(f"Wallet: {Path(args.wallet).name} (read-only)")
    print(f"Berkeley DB v{header['bdb_version']}, {header['page_size']} byte pages")
    print(f"Wallet database root page: {header['wallet_root_page']}")
    print(f"Extracted records: {len(records)}")
    for kind, count in sorted(counts.items()):
        print(f"  {kind}: {count}")
    print(f"JSON report: {Path(args.json).resolve()}")
    print(f"Text report: {Path(args.text).resolve()}")
    print(
        "Sapling cryptographic validation/address derivation: "
        + ("enabled" if args.validate_shielded else "not run")
    )
    if args.validate_shielded:
        print(
            "Validated Sapling key records: "
            + str(report["security"]["sapling_crypto_validated_count"])
        )
    if args.export_wif and wif_export_count:
        print(f"Exported {wif_export_count} private key(s) to: {Path(args.export_wif).resolve()}")
        print("Warning: this CSV contains plaintext private keys; keep it secure and delete it when no longer needed.")
    else:
        print(
            "Private keys remain redacted. Use --export-wif PATH or "
            "--export-shielded PATH to explicitly export supported unencrypted keys."
        )
    if args.export_shielded and shielded_export_count:
        print(
            f"Exported {shielded_export_count} shielded spending key(s) to: "
            f"{Path(args.export_shielded).resolve()}"
        )
        print("Warning: this CSV contains plaintext spending keys; keep it secure and delete it when no longer needed.")
    elif args.export_shielded:
        print("No supported unencrypted shielded spending keys were available to export.")
    print("Review report validation/limitations.")
    return 1 if (
        (args.export_wif and not wif_export_count)
        or (args.export_shielded and not shielded_export_count)
        or reader.errors
        or any(
            r["decode_status"] in {
                "malformed", "unsupported", "unknown_record_type", "partially_decoded"
            }
            for r in records
        )
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
