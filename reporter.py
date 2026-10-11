"""Redacted JSON and human-readable wallet decoder reports."""

from __future__ import annotations

from collections import Counter
import csv
import json
import os
from pathlib import Path
from typing import Any


PAGE_TYPE_NAMES = {
    "0": "free or unallocated",
    "3": "B-tree internal",
    "5": "B-tree leaf",
    "7": "overflow",
    "9": "B-tree metadata",
    "12": "duplicate leaf",
}


def build_report(header: dict[str, Any], page_types: dict[str, int],
                 records: list[dict[str, Any]], errors: list[dict[str, Any]],
                 warnings: list[str]) -> dict[str, Any]:
    counts = Counter(item["type"] for item in records)
    statuses = Counter(item["decode_status"] for item in records)
    unsupported = sorted({
        item["type"] for item in records
        if item["decode_status"] in {"unsupported", "unknown_record_type", "partially_decoded"}
    })
    redacted = sorted({
        item["type"] for item in records
        if item.get("seed_material") == "present; redacted"
        or item.get("secret_exported") is False
    })
    encrypted_count = sum(
        count for kind, count in counts.items()
        if kind in {"ckey", "czkey", "csapzkey", "mkey", "chdseed"}
    )
    addresses = sorted({
        item["address"] for item in records
        if isinstance(item.get("address"), str)
    })
    shielded_addresses_by_type = {
        shielded_type: sorted({
            address
            for item in records
            if item.get("shielded_type") == shielded_type
            for address in item.get("shielded_addresses", [])
            if isinstance(address, str)
        })
        for shielded_type in ("Sprout", "Sapling")
    }
    shielded_key_counts = {
        "Sprout": counts.get("zkey", 0) + counts.get("czkey", 0),
        "Sapling": counts.get("sapzkey", 0) + counts.get("csapzkey", 0),
    }
    return {
        "format": "BitcoinZ Core Berkeley DB wallet",
        "header": header,
        "page_counts_by_type": page_types,
        "page_type_names": {
            kind: PAGE_TYPE_NAMES.get(kind, "unknown page type")
            for kind in page_types
        },
        "unsupported_page_types": [
            kind for kind in sorted(page_types, key=int)
            if int(kind) not in {0, 3, 5, 7, 9, 12}
        ],
        "record_counts_by_type": dict(sorted(counts.items())),
        "transparent_addresses": addresses,
        "shielded_addresses_by_type": shielded_addresses_by_type,
        "shielded_key_record_counts": shielded_key_counts,
        "decode_counts": dict(sorted(statuses.items())),
        "failed_or_incomplete_record_decodes": sum(
            count for status, count in statuses.items() if status != "decoded"
        ),
        "records": records,
        "unsupported_or_partial_record_types": unsupported,
        "sensitive_record_types_redacted": redacted,
        "encryption": {
            "encrypted_records_detected": encrypted_count,
            "wallet_encrypted": encrypted_count > 0,
            "password_decryption_supported": False,
        },
        "errors": errors,
        "warnings": warnings,
        "security": {
            "private_key_bytes_included": False,
            "encrypted_secret_bytes_included": False,
            "seed_material_included": False,
            "passwords_attempted": False,
            "wallet_opened_read_only": True,
            "wif_exported_to_separate_file": False,
            "wif_export_count": 0,
            "shielded_keys_exported_to_separate_file": False,
            "shielded_key_export_count": 0,
            "sapling_crypto_validation_enabled": False,
            "sapling_crypto_validated_count": 0,
        },
        "validation": {
            "bdb_page_structures_validated": not any(
                e.get("kind") in {"incomplete_page", "malformed_page", "btree_decode_error"}
                for e in errors
            ),
            "database_checksums_validated": False,
            "all_reachable_wallet_records_extracted": not any(
                e.get("kind") == "btree_decode_error" for e in errors
            ),
            "all_extracted_wallet_records_fully_decoded": (
                not errors and not unsupported
                and all(r["decode_status"] == "decoded" for r in records)
            ),
            "decoder_complete_for_all_bitcoinz_wallet_variants": False,
        },
        "limitations": [
            "Password-based master-key derivation and AES decryption are not implemented.",
            "BitcoinZ Sprout/Sapling note-witness maps in wallet transaction metadata are not decoded.",
            "Sapling ZIP32 validation and default-address derivation are opt-in with --validate-shielded; the pure-Python arithmetic is variable-time and is not suitable for signing.",
            "Sprout spending-key/address correspondence is not independently cryptographically re-derived.",
            "Database page checksums are not verified; structural bounds and page references are checked.",
        ],
    }


def render_text(report: dict[str, Any]) -> str:
    header = report["header"]
    lines = [
        "BitcoinZ Core wallet.dat decode report",
        "=" * 39,
        f"File: {header['file']}",
        f"Size: {header['size_bytes']:,} bytes",
        f"Berkeley DB version: {header['bdb_version']}",
        f"Byte order: {header['byte_order']}",
        f"Page size: {header['page_size']:,} bytes",
        f"Wallet tree root: page {header['wallet_root_page']}",
        "Encrypted wallet records detected: " + str(report["encryption"]["wallet_encrypted"]),
        "",
        "Pages by type:",
    ]
    for kind, count in sorted(report["page_counts_by_type"].items()):
        name = report["page_type_names"].get(kind, "unknown page type")
        lines.append(f"  type {kind} ({name}): {count}")
    lines.extend(["", "Records by type:"])
    for kind, count in report["record_counts_by_type"].items():
        lines.append(f"  {kind}: {count}")
    lines.extend(["", "Decode outcomes:"])
    for status, count in report["decode_counts"].items():
        lines.append(f"  {status}: {count}")
    lines.extend([
        "",
        "Transparent addresses:",
        *(
            [f"  {address}" for address in report["transparent_addresses"]]
            or ["  none derived"]
        ),
        "",
        "Shielded addresses:",
    ])
    for shielded_type, addresses in report["shielded_addresses_by_type"].items():
        key_count = report["shielded_key_record_counts"][shielded_type]
        lines.append(f"  {shielded_type} ({key_count} key records):")
        lines.extend(f"    {address}" for address in addresses)
        if not addresses:
            lines.append("    none found")
    lines.extend([
        "",
        "Security: private keys, encrypted secrets, and seed material are redacted from reports.",
        "Separate WIF export count: "
        + str(report["security"]["wif_export_count"]),
        "Separate shielded-key export count: "
        + str(report["security"]["shielded_key_export_count"]),
        "Sapling cryptographic validation enabled: "
        + str(report["security"]["sapling_crypto_validation_enabled"]),
        "Sapling key records cryptographically validated: "
        + str(report["security"]["sapling_crypto_validated_count"]),
        "Encryption: master-key metadata is parsed; password-based decryption is not implemented.",
        "All extracted records fully decoded: "
        + str(report["validation"]["all_extracted_wallet_records_fully_decoded"]),
        "Failed or incomplete record decodes: "
        + str(report["failed_or_incomplete_record_decodes"]),
        "Decoder complete for all BitcoinZ variants: false",
    ])
    if report["unsupported_page_types"]:
        lines.extend([
            "",
            "Page types not decoded:",
            *[f"  type {kind}: {report['page_counts_by_type'][kind]}" for kind in report["unsupported_page_types"]],
        ])
    if report["unsupported_or_partial_record_types"]:
        lines.extend([
            "",
            "Unsupported or partially decoded record types:",
            *[f"  {kind}" for kind in report["unsupported_or_partial_record_types"]],
        ])
    if report["limitations"]:
        lines.extend(["", "Limitations:", *[f"  {item}" for item in report["limitations"]]])
    if report["errors"]:
        lines.extend(["", "Errors:"])
        lines.extend(f"  {e.get('kind', 'error')}: {e.get('message', 'Unknown error')}" for e in report["errors"])
    if report["warnings"]:
        lines.extend(["", "Warnings:", *[f"  {warning}" for warning in report["warnings"]]])
    lines.append("")
    return "\n".join(lines)


def write_reports(report: dict[str, Any], json_path: str | Path,
                  text_path: str | Path, input_path: str | Path) -> None:
    source = Path(input_path).resolve()
    targets = [Path(json_path).resolve(), Path(text_path).resolve()]
    if targets[0] == targets[1]:
        raise ValueError("JSON and text report paths must be different.")
    if source in targets:
        raise ValueError("Report path must not be the wallet input file.")
    json_path = Path(json_path)
    text_path = Path(text_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    text_path.write_text(render_text(report), encoding="utf-8")


def write_wif_export(
    entries: list[tuple[str, str]],
    export_path: str | Path,
    input_path: str | Path,
    report_paths: tuple[str | Path, str | Path],
) -> None:
    """Write explicitly requested WIFs to a new, separate file without overwriting."""
    path = Path(export_path).resolve()
    protected_paths = {
        Path(input_path).resolve(),
        *(Path(item).resolve() for item in report_paths),
    }
    if path in protected_paths:
        raise ValueError("WIF export path must differ from the wallet and report files.")
    if not entries:
        raise ValueError("No validated unencrypted private keys are available to export.")

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        output = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
    except OSError:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    try:
        with output:
            writer = csv.writer(output)
            writer.writerow(("address", "private_key_wif"))
            writer.writerows(entries)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def write_shielded_export(
    entries: list[tuple[str, str, str, str, str, str]],
    export_path: str | Path,
    input_path: str | Path,
    report_paths: tuple[str | Path, str | Path],
) -> None:
    """Write requested shielded spending keys to a new plaintext CSV."""
    path = Path(export_path).resolve()
    protected_paths = {
        Path(input_path).resolve(),
        *(Path(item).resolve() for item in report_paths),
    }
    if path in protected_paths:
        raise ValueError("Shielded export path must differ from the wallet and report files.")
    if not entries:
        raise ValueError("No supported unencrypted shielded spending keys are available to export.")

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        output = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
    except OSError:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    try:
        with output:
            writer = csv.writer(output)
            writer.writerow(
                (
                    "type",
                    "address",
                    "derived_address",
                    "key_format",
                    "key_validation",
                    "spending_key",
                )
            )
            writer.writerows(entries)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
