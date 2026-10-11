# ZWallet Tools

**ZWallet Tools** is a native-Python, read-only decoder for BitcoinZ Core `wallet.dat` files. It parses Berkeley DB wallet records, derives transparent addresses, identifies shielded wallet data, validates supported key records, and generates JSON and text reports.

- Native Python implementation with no third-party Python dependencies.
- Supports Windows, Linux, and macOS.
- Accepts custom paths for wallet files, reports, and exports.
- Redacts private keys from reports and console output by default.
- Supports explicitly requested exports of supported unencrypted private and shielded spending keys.

> **Security:** Exported private keys and shielded spending keys are plaintext secrets. Keep them secure and never share them with untrusted parties.

## Requirements

- Python 3.10 or newer.
- The standard library's RIPEMD-160 implementation must be available for transparent address derivation.

## Installation

Clone or download the repository and open a terminal in the project directory.

### Windows (PowerShell)

Create a virtual environment:

```powershell
py -3 -m venv env
```

Run the decoder:

```powershell
.\env\Scripts\python.exe start.py wallet.dat
```

Run the tests:

```powershell
.\env\Scripts\python.exe -m unittest discover -s tests -v
```

### Linux

Create a virtual environment:

```bash
python3 -m venv env
```

Run the decoder:

```bash
./env/bin/python start.py wallet.dat
```

Run the tests:

```bash
./env/bin/python -m unittest discover -s tests -v
```

### macOS

Create a virtual environment:

```bash
python3 -m venv env
```

Run the decoder:

```bash
./env/bin/python start.py wallet.dat
```

Run the tests:

```bash
./env/bin/python -m unittest discover -s tests -v
```

## Usage

### Decode a wallet

By default, the decoder reads `wallet.dat` from the current directory and writes `wallet_report.json` and `wallet_report.txt`.

```bash
python start.py
```

Specify a wallet file:

```bash
python start.py wallet.dat
```

### Use custom paths

You can specify absolute or relative paths for the wallet, JSON report, and text report.

**Windows (PowerShell):**

```powershell
.\env\Scripts\python.exe start.py "D:\Wallets\wallet.dat" --json "D:\Reports\wallet.json" --text "D:\Reports\wallet.txt"
```

**Linux:**

```bash
./env/bin/python start.py "/home/user/wallets/wallet.dat" --json "/home/user/reports/wallet.json" --text "/home/user/reports/wallet.txt"
```

**macOS:**

```bash
./env/bin/python start.py "/Users/user/Wallets/wallet.dat" --json "/Users/user/Reports/wallet.json" --text "/Users/user/Reports/wallet.txt"
```

Output directories must already exist. The wallet, report, and export paths must be different.

### Export transparent private keys

```bash
python start.py wallet.dat --export-wif private-keys.csv
```

Exports supported, validated, unencrypted private-key records as BitcoinZ WIF plus address to a new plaintext CSV file.

Custom export path:

```bash
python start.py "D:\Wallets\wallet.dat" --export-wif "D:\Exports\private-keys.csv"
```

Existing export files are never overwritten. Encrypted keys cannot be exported because password-based decryption is not implemented.

### Export shielded spending keys

```bash
python start.py wallet.dat --export-shielded shielded-keys.csv
```

Exports supported, unencrypted shielded spending keys:

- Sprout spending keys in BitcoinZ `SK...` Base58Check format.
- Sapling ZIP32 extended spending keys in Bech32 form.

The export is plaintext and is created only when explicitly requested.

### Validate Sapling keys and derive addresses

```bash
python start.py wallet.dat --validate-shielded
```

This enables pure-Python Sapling ZIP32 key validation, external and internal viewing-key derivation, incoming viewing-key matching, and derivation of a default Sapling payment address when possible.

To include validation results and derived addresses in a shielded-key export:

```bash
python start.py wallet.dat --validate-shielded --export-shielded shielded-keys.csv
```

Validation results are reported separately from stored addresses. Spending keys remain redacted from reports and console output.

## Command-line options

| Option | Description |
|---|---|
| `wallet` | Input wallet path. Defaults to `wallet.dat`. |
| `--json PATH` | JSON report output path. |
| `--text PATH` | Text report output path. |
| `--export-wif PATH` | Explicitly export supported unencrypted transparent private keys. |
| `--export-shielded PATH` | Explicitly export supported unencrypted shielded spending keys. |
| `--validate-shielded` | Enable Sapling key validation and default-address derivation. |

## Implemented features

### Berkeley DB parsing

- Database metadata, byte order, page size, and named `main` database.
- B-tree internal and leaf pages.
- Duplicate pages, overflow chains, and leaf links.
- Validation of page boundaries, references, record lengths, and overflow-chain lengths.

### BitcoinZ wallet records

- Transparent key and encrypted-key records.
- Master-key records and key metadata.
- Keypool and address-book records.
- Transactions and transaction metadata.
- Scripts and watch-only records.
- HD chain/seed records, version, block locator, flags, and numeric records.

### Transaction decoding

- BitcoinZ legacy transaction format.
- Overwinter v3 transaction format.
- Sapling v4 transaction format.
- Transaction ID verification against database keys.

### Key and address validation

- secp256k1 public-key point checks.
- BitcoinZ transparent-address derivation.
- Private-key DER envelope and record-checksum validation without returning private-key bytes.
- Sprout and Sapling shielded address recognition.
- Optional Sapling ZIP32 validation and default-address derivation.

### Reports and exports

- JSON and human-readable text reports.
- Secret redaction by default.
- Separate CSV exports for supported unencrypted transparent and shielded spending keys.
- Reporting of unknown, malformed, unsupported, partially decoded, and redacted records.

## Security considerations

- The source wallet is opened in read-only mode.
- Reports and exports must use separate paths from the wallet input.
- Private keys remain redacted unless an export is explicitly requested.
- Exported WIF and shielded spending keys are plaintext secrets.
- Existing export files are never overwritten.
- Encrypted keys cannot be exported; password-based master-key derivation, AES decryption, and decrypted-key verification are not implemented.
- Sapling validation uses variable-time big-integer arithmetic and must not be used for signing or other operations requiring constant-time cryptography.
- Berkeley DB page checksums are not verified.
- Transparent address derivation depends on RIPEMD-160 being available in the Python runtime.

Use a copy of your wallet for testing and store any exported keys securely.

## Known limitations

- Password-based decryption of encrypted wallet keys is not supported.
- Non-empty Sprout/Sapling note-witness maps in wallet transaction metadata are not implemented.
- Berkeley DB page checksums are not verified.
- Not every BitcoinZ wallet version or record variant is guaranteed to be supported.

The report's `all_extracted_wallet_records_fully_decoded` field refers only to records actually extracted from the wallet tree. It does not imply support for every BitcoinZ wallet variant.

## BitcoinZ Core references

The BitcoinZ-specific serialization and encoding definitions are based on the following BitcoinZ Core source files:

- [`walletdb.h`](https://github.com/btcz/bitcoinz/blob/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/wallet/walletdb.h)
- [`wallet.h`](https://github.com/btcz/bitcoinz/blob/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/wallet/wallet.h)
- [`transaction.h`](https://github.com/btcz/bitcoinz/blob/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/primitives/transaction.h)
- [`chainparams.cpp`](https://github.com/btcz/bitcoinz/blob/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/chainparams.cpp)
- [`key_io.cpp`](https://github.com/btcz/bitcoinz/blob/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/key_io.cpp)
- [Zcash address serializers](https://github.com/btcz/bitcoinz/tree/f9047533ebabb971b92b5103efd9fdbe9eb5c3fb/src/zcash/address)

## Disclaimer

ZWallet Tools is intended for offline wallet inspection, decoding, and validation. It is not a signing tool and does not guarantee complete compatibility with every BitcoinZ Core wallet variant.

Always verify important recovery information independently before relying on it.

---

**ZWallet Tools — Read-only BitcoinZ wallet inspection, built with native Python.**
