# D1 — Memory Forensics Toolkit

Memory dump parsing: byte-level string carving, PE header carving, process carving, known-bad string detection, timeline.

## IMPORTANT: Read before use.

This tool is for **authorized educational and blue-team analysis only**. Analyze memory dumps only from systems you own or are explicitly permitted to examine. The bundled fixture is synthetic; no personal data. All example IPs are RFC 5737 documentation addresses.

## Features

- **Real string carving**: byte-scanning any binary blob for printable ASCII strings (works on any provided memdump)
- **PE carving**: locate `MZ` + `PE\0\0` headers, extract machine/timestamp
- **Process carving**: 
  - documented synthetic `PROC` record format (see below)
  - Windows EPROCESS-style scan using kernel offsets (for real-ish dumps)
  - PID plausibility + printable-name validation
- **Known-bad string detection**: mimikatz, cmd.exe, powershell, certutil, reverse shells, etc.
- **Hash calculation**: MD5 / SHA1 / SHA256
- **Timeline**: PE compile-time ordering
- **JSON report output**

## Documented Synthetic Fixture Format

`tests/fixtures/memdump.bin` is a 256 KiB deterministic binary blob containing:

| Offset | Content |
|--------|---------|
| `0x200` | printable ASCII string region (carvable) |
| `0x10000`, `0x18000` | `MZ` + `PE\0\0` headers (x64, timestamps) |
| `0x30000`, `0x31000`, `0x32000` | process records: `PROC` + u32 PID + 16-byte name |
| `0x40000` | known-bad strings (mimikatz, cmd.exe, ...) |

Regenerate with `python3 tests/generate_fixtures.py`.

## Quick Start

```bash
# Analyze the bundled synthetic memdump
python3 cli.py --demo

# Analyze any memory dump you own
python3 cli.py --dump /path/to/dump.raw --output reports/report.json

# Carve strings only from any binary
python3 cli.py --dump /path/to/dump.raw --strings
```

## Testing

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `python3 cli.py --demo` — should exit 0, print process list incl. `malware.exe` PID 1234
2. Run `python3 -m unittest discover -s tests` — all tests pass
3. Verify `reports/d1_report.json` contains hashes, executables, processes, bad strings

## Metrics

- Parsing methods: string carving (bytes), PE carving, process carving (synthetic + EPROCESS)
- Known-bad patterns scanned: ~35
- Test count: 16
- Demo exit code: 0

## License

MIT License — see [LICENSE](LICENSE).
