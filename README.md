> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# D1 — Memory Forensics Toolkit

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/d1-memory-forensics)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/d1-memory-forensics)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/d1-memory-forensics)

> **Memory forensics analyzer** — byte-level string carving, PE header carving,
> process carving, known-bad artifact detection, hashing, and timeline reports
> from RAM dumps, built for digital forensics and incident response education.

## Why

Malware lives in memory, so incident responders carve evidence straight out of
RAM dumps. D1 reconstructs the basics of that work in a single, dependency-free
tool: it byte-scans any binary blob for printable strings, locates `MZ`+`PE\0\0`
headers with machine type and compile timestamps, carves process records (both a
documented synthetic format and a Windows `EPROCESS`-style scan with kernel
offsets), and flags known-bad indicators such as `mimikatz`, `cmd.exe`, and
reverse-shell strings. It ships with a deterministic synthetic `memdump.bin`
fixture so the full pipeline can be practiced and tested offline before any real
— always authorized — analysis.

## Features

- **String carving** — extract printable ASCII strings from any binary blob.
- **PE carving** — locate `MZ` + `PE\0\0` headers; extract machine + timestamp.
- **Process carving** — synthetic `PROC` records and `EPROCESS`-style scans with
  PID/name validation.
- **Known-bad detection** — ~35 signatures (mimikatz, cmd.exe, powershell,
  certutil, reverse shells, and more).
- **Hashing** — MD5 / SHA-1 / SHA-256 of artifacts.
- **Timeline** — PE compile-time ordering and JSON report export.

## Quickstart

```bash
# Analyze the bundled synthetic memdump (exit 0)
python3 cli.py --demo

# Analyze any memory dump you own
python3 cli.py --dump /path/to/dump.raw --output reports/report.json

# Carve strings only
python3 cli.py --dump /path/to/dump.raw --strings
```

## Tests

```bash
python3 -m unittest discover -s tests
python3 tests/generate_fixtures.py   # regenerate the synthetic memdump.bin
```

The fixture is a 256 KiB deterministic blob holding carveable strings, PE
headers (`0x10000`, `0x18000`), `PROC` records (`0x30000`–`0x32000`), and
known-bad strings (`0x40000`).

## Project structure

```
cli.py                    # entry point (thin wrapper)
firmware/mem_forensics.py # carving + analysis engine
tests/                    # unit tests + fixture generator
ETHICS.md                 # ethics/authorized-use policy (read first)
SCOPE.md                  # defined assessment scope
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

Additional carving routines, artifact signatures, and report formats are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).