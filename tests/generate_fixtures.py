#!/usr/bin/env python3
"""Generate a deterministic synthetic memory dump fixture for D1 Memory Forensics.

Format: pure binary blob (documented) containing:
  - a small run of ASCII/printable strings (carved by the string extractor)
  - 'MZ' + PE header at known offsets (PE carving)
  - EPROCESS-like records at known offsets with PID + 16-byte image name
  - embedded known-bad strings
The format is documented so the parser's behavior is deterministic and testable.
"""
import os
import struct

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SIZE = 256 * 1024


def main():
    data = bytearray(SIZE)
    # Fill with a deterministic pseudo-random pattern (seeded) so scanning is reproducible.
    import random
    random.seed(7)
    for i in range(0, SIZE, 4):
        struct.pack_into("<I", data, i, random.getrandbits(32))

    # ---- ASCII string region (carvable) ----
    strings = [
        "Welcome to the synthetic memory sample",
        "srv.exe running with credentials",
        "reverse shell established on port 4444",
        "downloads payload to /tmp/beacon",
    ]
    off = 0x200
    for s in strings:
        data[off:off + len(s)] = s.encode("ascii")
        off += 0x80

    # ---- PE header carving targets ----
    pe_offsets = [0x10000, 0x18000]
    for idx, pe_off in enumerate(pe_offsets):
        data[pe_off:pe_off + 2] = b"MZ"
        pe_sig = pe_off + 0x40
        data[pe_sig:pe_sig + 4] = b"PE\x00\x00"
        struct.pack_into("<I", data, pe_sig + 4, 0x8664)          # machine x64
        struct.pack_into("<I", data, pe_sig + 8, 0x65000000 + idx)  # timestamp

    # ---- EPROCESS-like records ----
    # Each record: signature 'PROC', PID (u32), 16-byte image name.
    procs = [
        (0x30000, 4, b"System"),
        (0x31000, 432, b"winlogon.exe"),
        (0x32000, 1234, b"malware.exe"),
    ]
    for proc_off, pid, name in procs:
        data[proc_off:proc_off + 4] = b"PROC"
        struct.pack_into("<I", data, proc_off + 4, pid)
        padded = name.ljust(16, b"\x00")
        data[proc_off + 8:proc_off + 8 + 16] = padded

    # ---- known-bad strings ----
    bad = [
        b"cmd.exe /c whoami",
        b"mimikatz",
        b"powershell -enc",
        b"certutil -urlcache",
        b"/bin/bash -i",
    ]
    bad_off = 0x40000
    for s in bad:
        data[bad_off:bad_off + len(s)] = s
        bad_off += 0x100

    os.makedirs(FIXTURE_DIR, exist_ok=True)
    path = os.path.join(FIXTURE_DIR, "memdump.bin")
    with open(path, "wb") as f:
        f.write(data)
    print("Wrote %s (%d bytes)" % (path, SIZE))


if __name__ == "__main__":
    main()
