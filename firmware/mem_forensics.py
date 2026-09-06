#!/usr/bin/env python3
"""
D1 — Memory Forensics Toolkit
Parses memory dumps, carves processes/strings, detects known-bad strings, builds timeline.
"""

import struct
import os
import sys
import json
import hashlib
from datetime import datetime
from collections import defaultdict


class MemoryForensics:
    """Core memory forensics engine using struct for binary parsing."""

    # Windows kernel process offsets (x64 Windows 10/11) for EPROCESS-style carving
    EPROCESS_IMAGE_NAME_OFFSET = 0x5A8
    EPROCESS_UNIQUE_PID_OFFSET = 0x440

    # Fixture document record signature: 'PROC' at +0, PID (u32) at +4, 16-byte name at +8
    SYNT_PROC_SIG = b"PROC"

    PE_MAGIC = b"MZ"
    PE_SIGNATURE = b"PE\x00\x00"

    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.data = None
        self.file_size = 0

    def load_dump(self):
        if not os.path.exists(self.dump_path):
            raise FileNotFoundError(self.dump_path)
        self.file_size = os.path.getsize(self.dump_path)
        if self.file_size == 0:
            raise ValueError("Empty memory dump")
        with open(self.dump_path, "rb") as f:
            self.data = f.read()
        return True

    def calculate_hashes(self):
        out = {}
        for name, algo in [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)]:
            h = algo()
            h.update(self.data)
            out[name] = h.hexdigest()
        return out

    def scan_pe_executables(self, max_scan=100000):
        executables = []
        offset = 0
        scan_limit = min(len(self.data), max_scan)
        while offset < scan_limit:
            pos = self.data.find(self.PE_MAGIC, offset)
            if pos == -1:
                break
            pe_sig_pos = self.data.find(self.PE_SIGNATURE, pos + 2, pos + 0x200)
            if pe_sig_pos != -1:
                try:
                    pe_offset = struct.unpack_from("<I", self.data, pe_sig_pos + 4)[0]
                    machine = struct.unpack_from("<H", self.data, pe_sig_pos + 4)[0]
                    timestamp = struct.unpack_from("<I", self.data, pe_sig_pos + 8)[0]
                    name = self._extract_string_at(pos, 32)
                    executables.append({
                        "offset": pos,
                        "pe_offset": pe_offset,
                        "machine": "0x%04x" % machine,
                        "timestamp": timestamp,
                        "name": name,
                        "md5": hashlib.md5(self.data[pos:pos + 0x200]).hexdigest(),
                    })
                except (struct.error, IndexError):
                    pass
            offset = pos + 1
            if len(executables) >= 50:
                break
        return executables

    def scan_strings(self, min_length=6, max_results=2000):
        """Real byte-scanning string carver: works on any binary blob."""
        strings = []
        current = []
        start = 0
        for i, byte in enumerate(self.data):
            if 32 <= byte < 127:
                if not current:
                    start = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append({"offset": start, "text": "".join(current)})
                current = []
                if len(strings) >= max_results:
                    break
        return strings

    def detect_suspicious_strings(self):
        patterns = [
            b"cmd.exe", b"/bin/sh", b"/bin/bash", b"powershell",
            b"mimikatz", b"psexec", b"lateral movement", b"payload",
            b"reverse shell", b"keylog", b"credential", b"password",
            b"ntlm", b"hash dump", b"kerberos", b"ticket",
            b"reg save", b"certutil", b"bitsadmin", b"mshta", b"wmic",
            b"base64", b"eval(", b"exec(", b"system(",
            b"nc -e", b"netcat", b"socat", b"bash -i",
        ]
        findings = []
        for pattern in patterns:
            offset = 0
            while True:
                pos = self.data.find(pattern, offset)
                if pos == -1:
                    break
                context = self._extract_string_at(max(0, pos - 20), 80)
                findings.append({
                    "pattern": pattern.decode("utf-8", errors="replace"),
                    "offset": pos,
                    "context": context,
                })
                offset = pos + 1
                if len(findings) > 200:
                    break
        return findings

    def carve_processes(self):
        """Carve processes.

        Two sources are supported:
          1. The documented synthetic fixture record: b'PROC' + u32 PID + 16-byte name.
          2. A Windows-style EPROCESS scan using kernel offsets on real-ish dumps.
        A process is only accepted if the PID is plausible (1..65535) and the
        image name contains printable characters.
        """
        processes = {}

        # 1. Synthetic documented format
        offset = 0
        while True:
            pos = self.data.find(self.SYNT_PROC_SIG, offset)
            if pos == -1:
                break
            try:
                pid = struct.unpack_from("<I", self.data, pos + 4)[0]
                name = self.data[pos + 8:pos + 8 + 16].split(b"\x00")[0]
                if self._plausible_process(pid, name):
                    processes[pos] = {"pid": pid, "name": name.decode("latin-1"), "offset": pos}
            except (struct.error, IndexError):
                pass
            offset = pos + 1

        # 2. EPROCESS-style scan
        eprocess_sig = b"\x03\x00\x00\x00\x04\x00\x00\x00"
        offset = 0
        while True:
            pos = self.data.find(eprocess_sig, offset)
            if pos == -1 or pos > len(self.data) - 0x600:
                break
            try:
                pid = struct.unpack_from("<I", self.data, pos + self.EPROCESS_UNIQUE_PID_OFFSET)[0]
                name = self.data[pos + self.EPROCESS_IMAGE_NAME_OFFSET:
                                 pos + self.EPROCESS_IMAGE_NAME_OFFSET + 16].split(b"\x00")[0]
                if self._plausible_process(pid, name):
                    processes.setdefault(pos, {"pid": pid, "name": name.decode("latin-1", errors="replace"), "offset": pos})
            except (struct.error, IndexError):
                pass
            offset = pos + 1

        return sorted(processes.values(), key=lambda p: p["pid"])

    def _plausible_process(self, pid, name):
        if not 1 <= pid <= 65535:
            return False
        if not name:
            return False
        return all(32 <= b < 127 for b in name)

    def analyze_timeline(self):
        events = []
        for exe in self.scan_pe_executables():
            if exe["timestamp"] > 0:
                try:
                    dt = datetime.utcfromtimestamp(exe["timestamp"])
                    events.append({
                        "type": "PE Compile Time",
                        "offset": exe["offset"],
                        "timestamp": dt.isoformat(),
                        "name": exe.get("name", "unknown"),
                    })
                except (ValueError, OSError):
                    pass
        events.sort(key=lambda x: x["timestamp"])
        return {
            "earliest": events[0]["timestamp"] if events else None,
            "latest": events[-1]["timestamp"] if events else None,
            "events": events,
        }

    def _extract_string_at(self, offset, max_len):
        result = []
        for i in range(offset, min(offset + max_len, len(self.data))):
            b = self.data[i]
            if 32 <= b < 127:
                result.append(chr(b))
            else:
                break
        return "".join(result)

    def full_analysis(self):
        if self.data is None:
            self.load_dump()
        result = {
            "file": self.dump_path,
            "size": self.file_size,
            "hashes": self.calculate_hashes(),
            "executables": self.scan_pe_executables(),
            "suspicious_strings": self.detect_suspicious_strings(),
            "processes": self.carve_processes(),
            "timeline": self.analyze_timeline(),
            "strings_count": len(self.scan_strings()),
        }
        return result

    def _print_summary(self, result):
        print("=" * 60)
        print("  D1 — Memory Forensics Toolkit — Analysis Report")
        print("=" * 60)
        print("  File: %s" % result["file"])
        print("  Size: %d bytes" % result["size"])
        print("  MD5:  %s" % result["hashes"]["md5"])
        print("  PE Executables: %d" % len(result["executables"]))
        print("  Suspicious strings: %d" % len(result["suspicious_strings"]))
        print("  Processes carved: %d" % len(result["processes"]))
        print("  Carved strings: %d" % result["strings_count"])
        if result["processes"]:
            print("  --- Process List ---")
            for p in result["processes"]:
                print("    PID %6d: %s (0x%x)" % (p["pid"], p["name"], p["offset"]))
        if result["suspicious_strings"]:
            print("  --- Known-bad findings ---")
            for s in result["suspicious_strings"][:8]:
                print("    [%s] at 0x%x" % (s["pattern"], s["offset"]))
        if result["timeline"]["earliest"]:
            print("  Timeline: %s" % result["timeline"]["earliest"])
        print("=" * 60)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="D1 — Memory Forensics Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dump", "-d", help="Path to memory dump file")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument("--demo", action="store_true", help="Analyze built-in fixture")
    parser.add_argument("--strings", "-s", action="store_true", help="Extract strings only")
    args = parser.parse_args()

    if args.demo:
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        if os.path.basename(base) == "firmware":
            base = os.path.dirname(base)
        fixture = os.path.join(base, "tests", "fixtures", "memdump.bin")
        if not os.path.isfile(fixture):
            print("[ERROR] Fixture not found: %s" % fixture)
            sys.exit(1)
        mf = MemoryForensics(fixture)
        mf.load_dump()
        result = mf.full_analysis()
        out_dir = os.path.join(base, "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "d1_report.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        mf._print_summary(result)
        print("Report written to %s" % out_path)
        sys.exit(0)

    if not args.dump:
        parser.print_help()
        sys.exit(1)

    mf = MemoryForensics(args.dump)
    mf.load_dump()

    if args.strings:
        for s in mf.scan_strings(min_length=8):
            print("0x%08x: %s" % (s["offset"], s["text"]))
        sys.exit(0)

    result = mf.full_analysis()
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print("Report written to %s" % args.output)
    mf._print_summary(result)
    sys.exit(0)


if __name__ == "__main__":
    main()
