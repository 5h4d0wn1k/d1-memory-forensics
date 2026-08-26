#!/usr/bin/env python3
"""
D1 — Memory Forensics Toolkit
Parses memory dumps, extracts processes, finds network connections, detects malware indicators.
"""

import struct
import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict


class MemoryForensics:
    """Core memory forensics engine using struct for binary parsing."""

    # Windows kernel process offsets (x64 Windows 10/11)
    EPROCESS_IMAGE_NAME_OFFSET = 0x5A8
    EPROCESS_UNIQUE_PID_OFFSET = 0x440
    EPROCESS_ACTIVE_OFFSET = 0x2E0
    EPROCESS_PEB_OFFSET = 0x450
    EPROCESS_CREATE_DATE_OFFSET = 0x448

    # PE header magic
    PE_MAGIC = b"MZ"
    PE_SIGNATURE = b"PE\x00\x00"

    def __init__(self, dump_path: str):
        self.dump_path = dump_path
        self.data = None
        self.processes = []
        self.network_connections = []
        self.suspicious_indicators = []
        self.file_size = 0

    def load_dump(self) -> bool:
        """Load a memory dump file into memory."""
        if not os.path.exists(self.dump_path):
            print(f"[ERROR] File not found: {self.dump_path}")
            return False
        self.file_size = os.path.getsize(self.dump_path)
        if self.file_size == 0:
            print(f"[ERROR] File is empty: {self.dump_path}")
            return False
        with open(self.dump_path, "rb") as f:
            self.data = f.read()
        print(f"[+] Loaded memory dump: {self.dump_path} ({self.file_size:,} bytes)")
        return True

    def calculate_hashes(self) -> dict:
        """Calculate MD5, SHA1, SHA256 of the memory dump."""
        hashes = {}
        for algo_name, algo in [("md5", hashlib.md5), ("sha1", hashlib.sha1), ("sha256", hashlib.sha256)]:
            h = algo()
            h.update(self.data)
            hashes[algo_name] = h.hexdigest()
        return hashes

    def scan_pe_executables(self, max_scan: int = 100000) -> list:
        """Scan for PE (Portable Executable) headers in memory."""
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
                    machine = struct.unpack_from("<H", self.data, pe_sig_pos + 4 + 2)[0]
                    timestamp = struct.unpack_from("<I", self.data, pe_sig_pos + 4 + 8)[0]
                    exe_name = self._extract_string_at(pos, 64)
                    executables.append({
                        "offset": pos,
                        "pe_offset": pe_offset,
                        "machine": f"0x{machine:04x}",
                        "timestamp": timestamp,
                        "name": exe_name,
                        "md5": hashlib.md5(self.data[pos:pos + 0x200]).hexdigest()
                    })
                except (struct.error, IndexError):
                    pass
            offset = pos + 1
            if len(executables) >= 50:
                break
        return executables

    def scan_strings(self, min_length: int = 6, max_results: int = 500) -> list:
        """Extract printable ASCII strings from memory."""
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

    def detect_suspicious_strings(self) -> list:
        """Find suspicious/malware-related strings in memory."""
        suspicious_patterns = [
            b"cmd.exe", b"/bin/sh", b"/bin/bash", b"powershell",
            b"mimikatz", b"psexec", b"lateral movement", b"payload",
            b"reverse shell", b"keylog", b"credential", b"password",
            b"ntlm", b"hash dump", b"kerberos", b"ticket",
            b"reg save", b"sam", b"system", b"security",
            b"certutil", b"bitsadmin", b"mshta", b"wmic",
            b"base64", b"eval(", b"exec(", b"system(",
            b"nc -e", b"netcat", b"socat", b"bash -i",
        ]
        findings = []
        for pattern in suspicious_patterns:
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

    def scan_kernel_objects(self) -> list:
        """Scan for potential kernel object signatures."""
        kernel_signatures = [
            (b"\xe8\x00\x00\x00\x00\x5b\x48\x8d\x05", "Kernel call pattern"),
            (b"\x48\x89\x5c\x24", "Windows x64 function prologue"),
            (b"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", "INT3 padding (debug)"),
        ]
        results = []
        for sig, desc in kernel_signatures:
            offset = 0
            count = 0
            while count < 20:
                pos = self.data.find(sig, offset)
                if pos == -1:
                    break
                results.append({"offset": pos, "type": desc})
                offset = pos + len(sig)
                count += 1
        return results

    def parse_windows_processes(self) -> list:
        """Parse Windows EPROCESS structures to extract process list."""
        processes = []
        eprocess_sig = b"\x03\x00\x00\x00\x04\x00\x00\x00"
        offset = 0
        while len(processes) < 100:
            pos = self.data.find(eprocess_sig, offset)
            if pos == -1 or pos > len(self.data) - 0x600:
                break
            try:
                pid = struct.unpack_from("<I", self.data, pos + self.EPROCESS_UNIQUE_PID_OFFSET)[0]
                if 0 < pid < 100000:
                    name_bytes = self.data[pos + self.EPROCESS_IMAGE_NAME_OFFSET:pos + self.EPROCESS_IMAGE_NAME_OFFSET + 16]
                    name = name_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
                    if name:
                        processes.append({
                            "pid": pid,
                            "name": name,
                            "eprocess_offset": pos,
                        })
            except (struct.error, IndexError):
                pass
            offset = pos + 1
            if len(processes) >= 50:
                break
        return processes

    def detect_network_connections(self) -> list:
        """Scan for network connection structures in memory."""
        connections = []
        tcp_sig = b"\x02\x00\x00\x00"
        udp_sig = b"\x11\x00\x00\x00"
        for sig, proto in [(tcp_sig, "TCP"), (udp_sig, "UDP")]:
            offset = 0
            count = 0
            while count < 20:
                pos = self.data.find(sig, offset)
                if pos == -1 or pos > len(self.data) - 0x100:
                    break
                try:
                    port_raw = struct.unpack_from(">H", self.data, pos + 2)[0]
                    ip_raw = struct.unpack_from(">I", self.data, pos + 4)[0]
                    ip_str = f"{(ip_raw >> 24) & 0xff}.{(ip_raw >> 16) & 0xff}.{(ip_raw >> 8) & 0xff}.{ip_raw & 0xff}"
                    connections.append({
                        "protocol": proto,
                        "port": port_raw,
                        "ip": ip_str,
                        "offset": pos,
                    })
                except (struct.error, IndexError):
                    pass
                offset = pos + len(sig)
                count += 1
        return connections

    def analyze_timeline(self) -> dict:
        """Extract timestamp information from memory for timeline analysis."""
        timestamps = []
        pe_executables = self.scan_pe_executables()
        for exe in pe_executables:
            if exe["timestamp"] > 0:
                try:
                    dt = datetime.utcfromtimestamp(exe["timestamp"])
                    timestamps.append({
                        "type": "PE Compile Time",
                        "offset": exe["offset"],
                        "timestamp": dt.isoformat(),
                        "name": exe.get("name", "unknown"),
                    })
                except (ValueError, OSError):
                    pass
        timestamps.sort(key=lambda x: x["timestamp"])
        return {
            "earliest": timestamps[0]["timestamp"] if timestamps else None,
            "latest": timestamps[-1]["timestamp"] if timestamps else None,
            "events": timestamps[:20],
        }

    def full_analysis(self) -> dict:
        """Run complete memory forensics analysis."""
        if self.data is None:
            if not self.load_dump():
                return {}

        print("[*] Running memory forensics analysis...")
        print("[*] Calculating file hashes...")
        hashes = self.calculate_hashes()

        print("[*] Scanning for PE executables...")
        executables = self.scan_pe_executables()

        print("[*] Extracting strings...")
        strings = self.scan_strings()

        print("[*] Detecting suspicious patterns...")
        suspicious = self.detect_suspicious_strings()

        print("[*] Scanning kernel objects...")
        kernel = self.scan_kernel_objects()

        print("[*] Parsing process list...")
        processes = self.parse_windows_processes()

        print("[*] Detecting network connections...")
        connections = self.detect_network_connections()

        print("[*] Building timeline...")
        timeline = self.analyze_timeline()

        self.processes = processes
        self.network_connections = connections
        self.suspicious_indicators = suspicious

        result = {
            "file": self.dump_path,
            "size": self.file_size,
            "hashes": hashes,
            "executables": executables,
            "suspicious_strings": suspicious,
            "kernel_objects": kernel,
            "processes": processes,
            "network_connections": connections,
            "timeline": timeline,
            "strings_count": len(strings),
        }

        self._print_summary(result)
        return result

    def export_json(self, output_path: str):
        """Export analysis results to JSON."""
        result = self.full_analysis()
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Results exported to {output_path}")

    def _extract_string_at(self, offset: int, max_len: int) -> str:
        """Extract a printable string starting at offset."""
        result = []
        for i in range(offset, min(offset + max_len, len(self.data))):
            byte = self.data[i]
            if 32 <= byte < 127:
                result.append(chr(byte))
            else:
                break
        return "".join(result)

    def _print_summary(self, result: dict):
        """Print analysis summary."""
        print("\n" + "=" * 60)
        print("  D1 — Memory Forensics Toolkit — Analysis Report")
        print("=" * 60)
        print(f"  File: {result['file']}")
        print(f"  Size: {result['size']:,} bytes")
        print(f"  MD5:  {result['hashes'].get('md5', 'N/A')}")
        print(f"  SHA1: {result['hashes'].get('sha1', 'N/A')}")
        print(f"\n  PE Executables Found:  {len(result['executables'])}")
        print(f"  Suspicious Strings:   {len(result['suspicious_strings'])}")
        print(f"  Kernel Objects:       {len(result['kernel_objects'])}")
        print(f"  Processes Detected:   {len(result['processes'])}")
        print(f"  Network Connections:  {len(result['network_connections'])}")
        if result["timeline"]["earliest"]:
            print(f"\n  Timeline: {result['timeline']['earliest']} to {result['timeline']['latest']}")
        if result["suspicious_strings"]:
            print("\n  --- Suspicious Findings ---")
            for s in result["suspicious_strings"][:10]:
                print(f"    [!] \"{s['pattern']}\" at offset 0x{s['offset']:x}")
                if s["context"]:
                    print(f"        Context: ...{s['context']}...")
        if result["processes"]:
            print("\n  --- Process List ---")
            for p in result["processes"][:10]:
                print(f"    PID {p['pid']:>6}: {p['name']}")
        print("=" * 60)

    def generate_test_dump(self, output_path: str, size: int = 1024 * 1024):
        """Generate a synthetic test memory dump for testing."""
        print(f"[*] Generating test memory dump ({size:,} bytes)...")
        data = bytearray(size)
        # Populate with random-ish data
        import random
        random.seed(42)
        for i in range(0, size, 4):
            val = random.getrandbits(32)
            struct.pack_into("<I", data, i, val)

        # Embed PE headers
        pe_offset = 0x1000
        data[pe_offset:pe_offset + 2] = b"MZ"
        pe_sig = pe_offset + 0x80
        data[pe_sig:pe_sig + 4] = b"PE\x00\x00"
        struct.pack_into("<H", data, pe_sig + 4, 0x8664)  # x64
        struct.pack_into("<I", data, pe_sig + 8, 0x60000000)  # timestamp

        # Embed suspicious strings
        suspicious_strings = [
            b"cmd.exe /c whoami", b"mimikatz", b"reverse shell",
            b"powershell -enc", b"certutil -urlcache",
            b"/bin/bash -i", b"password", b"credential dump",
        ]
        offset = 0x5000
        for s in suspicious_strings:
            data[offset:offset + len(s)] = s
            offset += 0x200

        # Embed EPROCESS-like signatures
        eprocess_sig = b"\x03\x00\x00\x00\x04\x00\x00\x00"
        ep_offset = 0x8000
        data[ep_offset:ep_offset + len(eprocess_sig)] = eprocess_sig
        struct.pack_into("<I", data, ep_offset + 0x440, 1234)  # PID
        name = b"malware.exe\x00"
        data[ep_offset + 0x5A8:ep_offset + 0x5A8 + len(name)] = name

        with open(output_path, "wb") as f:
            f.write(data)
        print(f"[+] Test dump written: {output_path}")
        return output_path


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="D1 — Memory Forensics Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 mem_forensics.py --dump memory.raw --output report.json"
    )
    parser.add_argument("--dump", "-d", help="Path to memory dump file")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument("--generate-test", "-g", help="Generate a test memory dump", metavar="PATH")
    parser.add_argument("--strings", "-s", action="store_true", help="Extract strings only")
    parser.add_argument("--hash", action="store_true", help="Calculate file hashes only")
    args = parser.parse_args()

    if args.generate_test:
        forensics = MemoryForensics(args.generate_test)
        forensics.generate_test_dump(args.generate_test)
        forensics.load_dump()
        forensics.full_analysis()
        return

    if not args.dump:
        parser.print_help()
        sys.exit(1)

    forensics = MemoryForensics(args.dump)

    if args.hash:
        forensics.load_dump()
        hashes = forensics.calculate_hashes()
        for algo, digest in hashes.items():
            print(f"  {algo.upper():>8}: {digest}")
        return

    if args.strings:
        forensics.load_dump()
        strings = forensics.scan_strings(min_length=8, max_results=100)
        for s in strings:
            print(f"  0x{s['offset']:08x}: {s['text']}")
        return

    if args.output:
        forensics.export_json(args.output)
    else:
        forensics.full_analysis()


if __name__ == "__main__":
    main()
