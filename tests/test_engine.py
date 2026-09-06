#!/usr/bin/env python3
"""Tests for D1 Memory Forensics."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from mem_forensics import MemoryForensics

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "memdump.bin")


class TestLoad(unittest.TestCase):
    def test_load(self):
        mf = MemoryForensics(FIXTURE)
        self.assertTrue(mf.load_dump())
        self.assertGreater(mf.file_size, 0)
        self.assertIsNotNone(mf.data)


class TestStringCarving(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mf = MemoryForensics(FIXTURE)
        cls.mf.load_dump()
        cls.strings = cls.mf.scan_strings(min_length=6)

    def test_strings_found(self):
        self.assertGreater(len(self.strings), 0)

    def test_known_string_present(self):
        texts = [s["text"] for s in self.strings]
        self.assertTrue(any("synthetic memory sample" in t for t in texts))
        self.assertTrue(any("reverse shell established" in t for t in texts))


class TestSuspiciousStrings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mf = MemoryForensics(FIXTURE)
        cls.mf.load_dump()
        cls.findings = cls.mf.detect_suspicious_strings()

    def test_findings_present(self):
        self.assertGreater(len(self.findings), 0)

    def test_mimikatz_found(self):
        patterns = [f["pattern"] for f in self.findings]
        self.assertIn("mimikatz", patterns)
        self.assertIn("cmd.exe", patterns)
        self.assertIn("powershell", patterns)


class TestCarveProcesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mf = MemoryForensics(FIXTURE)
        cls.mf.load_dump()
        cls.procs = cls.mf.carve_processes()

    def test_processes_found(self):
        self.assertGreaterEqual(len(self.procs), 3)

    def test_known_processes(self):
        names = [p["name"] for p in self.procs]
        self.assertIn("System", names)
        self.assertIn("malware.exe", names)
        self.assertIn("winlogon.exe", names)

    def test_pid_malware(self):
        malware = [p for p in self.procs if p["name"] == "malware.exe"]
        self.assertEqual(malware[0]["pid"], 1234)

    def test_offsets_recorded(self):
        for p in self.procs:
            self.assertGreater(p["offset"], 0)


class TestScanPE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mf = MemoryForensics(FIXTURE)
        cls.mf.load_dump()
        cls.pexes = cls.mf.scan_pe_executables()

    def test_pe_found(self):
        self.assertGreaterEqual(len(self.pexes), 2)

    def test_pe_fields(self):
        x64 = [exe for exe in self.pexes if exe["machine"] == "0x8664"]
        self.assertGreaterEqual(len(x64), 1)
        for exe in self.pexes:
            self.assertIn("machine", exe)
            self.assertIn("timestamp", exe)


class TestHashes(unittest.TestCase):
    def test_hashes_deterministic(self):
        mf = MemoryForensics(FIXTURE)
        mf.load_dump()
        h1 = mf.calculate_hashes()
        self.assertEqual(len(h1["md5"]), 32)
        self.assertEqual(len(h1["sha256"]), 64)


class TestPlausible(unittest.TestCase):
    def test_invalid_pid(self):
        mf = MemoryForensics(FIXTURE)
        mf.load_dump()
        self.assertFalse(mf._plausible_process(0, b"name"))
        self.assertFalse(mf._plausible_process(999999, b"name"))

    def test_invalid_name(self):
        mf = MemoryForensics(FIXTURE)
        mf.load_dump()
        self.assertFalse(mf._plausible_process(1234, b""))
        self.assertFalse(mf._plausible_process(1234, b"a\xffb"))


class TestTimeline(unittest.TestCase):
    def test_timeline(self):
        mf = MemoryForensics(FIXTURE)
        mf.load_dump()
        tl = mf.analyze_timeline()
        self.assertIsNotNone(tl["earliest"])
        self.assertEqual(len(tl["events"]), 2)
        self.assertLessEqual(tl["earliest"], tl["latest"])


class TestCLIHelp(unittest.TestCase):
    def test_help_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--demo"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Memory Forensics", r.stdout)
        self.assertIn("malware.exe", r.stdout)


if __name__ == "__main__":
    unittest.main()
