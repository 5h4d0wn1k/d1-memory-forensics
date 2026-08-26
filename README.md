# D1 — Memory Forensics Toolkit

Parses memory dumps, extracts processes, finds network connections, detects malware indicators.

## Overview

This project implements a memory forensics toolkit that:
- Parses raw memory dumps using Python's struct module
- Extracts PE (Portable Executable) headers and metadata
- Detects Windows EPROCESS kernel structures
- Finds suspicious/malware-related strings
- Identifies network connection structures
- Builds forensic timelines from timestamps
- Detects kernel code patterns

## Features

- **Binary parsing**: Uses Python struct module for low-level binary analysis
- **PE detection**: Finds executable headers in memory dumps
- **Process extraction**: Parses Windows kernel EPROCESS structures
- **Network detection**: Identifies TCP/UDP connection structures
- **Malware detection**: Scans for suspicious strings and patterns
- **Timeline analysis**: Extracts timestamps for forensic timeline
- **Hash calculation**: MD5, SHA1, SHA256 of memory dumps
- **Test mode**: Generate synthetic test memory dumps

## Installation

```bash
pip install scapy  # optional, for extended analysis
```

## Usage

```bash
# Full analysis
python3 mem_forensics.py --dump memory.raw

# Generate test dump and analyze
python3 mem_forensics.py --generate-test test_dump.raw

# Extract strings only
python3 mem_forensics.py --dump memory.raw --strings

# Calculate hashes only
python3 mem_forensics.py --dump memory.raw --hash

# Export to JSON
python3 mem_forensics.py --dump memory.raw --output report.json
```

## Example Output

```
============================================================
  D1 — Memory Forensics Toolkit — Analysis Report
============================================================
  File: memory.raw
  Size: 1,048,576 bytes
  MD5:  a1b2c3d4e5f6...

  PE Executables Found:  1
  Suspicious Strings:   8
  Kernel Objects:       3
  Processes Detected:   1
  Network Connections:  0

  --- Suspicious Findings ---
    [!] "cmd.exe" at offset 0x5000
    [!] "mimikatz" at offset 0x5200
    [!] "reverse shell" at offset 0x5400

  --- Process List ---
    PID   1234: malware.exe
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Unauthorized access to computer systems is illegal under federal and state laws
- This tool should ONLY be used on systems you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Federal Rules of Evidence**: Evidence obtained without authorization may be inadmissible
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Memory dumps may contain personal data subject to privacy regulations

### Acceptable Use
- Forensic analysis of your own systems during incident response
- Authorized digital forensics investigations with proper legal authority
- Academic research in controlled lab environments
- Security education and training with synthetic test data

### Prohibited Use
- Analyzing memory dumps from systems without authorization
- Extracting credentials or sensitive data without legal authority
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
