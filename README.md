# ⚡ REV LAB — Static Binary Analysis & Inspection Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20Mint%20%7C%20macOS-4A154B?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/UI-Claude%20Code%20Inspired-DA7756?style=for-the-badge" alt="UI Style">
</p>

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  ⚡ REV LAB v1.0.0 — Static Binary Analysis & Reverse Engineering Toolkit      │
└────────────────────────────────────────────────────────────────────────────────┘
```

> **REV LAB** is a modern, modular, cross-platform terminal-native Static Binary Analysis Toolkit built with Python, Typer, Rich, and Textual. Designed with a **Claude Code inspired visual aesthetic** (Warm Terracotta `#DA7756` and Slate Cyan `#4CB9E7`), RevLab allows security researchers, malware analysts, and reverse engineers to inspect, disassemble, de-obfuscate, scan YARA signatures, and profile executable files (`PE`, `ELF`, `Mach-O`, and raw binaries) without execution.

---

## 🏛 System Architecture

```
                       ┌─────────────────────────────┐
                       │        Terminal CLI         │
                       │ Rich • Typer • Textual TUI  │
                       └──────────────┬──────────────┘
                                      │
                            Command Dispatcher
                                      │
       ┌──────────────────────────────┼──────────────────────────────┐
       │                              │                              │
   Parser Layer                 Analysis Layer                 Output Layer
       │                              │                              │
       ▼                              ▼                              ▼
 PE / ELF / Mach-O          YARA • Deobfuscation • CFG       Tables • Badges • Web CFG
 Raw Binary Loader          Entropy • Opcodes • Hashes       HTML • JSON • MD
       │                              │                              │
       └──────────────────────────────┼──────────────────────────────┘
                                      ▼
                             Shared Data Model
                                      │
               ┌──────────────────────┼──────────────────────┐
               ▼                      ▼                      ▼
        SQLite History         Plugin Framework       FastAPI REST Server
```

---

## 🌟 Key Features

- 🎨 **Claude Code Visual Aesthetics**: Custom color palette, rounded borders (`box.ROUNDED`), status badges (`[PACKED]`, `[SUSPICIOUS]`), animated spinners, and syntax-highlighted assembly disassembly.
- 🔍 **Multi-Format Format Parser**: Auto-detects `PE` (Windows), `ELF` (Linux), `Mach-O` (macOS), and raw binary magic signatures.
- 🛡 **YARA Signature Rule Scanner**: Built-in rules for anti-debugging APIs, UPX packers, shellcode prologues, and network downloaders, plus custom `.yar` rule directory loading.
- 🔓 **De-obfuscation & Stack Strings Engine**: Assembly stack string heuristics and single-byte XOR key brute-forcer (`0x01`–`0xFF`) extracting hidden URLs, IPs, Registry keys, and Windows APIs.
- 📊 **Interactive Web-Based CFG Visualizer**: Generates standalone interactive HTML graphs (`vis-network`) for basic block panning, zooming, and branch traversal.
- 📜 **PE Rich Header & Resource Inspector**: Decrypts MSVC **Rich Header** (`DanS` magic, XOR key, build numbers, tool IDs) and parses `.rsrc` resource section items.
- 🧮 **Shannon Entropy & Opcode Profiler**: Section-by-section entropy calculation with visual ASCII bars and opcode mnemonic frequency distribution.
- 💾 **SQLite History Tracker**: Automatically logs analysis runs into `~/.revlab.db` for queryable history (`rl h`).
- 🌐 **Headless REST API Server**: Built-in FastAPI server (`rl srv`) powering automated remote binary analysis pipelines.

---

## 🚀 Quick Commands & Shortcuts Matrix

You can use standard command names (`revlab analyze`) or **ultra-fast 1-to-3 letter shortcuts** (`rl a`):

| Feature | Full Command | **⚡ Short Shortcut** |
| :--- | :--- | :--- |
| **Executive Analysis** | `revlab analyze <bin>` | **`rl a <bin>`** |
| **Extract Strings** | `revlab strings <bin>` | **`rl s <bin>`** |
| **Stack Strings & XOR Scan** | `revlab strings <bin> --deobfuscate` | **`rl s <bin> -d`** |
| **YARA Signature Scan** | `revlab yara <bin>` | **`rl yr <bin>`** |
| **Disassemble Code** | `revlab disassemble <bin>` | **`rl d <bin>`** |
| **Control Flow Graph (CFG)** | `revlab cfg <bin>` | **`rl g <bin>`** |
| **Web Interactive CFG** | `revlab cfg <bin> --web` | **`rl g <bin> -w`** |
| **PE Rich Header & Resources** | `revlab resources <bin>` | **`rl res <bin>`** |
| **Shannon Entropy Graph** | `revlab entropy <bin>` | **`rl ent <bin>`** |
| **Sections Inspection** | `revlab sections <bin>` | **`rl sec <bin>`** |
| **Imported APIs** | `revlab imports <bin>` | **`rl imp <bin>`** |
| **Exported Symbols** | `revlab exports <bin>` | **`rl exp <bin>`** |
| **Interactive TUI Dashboard** | `revlab tui <bin>` | **`rl ui <bin>`** |
| **Binary Similarity Diff** | `revlab compare <bin1> <bin2>` | **`rl cmp <bin1> <bin2>`** |
| **Export Report** | `revlab report <bin> -f html` | **`rl rep <bin> -f html`** |
| **Metadata & Hashes** | `revlab metadata <bin>` | **`rl meta <bin>`** |
| **Opcode Profiling** | `revlab opcodes <bin>` | **`rl op <bin>`** |
| **Function Prologues** | `revlab functions <bin>` | **`rl fn <bin>`** |
| **SQLite History Query** | `revlab history` | **`rl h`** |
| **System Diagnostics** | `revlab doctor` | **`rl doc`** |
| **Headless REST API Server** | `revlab serve` | **`rl srv`** |

---

## 💻 Installation

### Linux Mint / Ubuntu / Debian
```bash
# 1. Install prerequisites
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# 2. Clone repository & install
git clone https://github.com/HNS-06/RevLab.git
cd RevLab
pip3 install -e .

# 3. Test installation
./rl doc
```

### Windows (PowerShell / CMD)
```powershell
# Clone repository & install
git clone https://github.com/HNS-06/RevLab.git
cd RevLab
py -m pip install -e .

# Test installation
rl doc
```

---

## 🧪 Testing & Verification

Run automated test suite:
```bash
python3 tests/test_revlab.py
```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
