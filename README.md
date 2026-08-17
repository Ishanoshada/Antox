# 🔒 Antox

**Android APK Security Analysis Tool** — High-performance static analysis for Android applications.

[![GitHub](https://img.shields.io/badge/GitHub-ishanoshada/Antox-blue?logo=github)](https://github.com/ishanoshada/Antox)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](#license)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()




---

## Overview


**Antox** is a command-line tool that performs comprehensive security analysis on Android APK files. It integrates with **jadx-gui** through the Model Context Protocol (MCP) to extract and analyze security-relevant information from decompiled APK content, native libraries, and configuration files.


<center>

![1](/imgs/image.png)

</center>

Antox goes beyond basic APK inspection by:
- 🔍 Detecting anti-tampering & anti-debugging techniques
- 🔐 Extracting credentials, API keys, and secrets
- 📱 Analyzing vendor SDKs (RASP, hardening, attestation, etc.)
- 🔗 Mapping backend infrastructure and APIs
- 🏗️ Identifying native code & JNI implementations
- 🔓 Discovering obfuscation patterns and encoded strings
- 📊 Generating comprehensive security reports

### Key Features

| Feature | Description |
|---------|-------------|
| **Zero Dependencies** | Pure Go implementation — no external libraries |
| **Fast Analysis** | Concurrent class processing with bounded worker pools |
| **Multi-Format Reports** | JSON, Markdown, or both formats for flexibility |
| **Raw APK Scanning** | Direct analysis of `.apk` files (no extraction needed) |
| **Hex Decoding** | Automatic XOR decoding (0x42, 0x41, 0x5a) for obfuscated strings |
| **Native Code Analysis** | Auto-detect `.so` libs, JNI exports, syscalls, hooks |
| **SDK Inventory** | Catalog of 40+ vendor SDKs (Talsec, DexGuard, Promon, etc.) |
| **Infrastructure Mapping** | Backend hosts, IPs, Firebase config, TLS posture |
| **Interactive Shell** | Real-time querying with `shell` mode |

---

## Requirements

- **jadx-gui** with **jadx-mcp-server** plugin running
- **Go 1.26+** (for building from source)
- **Windows, Linux, or macOS**
- APK files for analysis

### MCP Server Setup

Antox requires the **jadx MCP server** to be running:

1. **Install jadx-mcp-server**:
   ```
   git clone https://github.com/zinja-coder/jadx-mcp-server
   cd jadx-mcp-server
   # Follow the FastMCP plugin installation guide
   ```

2. **Launch jadx-gui** with the plugin enabled (listening on `http://127.0.0.1:8651/mcp`)

3. **Load your APK** into jadx-gui

4. **Run antox** to analyze the loaded APK

---

## Installation

### Pre-built Binary

Download the latest release from [GitHub Releases](https://github.com/ishanoshada/Antox/releases)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ishanoshada/Antox.git
cd Antox

# Build (Windows)
go build -o antox.exe .

# Build (Linux/macOS)
go build -o antox .

# Verify installation
./antox.exe -help    # Windows
./antox -help        # Linux/macOS
```

**Build Requirements**: Go 1.26+, no external dependencies

---

## Quick Start

### 1. Verify MCP Connection

```bash
antox ping
# Output: Connected to jadx MCP server ✓
```

### 2. Extract Manifest Information

```bash
antox manifest
# Extracts: package name, version, permissions, activities, services, receivers
```

### 3. Find Credentials & Secrets

```bash
antox secrets
# Finds: API keys, tokens, passwords, JWT, Firebase credentials, etc.
```

### 4. Analyze Security Hardening

```bash
antox security
# Detects: root/jailbreak detection, frida/xposed hooks, emulator detection, 
#          SSL pinning, crypto usage, integrity checks, RASP implementations
```

### 5. Full Comprehensive Scan

```bash
antox full -out report.md
# Runs all analysis modes and generates a markdown report
```

### 6. Raw APK File Analysis

```bash
antox full -apk "C:\path\base.apk,C:\path\config.arm64_v8a.apk" -out report.md
# Analyzes raw APK files without jadx decompilation
```

---

## Analysis Modes

### Scan Levels

| Level | Scope | Speed | Modes |
|-------|-------|-------|-------|
| **L1 - Surface** | App identity, credentials, cloud config | Fast | `manifest`, `secrets`, `firebase` |
| **L2 - Hardening** | Anti-tampering logic, obfuscation | Medium | `security`, `detection`, `sdks`, `hexenc` |
| **L3 - Deep** | Native code, infrastructure, encoded strings | Slow | `native`, `backend`, `hexstr`, `hexdump`, `sostr` |
| **L4 - Full** | Everything combined + Markdown report | Very Slow | `full`, `all` |

### Mode Reference

#### Level 1: Surface Analysis

| Mode | Description | Output |
|------|-------------|--------|
| `manifest` | Parse AndroidManifest.xml | Package, version, permissions, exported components, activities, services |
| `secrets` | Extract credentials from code & strings | API keys, tokens, passwords, JWTs, Firebase credentials, DB strings |
| `firebase` | Parse Firebase configuration | Google API keys, app IDs, storage buckets, database URLs |

#### Level 2: Hardening Analysis

| Mode | Description | Output |
|------|-------------|--------|
| `security` | Map security layers | Root detection, frida/xposed hooks, emulator checks, debugger detection, SSL pinning, crypto, integrity checks, RASP |
| `detection` | Find detection logic | Detection functions, hardening SDK usage, anti-hook implementations |
| `sdks` | Vendor SDK inventory | Talsec, DexGuard, Promon, AppSealing, Zimperium, Play Integrity, SafetyNet, ThreatMetrix, AppsFlyer, Xposed, Frida, RootBeer, etc. |
| `hexenc` | Find obfuscation routines | Hex encoding/decoding functions, string obfuscation patterns |

#### Level 3: Deep Analysis

| Mode | Description | Output |
|------|-------------|--------|
| `native` | Auto-detect native code | .so libraries, Java_* JNI exports, native method declarations, syscalls, hook frameworks, detection functions |
| `sostr` | Scan packaged .so files | Hook/root/detection strings in binaries, reference resolution, file offsets |
| `backend` | Map infrastructure | Backend hosts, IPs, API endpoints, Firebase config, TLS/cleartext posture |
| `hexstr` | Decode hex blobs in code | Hex-encoded detection strings, credentials, and interesting content |
| `hexdump` | Decode hex snippets | XOR decoding (0x42, 0x41, 0x5a), ASCII conversion |
| `fridahook` | Generate Frida bypass script | App-tailored frida-hook.js for bypassing detection |

#### Utilities

| Mode | Description | Usage |
|------|-------------|-------|
| `search` | Custom keyword search | `antox search "apiKey" -scope code,method` |
| `shell` | Interactive REPL | `antox shell` |
| `ping` | Test connectivity | `antox ping` |
| `list-tools` | MCP tool listing | `antox list-tools` |
| `all` | Run all modes (no report) | `antox all` |
| `full` | Run all modes + report | `antox full -out report.md` |

---

## Examples

### Basic Scans

```bash
# Quick surface-level analysis
antox manifest
antox secrets -limit 20
antox firebase

# Full hardening check
antox security
antox detection
antox sdks -limit 50

# Deep native analysis
antox native -limit 40
antox sostr -apk "base.apk"
antox backend -apk "base.apk,config.arm64_v8a.apk"
```

### Advanced Usage

```bash
# Decode specific hex blob
antox hexdump -term "48 6F 6F 6B 69 6E 67 20 64 65 74 65 63 74 65 64"

# Search for specific patterns
antox search "firebase" -scope code,resource
antox search "TODO" -scope comments

# Generate full report with custom options
antox full -apk "C:\path\*.apk" -out report.json -format json -workers 16

# Interactive analysis
antox shell

# Custom output path
antox full -apk base.apk -out "C:\results\antox_report.md" -format md
```

### Threading & Performance

```bash
# Increase worker threads for faster processing
antox secrets -workers 16 -limit 40

# Set per-request timeout (seconds)
antox full -timeout 600

# Suppress output (quiet mode)
antox full -quiet

# Disable colors
antox full -no-color

# Save output without writing files
antox full -no-save
```

### Multi-APK Analysis

```bash
# Analyze split APK configuration
antox full \
  -apk "base.apk,config.arm64_v8a.apk,config.en.apk" \
  -out "D:\reports\split_analysis.md"
```

---

## Report Formats

### Markdown Reports

```bash
antox full -out report.md -format md
# Generates: human-readable analysis report
```

**Markdown Report Structure:**
- Executive Summary
- Manifest Analysis
- Security Findings
- Detected SDKs
- Native Code Analysis
- Backend Infrastructure
- Encoded Strings & Secrets
- Recommendations

### JSON Reports

```bash
antox full -out report.json -format json
# Generates: machine-parseable JSON output
```

**JSON Structure:**
```json
{
  "timestamp": "2026-08-16T10:30:00Z",
  "apk_package": "com.example.app",
  "manifest": { ... },
  "secrets": [ ... ],
  "security": { ... },
  "native": { ... },
  "backend": { ... }
}
```

### Both Formats

```bash
antox full -format both
# Generates: both report.md and report.json
```

---

## Advanced Features

### Backend Infrastructure Analysis

Antox extracts backend infrastructure from multiple sources:

1. **Decompiled Code** — Direct string references to hosts, URLs, API paths
2. **Resource Files** — Firebase config, google-services.json, network_security_config.xml
3. **Raw APK Content** — resources.arsc, compiled strings, Dart AOT snapshots

**Risk Levels:**
- 🔴 **HIGH** — Firebase secrets, cleartext HTTP URLs, cleartext TLS policies
- 🟡 **MEDIUM** — API endpoints, service prefixes, IP addresses
- 🟢 **LOW** — Schema/namespace URIs (www.w3.org, schemas.android.com, etc.)

### Hex Decoding

Antox automatically decodes obfuscated hex strings using:
- Plain ASCII
- XOR-0x42 (Standard Android encryption)
- XOR-0x41
- XOR-0x5a

```bash
antox hexstr -limit 60
# Finds and decodes all hex-encoded strings in code

antox native -limit 40
# Decodes hex strings within native libraries
```

### Native Code Analysis

Detects:
- ✅ `.so` library names and security payloads
- ✅ JNI exports and native method declarations
- ✅ Direct syscall usage (openat, getdents64, readlinkat, etc.)
- ✅ Detection function names (nativeScanMaps, nativeDetectFrida, etc.)
- ✅ Hook frameworks (Xposed, LSPosed, Dobby, ShadowHook, zygisk)
- ✅ Anti-hook detection methods

### SDK Inventory

Recognizes 40+ vendor SDKs including:

**Security & RASP:**
- Talsec, DexGuard, Promon, AppSealing, Zimperium
- Play Integrity, SafetyNet, ThreatMetrix

**Analytics & Tracking:**
- Sift, Adjust, AppsFlyer, Firebase Analytics

**Hook Frameworks:**
- Xposed, LSPosed, Frida, Substrate, zygisk

**Anti-Tampering:**
- RootBeer, TrustKit, SQLCipher

---

## Configuration

### Environment Variables

```bash
# Override MCP server endpoint
export ANTOX_MCP=http://192.168.1.100:8651/mcp
antox manifest

# Custom report directory
export ANTOX_OUT=D:\security_reports
antox full
```

### Default Behavior

| Setting | Default | Override |
|---------|---------|----------|
| MCP Endpoint | `http://127.0.0.1:8651/mcp` | `-mcp <url>` |
| Output Dir | `./reports` | `-out <dir>` |
| Report Format | `both` (JSON + MD) | `-format md\|json\|both` |
| Worker Threads | `8` | `-workers <n>` |
| Request Timeout | `900s` | `-timeout <s>` |
| Max Classes | `8` per category | `-limit <n>` |

---

## Project Structure

```
antox/
├── main.go                 # CLI entry point, flag parsing, mode dispatch
├── go.mod                  # Go module definition
├── README.md               # This file
├── antox.exe               # Compiled Windows binary
│
├── analyzer/               # Analysis engine (one file per mode)
│   ├── analyzer.go         # Analyzer interface & progress tracking
│   ├── all.go              # Full scan orchestration
│   ├── manifest.go         # AndroidManifest.xml parsing
│   ├── secrets.go          # Credential extraction
│   ├── firebase.go         # Firebase config detection
│   ├── security.go         # Security layer mapping
│   ├── detection.go        # Detection logic discovery
│   ├── sdks.go             # Vendor SDK inventory
│   ├── native.go           # Native code analysis
│   ├── sostr.go            # .so string extraction
│   ├── backend.go          # Backend infrastructure mapping
│   ├── hexstr.go           # Hex blob decoding
│   ├── hexenc.go           # Obfuscation detection
│   ├── hexdump.go          # Standalone hex decoder
│   ├── frida.go            # Frida bypass script generation
│   ├── report.go           # Report generation (MD/JSON)
│   ├── progress.go         # Progress tracking
│   └── *_test.go           # Unit tests
│
├── patterns/               # Detection dictionaries & regex patterns
│   ├── patterns.go         # Security keywords & categories
│   ├── sdks.go             # Vendor SDK catalog
│   ├── native.go           # Native function dictionary
│   ├── hex.go              # Hex parsing & decoding
│   ├── backend.go          # Infrastructure regex patterns
│   ├── sostr.go            # .so keyword list
│   └── *_test.go           # Pattern tests
│
├── mcp/                    # MCP client implementation
│   ├── client.go           # Streamable HTTP JSON-RPC client
│   ├── types.go            # MCP request/response types
│   └── (no external deps)
│
└── test-real/              # Test cases & real APK data
    ├── concepts-test/      # Test suites
    ├── extracted_data/     # Sample outputs
    └── (ignored by git)
```

---

## CLI Reference

### Usage

```bash
antox <mode> [flags]
```

### All Modes

```
Surface (L1):
  manifest    - Parse AndroidManifest.xml
  secrets     - Extract API keys / tokens / credentials
  firebase    - Extract Firebase / google-services configuration

Hardening (L2):
  security    - Map security layers (root, frida, emulator, debugger, ssl, crypto)
  detection   - Find detection logic & hardening SDKs
  sdks        - Inventory vendor SDKs
  hexenc      - Find hex / string obfuscation routines

Deep (L3):
  native      - Auto-detect .so libs, JNI exports, syscalls, hooks
  sostr       - Scan packaged .so files for detection strings
  backend     - Map backend hosts/IPs/endpoints + Firebase config
  hexstr      - Scan code for hex blobs and decode
  hexdump     - Decode a hex blob passed via -term
  fridahook   - Generate app-tailored Frida bypass script

Utilities:
  search      - Custom keyword search (requires -term)
  shell       - Interactive REPL
  ping        - Test connectivity to MCP server
  list-tools  - List tools exposed by MCP server
  all         - Run every mode (no default report)
  full        - Run every mode + generate .md report
```

### Flags

```
  -apk string
        unzipped APK dir(s) or raw .apk/.zip files (comma-separated)
        Enables raw binary scanning: resources.arsc, libapp.so, etc.

  -debug
        Print raw MCP search results for debugging

  -format string
        Report format: md, json, or both (default: both)
        For 'full' mode, defaults to md

  -limit int
        Max class sources fetched per category (default: 8)
        Limit results per analysis type

  -mcp string
        jadx MCP server endpoint (default: http://127.0.0.1:8651/mcp)

  -no-color
        Disable ANSI colors in console output

  -no-save
        Do not write report files (analyze only)

  -out string
        Output directory or file path (default: reports/)
        Can end in .md or .json to specify format

  -package string
        Restrict searches to a specific package name

  -quiet
        Suppress progress output during analysis

  -scope string
        Search scope: class, method, field, code, resource, comments
        Comma-separated, default: code

  -term string
        Custom search term for search/hexdump modes

  -timeout int
        Per-request timeout in seconds (default: 900)

  -workers int
        Concurrent class-source fetches (default: 8)
        Higher = faster but more server load
```

---

## Performance Tips

1. **Increase Workers** — Use `-workers 16` for faster processing (if server supports it)
2. **Limit Results** — Use `-limit 20` instead of default 8 to reduce overhead
3. **Use Quiet Mode** — `-quiet` suppresses output, slightly faster
4. **Split Analysis** — Run specific modes instead of `full` for targeted checks
5. **Raw APK Mode** — Use `-apk` for faster infrastructure analysis (no decompilation)

**Example: Fast credential scan**
```bash
antox secrets -workers 16 -limit 50 -quiet
```

---

## Troubleshooting

### Connection Issues

```bash
# Verify MCP server is running
antox ping

# Connection refused?
# 1. Check jadx-mcp-server is installed
# 2. Verify jadx-gui is running with plugin loaded
# 3. APK must be loaded in jadx-gui
```

### Slow Performance

```bash
# Reduce worker threads if server throttles
antox full -workers 4

# Use smaller limits
antox secrets -limit 10

# Run specific modes instead of full
antox manifest
antox secrets
```

### Memory Issues

```bash
# Reduce limit and workers for large APKs
antox full -limit 5 -workers 4 -timeout 600
```

### Missing Results

```bash
# Enable debug logging
antox full -debug

# Check MCP server logs
# Increase timeout
antox full -timeout 1200
```

---

## Contributing

We welcome contributions! To contribute:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Implement** your changes with tests
4. **Commit** with clear messages (`git commit -m 'Add amazing feature'`)
5. **Push** to your fork (`git push origin feature/amazing-feature`)
6. **Open** a Pull Request with description

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Antox.git
cd Antox

# Run tests
go test ./...

# Build locally
go build -o antox.exe .

# Run with verbose output
./antox.exe full -debug
```

---

## License

**Antox** is released under the **MIT License** — see [LICENSE](LICENSE) for details.

This project includes patterns and detection signatures derived from the native detection library **snitchtt** (XOR-0x42 encryption patterns, JNI signatures, syscall detection).

---

## Acknowledgments

- **jadx-gui** — Decompilation engine
- **jadx-mcp-server** — Model Context Protocol integration
- **snitchtt** — Native detection library (detection patterns)
- Community contributors & security researchers

---

## Citation

If you use **Antox** in your research or security assessments, please cite:

```
Antox - Android APK Security Analysis Tool
Repository: https://github.com/ishanoshada/Antox
License: MIT
Year: 2026
```

---

## Support & Contact

- 🐛 **Bug Reports** — [GitHub Issues](https://github.com/ishanoshada/Antox/issues)
- 💬 **Discussions** — [GitHub Discussions](https://github.com/ishanoshada/Antox/discussions)
- 📧 **Email** — [Contact](https://github.com/ishanoshada)
- 🐙 **GitHub** — [@ishanoshada](https://github.com/ishanoshada)

---

**Made with ❤️ for the security research community**

*Last Updated: August 16, 2026*
