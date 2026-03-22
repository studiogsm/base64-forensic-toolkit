# Base64 Forensic Toolkit

**Professional forensic tool for iOS analysis, Base64 decoding, PIN recovery and digital evidence processing.**

---

## Author

**Krystian Zarzecki**  
**Laboratorium Elektroniki**  
Court Expert
Mielec, Poland

🌐 [facebook.com/LaboratoriumElektroniki](https://facebook.com/LaboratoriumElektroniki)

---

## Features

### 🔍 Analysis
- **Base64 PIN Parser** — search for 4/6-digit PINs encoded in Base64 inside keychain dumps, logs and FFS files
- **SQLite Scanner** — scan all SQLite databases inside a ZIP/FFS archive for Base64, JWT and PIN values
- **iOS Artifact Extractor** — extract sms.db (messages), KnowledgeC (activity), CallHistory, Notes, Calendar from FFS ZIP → CSV
- **Research Analysis** — full Base64 candidate analysis with classification (pin4/pin6/digits/text/binary)
- **Keychain Decoder** — parse GrayKey keychain.plist → table view with hex/Base64/text columns, CSV export
- **JWT Analyzer** — detect and decode JWT tokens (eyJ...) from any text file
- **Entropy Analysis** — detect encrypted/compressed blocks by Shannon entropy, magic byte detection
- **Hash Identifier** — identify 24+ hash types: MD5, SHA-1/256/512, NTLM, bcrypt, iTunes backup, BitLocker recovery key, JWT, DPAPI GUID and more
- **BFU/AFU Checker** — determine whether an iPhone FFS extraction was BFU (Before First Unlock) or AFU (After First Unlock)
- **Lockdown Certificates** — parse com.apple.mobile.lockdown plists from FFS ZIP, extract UDID, device name, paired computers

### 🔑 Dictionaries
- **PIN Dictionary Generator** — generate all PINs from 4 to 10 digits, plain TXT or Base64→PIN format, random shuffle, split into parts
- **Birthday Dictionary** — generate date-based password variants (DDMM, MMDD, DDMMYYYY, YYYYMMDD, reversed etc.)
- **Dictionary Deduplicator** — merge multiple wordlist files, remove duplicates, sort alphabetically or by length
- **Password Strength Analyzer** — entropy, charset size, score 0–100, character class breakdown, file mode with CSV export
- **Leet Speak Generator** — generate leet speak variants of base words (a→4/@, e→3, o→0, s→5/$, i→1/!) at 3 substitution levels

### 🔄 Tools
- **TXT/Base64 Converter** — convert text files to Base64 line by line and back
- **Live Encoder/Decoder** — real-time Base64 ↔ text encoding/decoding
- **Hex Viewer** — open any binary file, hex + ASCII view, search by hex pattern or text, jump to offset
- **Timestamp Converter** — convert Unix (s/ms/µs), Apple NSDate/CoreData, Windows FILETIME, Chrome/WebKit, HFS+ timestamps to human-readable dates
- **URL/URI Decoder** — percent-decoding, parameter parsing, Base64 in params, JWT in URL, deep link detection, sensitive parameter highlighting

### 📋 Reports
- **PDF Report Generator** — generate a PDF report from any TXT/CSV file, with title, expert name, case number and notes fields — ready to attach to an expert opinion

### ⚙️ Settings
- Language selector: **PL / EN / DE / FR / ES / IT**
- Light / Dark theme
- Recent files history
- Application info

---

## Requirements

- Python 3.10+
- tkinter (included with standard Python on Windows)
- No external pip packages required for core functionality

---

## Build (compile to EXE)

Place all files in one folder and run:

```
build_v26.bat
```

Requires [PyInstaller](https://pyinstaller.org) — the bat installs it automatically if not present.  
Output: `dist\base64_forensic_toolkit_v2_7.exe`

### Files required in the same folder:
```
base64_forensic_toolkit_v2_5.py   ← base application
b64toolkit_v26_extension.py       ← v2.6 new modules
b64toolkit_layout_b.py            ← two-level layout patch
b64toolkit_v27_extension.py       ← v2.7 new modules
base64_forensic_toolkit_v2_6.py   ← main entry point
app_icon.ico                       ← application icon
build_v26.bat                      ← build script
```

---

## Version History

| Version | Changes |
|---------|---------|
| v2.7 | Hash Identifier, BFU/AFU Checker, Lockdown Certificates, Leet Speak Generator, Timestamp Converter, URL/URI Decoder |
| v2.6 | SQLite Scanner, iOS Artifact Extractor, Password Strength, Dict Deduplicator, PDF Report, Hex Viewer, two-level layout, Settings tab |
| v2.5 | Keychain Decoder, JWT Analyzer, Birthday Dictionary, Entropy Analysis, dark mode, multilanguage, recent files |
| v2.4 | Base64 PIN Parser, PIN Generator, Converter, Live Encoder, Research Analysis |

---

## License

This tool is intended for use by authorized forensic examiners and law enforcement only.  
All analysis should be performed on legally obtained data in accordance with applicable laws.
