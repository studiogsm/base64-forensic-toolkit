<p align="center">
  <img src="https://img.shields.io/badge/version-2.7-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10+-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-Forensic%20Use%20Only-red?style=for-the-badge" />
</p>

<h1 align="center">🔬 Base64 Forensic Toolkit</h1>

<p align="center">
  Professional forensic tool for iOS analysis, Base64 decoding, PIN recovery and digital evidence processing.<br>
  Built for court-appointed experts and law enforcement digital forensics units.
</p>

---

## 🧑‍💼 Author

**Krystian Zarzecki**  
President of the Board — Wezafon Sp. z o.o. (brand: **Laboratorium Elektroniki**)  
Court-Appointed Expert in Digital Forensics & Teleinformatics  
District Court in Tarnobrzeg, Poland  

🌐 [laboratoriumelektroniki.pl](https://laboratoriumelektroniki.pl)  
📘 [facebook.com/LaboratoriumElektroniki](https://facebook.com/LaboratoriumElektroniki)  
🐙 [github.com/studiogsm](https://github.com/studiogsm)

> First Polish court-appointed digital forensics expert to speak at the **Cellebrite C2C User Summit** (Washington DC, April 2025).  
> International Delegate at the **Magnet User Summit** (Nashville).

---

## ✨ Features

### 🔍 Analysis
| Module | Description |
|---|---|
| **Base64 PIN Parser** | Scans keychain/dump/log files for Base64-encoded PINs (4 and 6 digit). Built-in dictionary (0000–9999, 000000–999999) or custom wordlist. Generates TXT report with MD5/SHA-256 hashes. |
| **Research Analysis** | Finds all Base64 candidates in a file or ZIP archive. Classifies results: PIN / digits / text / binary. Entropy scoring, report with legal-ready hash summary. |
| **Keychain Decoder** | Parses GrayKey-style `keychain.plist` and `passwords.txt` exports. Displays account/service/password in sortable table. Multi-select TXT export. |
| **JWT Analyzer** | Extracts and decodes JWT tokens from any file. Shows header, payload, expiry, algorithm. |
| **Entropy Analysis** | Detects encrypted or compressed blocks by Shannon entropy. Configurable threshold and block size. |
| **BFU / AFU Checker** | Determines device state (Before/After First Unlock) from iOS artifacts. |
| **Lockdown Certificates** | Parses iOS pairing records and lockdown certificate data. |
| **Hash Identifier** | Identifies hash type from 24 formats: MD5, SHA-1/256/512, NTLM, bcrypt, LM, MySQL, etc. |
| **SQLite Scanner** | Scans all SQLite databases in a ZIP (FFS) or single `.db` file. Searches every table and column for Base64, JWT and PINs. Exports to CSV. |
| **iOS Artifact Extractor** | Extracts forensic artifacts from iPhone FFS ZIP: `sms.db`, `KnowledgeC.db`, `CallHistory`, `NoteStore`, `Calendar`, Safari History. Exports each to separate CSV. |

### 🔑 Dictionaries
| Module | Description |
|---|---|
| **PIN Dictionary Generator** | Generates PIN wordlists (4–10 digits). Output: plain TXT or Base64→PIN. Split into up to 20 files. Optional random shuffle. |
| **Birthday Dictionary** | Generates date-based wordlists from date of birth in 20+ formats (DDMMYYYY, YYYYMMDD, DDMMYY, reverse, etc.). |
| **Password Strength Analyzer** | Entropy score (0–100), character class breakdown, color-coded strength bar. Single password or batch file mode with CSV export. |
| **Dictionary Deduplicator** | Merge multiple TXT wordlist files, remove duplicates, sort alphabetically or by length. |
| **Leet Speak Generator** | Generate leet variants of base words (a→4/@, e→3, o→0, s→5/$, i→1/!) at 3 substitution levels. |

### 🔄 Tools
| Module | Description |
|---|---|
| **TXT/Base64 Converter** | Convert text files to Base64 line-by-line and back. |
| **Live Encoder/Decoder** | Real-time Base64 ↔ text encoding/decoding. |
| **Hex Viewer** | Open any binary file. Hex + ASCII view, search by hex pattern or text, jump to offset. |
| **Timestamp Converter** | Convert Unix (s/ms/µs), Apple NSDate/CoreData, Windows FILETIME, Chrome/WebKit, HFS+ timestamps to human-readable dates and back. |
| **URL/URI Decoder** | Percent-decoding, parameter parsing, Base64 in URL params, JWT in URL, deep link detection, sensitive parameter highlighting. |

### 📋 Reports
| Module | Description |
|---|---|
| **PDF Report Generator** | Generate a PDF report from any TXT/CSV file. Includes fields for title, expert name, case number and notes. Ready to attach to an expert opinion. |

### ⚙️ Settings
- Language selector: **PL / EN / DE / FR / ES / IT**
- Light / Dark theme
- Recent files history (last 10 per input)
- Application info & version

---

## 🖥️ Screenshots

> *Screenshots will be added after public release.*

---

## 📦 Requirements

- **Python 3.10+**
- `tkinter` — included with standard Python on Windows
- `fpdf2` — only for PDF Report module (`pip install fpdf2`)
- No other external packages required

---

## 🔨 Build (compile to Windows EXE)

Place **all required files** in one folder and run:

```
build_v26.bat
```

The script installs PyInstaller automatically if not present.  
Output: `dist\base64_forensic_toolkit_v2_7.exe`

### Required files:
```
base64_forensic_toolkit_v2_5.py    ← core application (v2.4 + v2.5 modules)
b64toolkit_v26_extension.py        ← v2.6 modules
b64toolkit_layout_b.py             ← two-level tab layout patch
b64toolkit_v27_extension.py        ← v2.7 modules
base64_forensic_toolkit_v2_6.py    ← main entry point
app_icon.ico                        ← application icon
build_v26.bat                       ← build script
```

---

## 📋 Version History

| Version | Release | New Features |
|---|---|---|
| **v2.7** | 2025-04 | Hash Identifier (24 types), BFU/AFU Checker, Lockdown Certificates Parser, Leet Speak Generator, Timestamp Converter, URL/URI Decoder |
| **v2.6** | 2025-03 | SQLite Scanner, iOS Artifact Extractor, Password Strength Analyzer, Dictionary Deduplicator, PDF Report Generator, Hex Viewer, two-level tab layout, Settings tab |
| **v2.5** | 2025-02 | Keychain Decoder, JWT Analyzer, Birthday Dictionary, Entropy Analysis, dark mode, multilanguage (6 langs), recent files |
| **v2.4** | 2025-01 | Base64 PIN Parser, PIN Generator, TXT/Base64 Converter, Live Encoder/Decoder, Research Analysis |

---

## ⚖️ Legal Notice

This tool is intended for use by **authorized forensic examiners and law enforcement only**.  
All analysis must be performed on legally obtained data in accordance with applicable laws and regulations.  
The author assumes no responsibility for misuse.

---

## 📄 License

© 2025 Krystian Zarzecki / Laboratorium Elektroniki  
All rights reserved. For authorized forensic use only.
