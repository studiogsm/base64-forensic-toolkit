#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# b64toolkit_v27_extension.py
# v2.7 patch — 6 new modules:
#   Analysis:    Hash Identifier, BFU/AFU Checker, Lockdown Certificates
#   Dictionaries: Leet Speak Generator
#   Tools:       Timestamp Converter, URL/URI Decoder

import base64
import csv
import hashlib
import os
import plistlib
import re
import sqlite3
import string
import tempfile
import tkinter as tk
import urllib.parse
import zipfile
from datetime import datetime, timezone, timedelta
from tkinter import filedialog, messagebox, scrolledtext, ttk

# =============================================================================
# TRANSLATIONS
# =============================================================================
V27_TRANSLATIONS = {
    "PL": {
        "tab_hashid":      "Hash Identifier",
        "tab_bfuafu":      "BFU/AFU Checker",
        "tab_lockdown":    "Lockdown Certs",
        "tab_leet":        "Leet Speak Gen.",
        "tab_timestamp":   "Timestamp Conv.",
        "tab_urldecoder":  "URL/URI Decoder",
        # hash id
        "lbl_hashid_info": "Wklej hash aby rozpoznać jego typ.\nObsługuje: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, iTunes backup, BitLocker, JWT, Base64 i inne.",
        "lbl_hashid_input": "Hash do rozpoznania:",
        "btn_hashid_run":  "Rozpoznaj",
        "btn_hashid_file": "Analizuj plik (jeden hash/linia)",
        "lbl_hashid_result": "Wynik:",
        # bfu/afu
        "lbl_bfuafu_info": "Skanuje archiwum ZIP (FFS iPhone) i ocenia czy ekstrakcja była BFU (Before First Unlock) czy AFU (After First Unlock).\nSprawdza obecność kluczowych baz danych, keychaina i certyfikatów lockdown.",
        "lbl_bfuafu_zip":  "Archiwum ZIP (FFS):",
        "btn_bfuafu_run":  "Sprawdź BFU/AFU",
        # lockdown
        "lbl_lockdown_info": "Parsuje certyfikaty lockdown (com.apple.mobile.lockdown) z archiwum ZIP lub folderu FFS.\nWyświetla UDID, nazwę urządzenia, parowane komputery i daty.",
        "lbl_lockdown_zip":  "Archiwum ZIP (FFS):",
        "btn_lockdown_run":  "Parsuj certyfikaty",
        "btn_lockdown_csv":  "Eksportuj CSV",
        # leet
        "lbl_leet_info":   "Generator wariantów leet speak.\nPodaj słowa bazowe (jedno/linię) — program generuje wszystkie kombinacje zamienników:\na→4/@, e→3, i→1/!, o→0, s→5/$, t→7 itp.\nPrzydatne do tworzenia słowników haseł.",
        "lbl_leet_input":  "Słowa bazowe (jedno/linię):",
        "lbl_leet_file":   "Lub wczytaj z pliku:",
        "lbl_leet_level":  "Poziom zamiany:",
        "lbl_leet_lvl1":   "1 — tylko cyfry (a→4, e→3, o→0)",
        "lbl_leet_lvl2":   "2 — cyfry + symbole (a→@, s→$, i→!)",
        "lbl_leet_lvl3":   "3 — wszystkie warianty (kombinacje)",
        "btn_leet_run":    "Generuj",
        "btn_leet_save":   "Zapisz słownik",
        "lbl_leet_count":  "Wygenerowano: {count} wpisów",
        # timestamp
        "lbl_ts_info":     "Konwersja znaczników czasu na czytelne daty.\nObsługuje: Unix (s/ms/µs), Apple NSDate (CoreData), Windows FILETIME, Chrome/WebKit, HFS+.",
        "lbl_ts_input":    "Wartość do konwersji:",
        "btn_ts_run":      "Konwertuj",
        "btn_ts_file":     "Analizuj plik",
        "lbl_ts_result":   "Wyniki konwersji:",
        # url decoder
        "lbl_url_info":    "Dekoder URL/URI.\nDekoduje: percent-encoding (%XX), base64 w parametrach, deep linki, JWT w URL.\nWykrywa ukryte parametry i potencjalnie wrażliwe dane.",
        "lbl_url_input":   "URL / URI do zdekodowania:",
        "btn_url_run":     "Dekoduj",
        "btn_url_clear":   "Wyczyść",
        "btn_url_file":    "Analizuj plik (jeden URL/linię)",
        "lbl_url_result":  "Wynik dekodowania:",
        # common
        "msg_no_input":    "Wprowadź dane do analizy.",
        "lbl_bfu_result":  "Wynik: {result}",
    },
    "EN": {
        "tab_hashid":      "Hash Identifier",
        "tab_bfuafu":      "BFU/AFU Checker",
        "tab_lockdown":    "Lockdown Certs",
        "tab_leet":        "Leet Speak Gen.",
        "tab_timestamp":   "Timestamp Conv.",
        "tab_urldecoder":  "URL/URI Decoder",
        "lbl_hashid_info": "Paste a hash to identify its type.\nSupports: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, iTunes backup, BitLocker, JWT, Base64 and more.",
        "lbl_hashid_input": "Hash to identify:",
        "btn_hashid_run":  "Identify",
        "btn_hashid_file": "Analyze file (one hash/line)",
        "lbl_hashid_result": "Result:",
        "lbl_bfuafu_info": "Scans a ZIP archive (iPhone FFS) and determines whether the extraction was BFU (Before First Unlock) or AFU (After First Unlock).\nChecks for key databases, keychain and lockdown certificates.",
        "lbl_bfuafu_zip":  "ZIP archive (FFS):",
        "btn_bfuafu_run":  "Check BFU/AFU",
        "lbl_lockdown_info": "Parses lockdown certificates (com.apple.mobile.lockdown) from a ZIP archive or FFS folder.\nShows UDID, device name, paired computers and dates.",
        "lbl_lockdown_zip":  "ZIP archive (FFS):",
        "btn_lockdown_run":  "Parse certificates",
        "btn_lockdown_csv":  "Export CSV",
        "lbl_leet_info":   "Leet speak variant generator.\nEnter base words (one/line) — generates all substitution combinations:\na→4/@, e→3, i→1/!, o→0, s→5/$, t→7 etc.\nUseful for creating password dictionaries.",
        "lbl_leet_input":  "Base words (one/line):",
        "lbl_leet_file":   "Or load from file:",
        "lbl_leet_level":  "Substitution level:",
        "lbl_leet_lvl1":   "1 — digits only (a→4, e→3, o→0)",
        "lbl_leet_lvl2":   "2 — digits + symbols (a→@, s→$, i→!)",
        "lbl_leet_lvl3":   "3 — all variants (combinations)",
        "btn_leet_run":    "Generate",
        "btn_leet_save":   "Save dictionary",
        "lbl_leet_count":  "Generated: {count} entries",
        "lbl_ts_info":     "Timestamp converter.\nSupports: Unix (s/ms/µs), Apple NSDate (CoreData), Windows FILETIME, Chrome/WebKit, HFS+.",
        "lbl_ts_input":    "Value to convert:",
        "btn_ts_run":      "Convert",
        "btn_ts_file":     "Analyze file",
        "lbl_ts_result":   "Conversion results:",
        "lbl_url_info":    "URL/URI decoder.\nDecodes: percent-encoding (%XX), base64 in parameters, deep links, JWT in URL.\nDetects hidden parameters and potentially sensitive data.",
        "lbl_url_input":   "URL / URI to decode:",
        "btn_url_run":     "Decode",
        "btn_url_clear":   "Clear",
        "btn_url_file":    "Analyze file (one URL/line)",
        "lbl_url_result":  "Decoded output:",
        "msg_no_input":    "Enter data to analyze.",
        "lbl_bfu_result":  "Result: {result}",
    },
    "DE": {
        "tab_hashid":      "Hash-Erkennung",
        "tab_bfuafu":      "BFU/AFU Prüfer",
        "tab_lockdown":    "Lockdown Zerts.",
        "tab_leet":        "Leet Speak Gen.",
        "tab_timestamp":   "Zeitstempel",
        "tab_urldecoder":  "URL-Decoder",
        "lbl_hashid_info": "Hash einfügen um den Typ zu erkennen.",
        "lbl_hashid_input": "Hash:",
        "btn_hashid_run":  "Erkennen",
        "btn_hashid_file": "Datei analysieren",
        "lbl_hashid_result": "Ergebnis:",
        "lbl_bfuafu_info": "Scannt ein ZIP-Archiv (iPhone FFS) und bestimmt BFU oder AFU.",
        "lbl_bfuafu_zip":  "ZIP-Archiv (FFS):",
        "btn_bfuafu_run":  "BFU/AFU prüfen",
        "lbl_lockdown_info": "Analysiert Lockdown-Zertifikate aus einem ZIP-Archiv.",
        "lbl_lockdown_zip":  "ZIP-Archiv (FFS):",
        "btn_lockdown_run":  "Zertifikate analysieren",
        "btn_lockdown_csv":  "CSV exportieren",
        "lbl_leet_info":   "Leet-Speak-Variantengenerator.",
        "lbl_leet_input":  "Basiswörter (eins/Zeile):",
        "lbl_leet_file":   "Oder aus Datei laden:",
        "lbl_leet_level":  "Ersetzungsebene:",
        "lbl_leet_lvl1":   "1 — nur Ziffern",
        "lbl_leet_lvl2":   "2 — Ziffern + Symbole",
        "lbl_leet_lvl3":   "3 — alle Varianten",
        "btn_leet_run":    "Generieren",
        "btn_leet_save":   "Wörterbuch speichern",
        "lbl_leet_count":  "Generiert: {count} Einträge",
        "lbl_ts_info":     "Zeitstempel-Konverter.",
        "lbl_ts_input":    "Wert:",
        "btn_ts_run":      "Konvertieren",
        "btn_ts_file":     "Datei analysieren",
        "lbl_ts_result":   "Ergebnisse:",
        "lbl_url_info":    "URL/URI-Decoder.",
        "lbl_url_input":   "URL / URI:",
        "btn_url_run":     "Dekodieren",
        "btn_url_clear":   "Löschen",
        "btn_url_file":    "Datei analysieren",
        "lbl_url_result":  "Ausgabe:",
        "msg_no_input":    "Daten eingeben.",
        "lbl_bfu_result":  "Ergebnis: {result}",
    },
    "FR": {
        "tab_hashid":      "Ident. de hash",
        "tab_bfuafu":      "Vérif. BFU/AFU",
        "tab_lockdown":    "Certs Lockdown",
        "tab_leet":        "Gén. Leet Speak",
        "tab_timestamp":   "Conv. Timestamp",
        "tab_urldecoder":  "Décodeur URL",
        "lbl_hashid_info": "Coller un hash pour identifier son type.",
        "lbl_hashid_input": "Hash à identifier :",
        "btn_hashid_run":  "Identifier",
        "btn_hashid_file": "Analyser fichier",
        "lbl_hashid_result": "Résultat :",
        "lbl_bfuafu_info": "Analyse une archive ZIP (FFS iPhone) pour déterminer BFU ou AFU.",
        "lbl_bfuafu_zip":  "Archive ZIP (FFS) :",
        "btn_bfuafu_run":  "Vérifier BFU/AFU",
        "lbl_lockdown_info": "Analyse les certificats lockdown depuis un ZIP.",
        "lbl_lockdown_zip":  "Archive ZIP (FFS) :",
        "btn_lockdown_run":  "Analyser les certificats",
        "btn_lockdown_csv":  "Exporter CSV",
        "lbl_leet_info":   "Générateur de variantes leet speak.",
        "lbl_leet_input":  "Mots de base (un/ligne) :",
        "lbl_leet_file":   "Ou charger depuis un fichier :",
        "lbl_leet_level":  "Niveau de substitution :",
        "lbl_leet_lvl1":   "1 — chiffres uniquement",
        "lbl_leet_lvl2":   "2 — chiffres + symboles",
        "lbl_leet_lvl3":   "3 — toutes les variantes",
        "btn_leet_run":    "Générer",
        "btn_leet_save":   "Enregistrer le dictionnaire",
        "lbl_leet_count":  "Généré : {count} entrées",
        "lbl_ts_info":     "Convertisseur de timestamps.",
        "lbl_ts_input":    "Valeur :",
        "btn_ts_run":      "Convertir",
        "btn_ts_file":     "Analyser fichier",
        "lbl_ts_result":   "Résultats :",
        "lbl_url_info":    "Décodeur URL/URI.",
        "lbl_url_input":   "URL / URI :",
        "btn_url_run":     "Décoder",
        "btn_url_clear":   "Effacer",
        "btn_url_file":    "Analyser fichier",
        "lbl_url_result":  "Sortie :",
        "msg_no_input":    "Saisir des données.",
        "lbl_bfu_result":  "Résultat : {result}",
    },
    "ES": {
        "tab_hashid":      "Ident. de hash",
        "tab_bfuafu":      "Verif. BFU/AFU",
        "tab_lockdown":    "Certs Lockdown",
        "tab_leet":        "Gen. Leet Speak",
        "tab_timestamp":   "Conv. Timestamp",
        "tab_urldecoder":  "Decodif. URL",
        "lbl_hashid_info": "Pegar hash para identificar el tipo.",
        "lbl_hashid_input": "Hash:",
        "btn_hashid_run":  "Identificar",
        "btn_hashid_file": "Analizar archivo",
        "lbl_hashid_result": "Resultado:",
        "lbl_bfuafu_info": "Escanea un ZIP (FFS iPhone) para determinar BFU o AFU.",
        "lbl_bfuafu_zip":  "Archivo ZIP (FFS):",
        "btn_bfuafu_run":  "Verificar BFU/AFU",
        "lbl_lockdown_info": "Analiza certificados lockdown desde un ZIP.",
        "lbl_lockdown_zip":  "Archivo ZIP (FFS):",
        "btn_lockdown_run":  "Analizar certificados",
        "btn_lockdown_csv":  "Exportar CSV",
        "lbl_leet_info":   "Generador de variantes leet speak.",
        "lbl_leet_input":  "Palabras base (una/línea):",
        "lbl_leet_file":   "O cargar desde archivo:",
        "lbl_leet_level":  "Nivel de sustitución:",
        "lbl_leet_lvl1":   "1 — solo dígitos",
        "lbl_leet_lvl2":   "2 — dígitos + símbolos",
        "lbl_leet_lvl3":   "3 — todas las variantes",
        "btn_leet_run":    "Generar",
        "btn_leet_save":   "Guardar diccionario",
        "lbl_leet_count":  "{count} entradas generadas",
        "lbl_ts_info":     "Conversor de timestamps.",
        "lbl_ts_input":    "Valor:",
        "btn_ts_run":      "Convertir",
        "btn_ts_file":     "Analizar archivo",
        "lbl_ts_result":   "Resultados:",
        "lbl_url_info":    "Decodificador URL/URI.",
        "lbl_url_input":   "URL / URI:",
        "btn_url_run":     "Decodificar",
        "btn_url_clear":   "Limpiar",
        "btn_url_file":    "Analizar archivo",
        "lbl_url_result":  "Salida:",
        "msg_no_input":    "Introducir datos.",
        "lbl_bfu_result":  "Resultado: {result}",
    },
    "IT": {
        "tab_hashid":      "Id. Hash",
        "tab_bfuafu":      "Verif. BFU/AFU",
        "tab_lockdown":    "Cert. Lockdown",
        "tab_leet":        "Gen. Leet Speak",
        "tab_timestamp":   "Conv. Timestamp",
        "tab_urldecoder":  "Decoder URL",
        "lbl_hashid_info": "Incolla un hash per identificarne il tipo.",
        "lbl_hashid_input": "Hash:",
        "btn_hashid_run":  "Identifica",
        "btn_hashid_file": "Analizza file",
        "lbl_hashid_result": "Risultato:",
        "lbl_bfuafu_info": "Scansiona un archivio ZIP (FFS iPhone) per determinare BFU o AFU.",
        "lbl_bfuafu_zip":  "Archivio ZIP (FFS):",
        "btn_bfuafu_run":  "Verifica BFU/AFU",
        "lbl_lockdown_info": "Analizza i certificati lockdown da un archivio ZIP.",
        "lbl_lockdown_zip":  "Archivio ZIP (FFS):",
        "btn_lockdown_run":  "Analizza certificati",
        "btn_lockdown_csv":  "Esporta CSV",
        "lbl_leet_info":   "Generatore di varianti leet speak.",
        "lbl_leet_input":  "Parole base (una/riga):",
        "lbl_leet_file":   "O carica da file:",
        "lbl_leet_level":  "Livello di sostituzione:",
        "lbl_leet_lvl1":   "1 — solo cifre",
        "lbl_leet_lvl2":   "2 — cifre + simboli",
        "lbl_leet_lvl3":   "3 — tutte le varianti",
        "btn_leet_run":    "Genera",
        "btn_leet_save":   "Salva dizionario",
        "lbl_leet_count":  "Generati: {count} voci",
        "lbl_ts_info":     "Convertitore di timestamp.",
        "lbl_ts_input":    "Valore:",
        "btn_ts_run":      "Converti",
        "btn_ts_file":     "Analizza file",
        "lbl_ts_result":   "Risultati:",
        "lbl_url_info":    "Decoder URL/URI.",
        "lbl_url_input":   "URL / URI:",
        "btn_url_run":     "Decodifica",
        "btn_url_clear":   "Pulisci",
        "btn_url_file":    "Analizza file",
        "lbl_url_result":  "Output:",
        "msg_no_input":    "Inserire dati.",
        "lbl_bfu_result":  "Risultato: {result}",
    },
}

# =============================================================================
# HASH IDENTIFIER — logic
# =============================================================================

HASH_PATTERNS = [
    # (name, regex, extra_info)
    ("MD5",               re.compile(r"^[0-9a-fA-F]{32}$"),
     "128-bit — common in older systems, NTLM passwords"),
    ("NTLM",              re.compile(r"^[0-9a-fA-F]{32}$"),
     "128-bit — Windows password hash (same length as MD5)"),
    ("SHA-1",             re.compile(r"^[0-9a-fA-F]{40}$"),
     "160-bit — iTunes backup key (non-encrypted), Git commits"),
    ("SHA-256",           re.compile(r"^[0-9a-fA-F]{64}$"),
     "256-bit — iTunes encrypted backup, common in forensics"),
    ("SHA-512",           re.compile(r"^[0-9a-fA-F]{128}$"),
     "512-bit — Linux shadow passwords ($6$)"),
    ("SHA-384",           re.compile(r"^[0-9a-fA-F]{96}$"),
     "384-bit"),
    ("SHA-224",           re.compile(r"^[0-9a-fA-F]{56}$"),
     "224-bit"),
    ("SHA3-256",          re.compile(r"^[0-9a-fA-F]{64}$"),
     "256-bit SHA-3 (same length as SHA-256)"),
    ("MD4",               re.compile(r"^[0-9a-fA-F]{32}$"),
     "128-bit — older Windows, same length as MD5"),
    ("CRC32",             re.compile(r"^[0-9a-fA-F]{8}$"),
     "32-bit checksum"),
    ("bcrypt",            re.compile(r"^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}$"),
     "Blowfish — macOS, Linux passwords"),
    ("bcrypt (Apache)",   re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "Apache MD5-crypt"),
    ("MD5-crypt",         re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
     "Linux shadow MD5"),
    ("SHA-256-crypt",     re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
     "Linux shadow SHA-256"),
    ("SHA-512-crypt",     re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
     "Linux shadow SHA-512"),
    ("PBKDF2-SHA1 (b64)", re.compile(r"^[A-Za-z0-9+/=]{40,}$"),
     "iTunes backup (encrypted) — base64 encoded"),
    ("JWT",               re.compile(r"^eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"),
     "JSON Web Token — 3 base64url parts separated by dots"),
    ("BitLocker Recovery Key",
     re.compile(r"^\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}$"),
     "BitLocker 48-digit recovery key (8 groups of 6)"),
    ("Windows DPAPI masterkey",
     re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
     "GUID format — DPAPI, keychain IDs"),
    ("LM Hash",           re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"),
     "Windows LAN Manager hash (user:hash format)"),
    ("MySQL 4.x",         re.compile(r"^\*[0-9A-F]{40}$"),
     "MySQL password hash"),
    ("WPA/WPA2 PSK",      re.compile(r"^[0-9a-fA-F]{64}$"),
     "Wi-Fi pre-shared key hash (same length as SHA-256)"),
    ("Base64 (generic)",  re.compile(r"^[A-Za-z0-9+/=]{16,}$"),
     "Base64 encoded data"),
    ("Base64url (generic)", re.compile(r"^[A-Za-z0-9\-_]{16,}$"),
     "URL-safe Base64 (no padding)"),
]


def identify_hash(h: str) -> list[dict]:
    """Return list of possible hash types for given string."""
    h = h.strip()
    matches = []
    for name, pattern, info in HASH_PATTERNS:
        if pattern.match(h):
            matches.append({
                "type": name,
                "length": len(h),
                "info": info,
            })
    if not matches:
        # Fallback — check length
        length_hints = {
            8:   "CRC32 or short hash",
            16:  "Half-MD5 or MySQL 3.x",
            32:  "MD5 / NTLM / MD4",
            40:  "SHA-1",
            48:  "Tiger-192",
            56:  "SHA-224 / Haval-224",
            64:  "SHA-256 / SHA3-256 / WPA-PSK",
            80:  "SHA-384 (partial) or Haval-256",
            96:  "SHA-384",
            128: "SHA-512 / Whirlpool",
        }
        hint = length_hints.get(len(h), f"Unknown ({len(h)} chars)")
        matches.append({
            "type": f"Unknown — possible: {hint}",
            "length": len(h),
            "info": "No exact pattern matched.",
        })
    return matches


# =============================================================================
# BFU / AFU CHECKER — logic
# =============================================================================

# Key artifacts and what their presence means
BFU_INDICATORS = {
    # Present in BFU — protected/encrypted, cannot be read
    "partial_only": [
        "com.apple.springboard.plist",
        "com.apple.preferences.plist",
    ],
    # Present in AFU — decryptable
    "afu_dbs": [
        "sms.db",
        "chat.db",
        "AddressBook.sqlitedb",
        "Calendar.sqlitedb",
        "notes.sqlite",
        "NoteStore.sqlite",
        "call_history.db",
        "CallHistory.storedata",
        "Health.sqlite",
        "KnowledgeC.db",
        "History.db",
    ],
    # Keychain present → AFU
    "keychain": [
        "keychain-backup.plist",
        "keychain.plist",
        "keychain2.db",
    ],
    # Lockdown certs → paired device
    "lockdown": [
        "SystemConfiguration/com.apple.network.identification.plist",
        "lockdown",
    ],
}


def check_bfu_afu(zip_path: str, log_cb=None) -> dict:
    log = log_cb or (lambda m: None)
    result = {
        "verdict":       "UNKNOWN",
        "confidence":    0,
        "afu_dbs_found": [],
        "afu_dbs_missing": [],
        "keychain_found": [],
        "lockdown_found": [],
        "total_files":   0,
        "db_files":      0,
        "notes":         [],
    }

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            all_files = [i.filename for i in zf.infolist() if not i.is_dir()]
            result["total_files"] = len(all_files)
            all_lower = [f.lower() for f in all_files]

            # Check AFU databases
            for db in BFU_INDICATORS["afu_dbs"]:
                found = any(db.lower() in f for f in all_lower)
                if found:
                    result["afu_dbs_found"].append(db)
                    log(f"  [AFU indicator] Found: {db}")
                else:
                    result["afu_dbs_missing"].append(db)

            # Check keychain
            for kc in BFU_INDICATORS["keychain"]:
                if any(kc.lower() in f for f in all_lower):
                    result["keychain_found"].append(kc)
                    log(f"  [Keychain] Found: {kc}")

            # Check lockdown
            for ld in BFU_INDICATORS["lockdown"]:
                if any(ld.lower() in f for f in all_lower):
                    result["lockdown_found"].append(ld)
                    log(f"  [Lockdown] Found: {ld}")

            # Count SQLite files
            result["db_files"] = sum(
                1 for f in all_lower
                if any(f.endswith(e) for e in
                       (".db", ".sqlite", ".sqlitedb", ".storedata"))
            )

    except Exception as e:
        log(f"  ERROR: {e}")
        result["notes"].append(f"Error: {e}")
        return result

    # Verdict logic
    afu_score  = len(result["afu_dbs_found"])
    kc_score   = len(result["keychain_found"]) * 3
    total_afu  = len(BFU_INDICATORS["afu_dbs"])

    if afu_score >= 5 or kc_score >= 3:
        result["verdict"]    = "AFU — After First Unlock"
        result["confidence"] = min(int((afu_score / total_afu) * 80
                                       + kc_score * 5), 99)
        result["notes"].append(
            f"Found {afu_score}/{total_afu} key databases.")
        if result["keychain_found"]:
            result["notes"].append("Keychain present — decrypted data available.")
    elif afu_score >= 2:
        result["verdict"]    = "AFU (partial) — likely AFU but limited data"
        result["confidence"] = int((afu_score / total_afu) * 60)
        result["notes"].append(
            f"Only {afu_score}/{total_afu} key databases found.")
        result["notes"].append(
            "Extraction may be incomplete or from encrypted backup.")
    else:
        result["verdict"]    = "BFU — Before First Unlock (or encrypted)"
        result["confidence"] = max(0, 80 - afu_score * 15)
        result["notes"].append(
            "Very few readable databases found.")
        result["notes"].append(
            "Device was likely locked during extraction, or backup is encrypted.")

    return result


# =============================================================================
# LOCKDOWN CERTIFICATES — logic
# =============================================================================

def parse_lockdown_certs(zip_path: str, log_cb=None) -> list[dict]:
    log = log_cb or (lambda m: None)
    results = []

    lockdown_patterns = [
        "lockdown",
        "com.apple.mobile.lockdown",
        "MobileDevice/ProvisioningProfiles",
        "SystemConfiguration",
    ]

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            candidates = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                fname_lower = info.filename.lower()
                if (fname_lower.endswith(".plist") and
                        any(p.lower() in fname_lower
                            for p in lockdown_patterns)):
                    candidates.append(info)

            log(f"[Lockdown] Found {len(candidates)} candidate plist files")

            for info in candidates:
                log(f"[Lockdown] Parsing: {info.filename}")
                try:
                    data = zf.read(info.filename)
                    plist = plistlib.loads(data)

                    rec = {
                        "file":         info.filename,
                        "DeviceName":   "",
                        "UDID":         "",
                        "ProductType":  "",
                        "BuildVersion": "",
                        "SystemPartitionLoggable": "",
                        "UniqueChipID": "",
                        "WiFiAddress":  "",
                        "BluetoothAddress": "",
                        "PairedDate":   "",
                        "HostID":       "",
                        "HostName":     "",
                        "raw_keys":     "",
                    }

                    for key in rec:
                        if key in plist:
                            rec[key] = str(plist[key])

                    # Extra fields from nested dicts
                    for nested_key in ["DevicePublicKey",
                                       "HostCertificate",
                                       "RootCertificate"]:
                        if nested_key in plist:
                            rec["raw_keys"] += f"{nested_key}=present;"

                    # Collect all top-level keys for reference
                    rec["raw_keys"] += " | ".join(
                        f"{k}={str(v)[:40]}"
                        for k, v in plist.items()
                        if k not in rec and
                        not isinstance(v, (bytes, dict, list))
                    )

                    results.append(rec)
                    log(f"  UDID={rec['UDID']} "
                        f"Device={rec['DeviceName']} "
                        f"Host={rec['HostName']}")

                except Exception as e:
                    log(f"  ERROR parsing {info.filename}: {e}")

    except Exception as e:
        log(f"[Lockdown] Cannot open ZIP: {e}")

    return results


# =============================================================================
# LEET SPEAK GENERATOR — logic
# =============================================================================

# Substitution maps per level
LEET_L1 = {
    "a": ["4"], "e": ["3"], "i": ["1"],
    "o": ["0"], "s": ["5"], "t": ["7"],
    "b": ["8"], "g": ["9"], "l": ["1"],
    "A": ["4"], "E": ["3"], "I": ["1"],
    "O": ["0"], "S": ["5"], "T": ["7"],
    "B": ["8"], "G": ["9"], "L": ["1"],
}
LEET_L2 = {
    **LEET_L1,
    "a": ["4", "@"],  "i": ["1", "!"],
    "s": ["5", "$"],  "e": ["3"],
    "A": ["4", "@"],  "I": ["1", "!"],
    "S": ["5", "$"],
}
LEET_L3 = {
    "a": ["4", "@", "/-\\"], "e": ["3"],
    "i": ["1", "!", "|"],    "o": ["0", "()"],
    "s": ["5", "$", "z"],    "t": ["7", "+"],
    "b": ["8", "|3"],        "g": ["9", "6"],
    "l": ["1", "|_"],        "c": ["(", "<"],
    "k": ["|<", "|("],       "n": ["|\\|"],
    "A": ["4", "@"],         "E": ["3"],
    "I": ["1", "!"],         "O": ["0"],
    "S": ["5", "$"],         "T": ["7"],
    "B": ["8"],              "G": ["9"],
    "L": ["1"],
}

LEET_MAPS = {"1": LEET_L1, "2": LEET_L2, "3": LEET_L3}
MAX_LEET_VARIANTS = 500_000  # safety cap per word


def generate_leet_variants(word: str, level: str = "2") -> list[str]:
    """Generate all leet speak variants for a word at given level."""
    leet_map = LEET_MAPS.get(level, LEET_L2)

    # Build list of options for each character
    char_options = []
    for ch in word:
        if ch in leet_map:
            opts = [ch] + leet_map[ch]  # always include original
        else:
            opts = [ch]
        char_options.append(opts)

    # Count total combinations
    total = 1
    for opts in char_options:
        total *= len(opts)
        if total > MAX_LEET_VARIANTS:
            total = MAX_LEET_VARIANTS
            break

    # Generate via iterative product (memory-safe)
    variants = set()
    variants.add(word)  # always include original

    def _product(options):
        result = [""]
        for opts in options:
            result = [r + o for r in result for o in opts]
            if len(result) > MAX_LEET_VARIANTS:
                result = result[:MAX_LEET_VARIANTS]
                break
        return result

    try:
        all_variants = _product(char_options)
        variants.update(all_variants)
    except MemoryError:
        pass

    return list(variants)


# =============================================================================
# TIMESTAMP CONVERTER — logic
# =============================================================================

# Apple NSDate epoch: 2001-01-01
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
# Windows FILETIME epoch: 1601-01-01
WIN_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# Chrome/WebKit epoch: 1601-01-01 (microseconds)
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# HFS+ epoch: 1904-01-01
HFS_EPOCH = datetime(1904, 1, 1, tzinfo=timezone.utc)
# Unix epoch
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def convert_timestamp(value_str: str) -> list[dict]:
    """Try all known timestamp formats and return interpretations."""
    results = []
    value_str = value_str.strip()

    # Try to parse as number
    try:
        val = float(value_str)
    except ValueError:
        return [{"format": "ERROR", "utc": "Not a valid number",
                 "local": "", "note": ""}]

    now = datetime.now(tz=timezone.utc)

    def _fmt(dt: datetime) -> tuple[str, str]:
        if dt is None:
            return "—", "—"
        try:
            utc_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            local_dt = dt.astimezone()
            local_str = local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
            return utc_str, local_str
        except (OSError, OverflowError, ValueError):
            return "Out of range", "—"

    def _plausible(dt: datetime) -> bool:
        """Check if datetime is within reasonable forensic range."""
        try:
            return (datetime(1995, 1, 1, tzinfo=timezone.utc) <= dt
                    <= datetime(2040, 1, 1, tzinfo=timezone.utc))
        except (OSError, OverflowError):
            return False

    # Unix seconds
    try:
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        utc, local = _fmt(dt)
        results.append({
            "format": "Unix (seconds)",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        results.append({"format": "Unix (seconds)", "utc": "Out of range",
                        "local": "", "note": ""})

    # Unix milliseconds
    try:
        dt = datetime.fromtimestamp(val / 1000, tz=timezone.utc)
        utc, local = _fmt(dt)
        results.append({
            "format": "Unix (milliseconds)",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # Unix microseconds
    try:
        dt = datetime.fromtimestamp(val / 1_000_000, tz=timezone.utc)
        utc, local = _fmt(dt)
        results.append({
            "format": "Unix (microseconds)",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # Apple NSDate (seconds since 2001-01-01)
    try:
        dt = APPLE_EPOCH + timedelta(seconds=val)
        utc, local = _fmt(dt)
        results.append({
            "format": "Apple NSDate / CoreData",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    try:
        dt = WIN_EPOCH + timedelta(microseconds=val / 10)
        utc, local = _fmt(dt)
        results.append({
            "format": "Windows FILETIME",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # Chrome / WebKit (microseconds since 1601-01-01)
    try:
        dt = CHROME_EPOCH + timedelta(microseconds=val)
        utc, local = _fmt(dt)
        results.append({
            "format": "Chrome / WebKit timestamp",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # HFS+ (seconds since 1904-01-01)
    try:
        dt = HFS_EPOCH + timedelta(seconds=val)
        utc, local = _fmt(dt)
        results.append({
            "format": "HFS+ / Mac OS",
            "utc": utc, "local": local,
            "note": "✓ plausible" if _plausible(dt) else "⚠ out of range",
        })
    except (OSError, OverflowError, ValueError):
        pass

    # Mark best guesses
    plausible = [r for r in results if "✓" in r.get("note", "")]
    if len(plausible) == 1:
        plausible[0]["note"] += " ← BEST MATCH"
    elif len(plausible) > 1:
        # Prefer the one where value magnitude makes most sense
        for r in plausible:
            if "Unix (seconds)" in r["format"] and 1e9 < val < 2e9:
                r["note"] += " ← BEST MATCH"
                break
            elif "Apple" in r["format"] and 0 < val < 1e9:
                r["note"] += " ← BEST MATCH"
                break

    return results


# =============================================================================
# URL / URI DECODER — logic
# =============================================================================

def decode_url(raw: str) -> dict:
    """Decode a URL/URI and extract all components."""
    raw = raw.strip()
    result = {
        "original":   raw,
        "decoded":    "",
        "scheme":     "",
        "host":       "",
        "path":       "",
        "params":     {},
        "fragments":  [],
        "base64_in_params": {},
        "jwt_found":  [],
        "sensitive":  [],
        "deep_link":  False,
        "notes":      [],
    }

    # Percent-decode
    try:
        result["decoded"] = urllib.parse.unquote(raw)
    except Exception:
        result["decoded"] = raw

    # Parse components
    try:
        parsed = urllib.parse.urlparse(result["decoded"])
        result["scheme"] = parsed.scheme
        result["host"]   = parsed.netloc
        result["path"]   = parsed.path

        # Query params
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query,
                                           keep_blank_values=True)
            result["params"] = {k: v[0] if len(v) == 1 else v
                                for k, v in params.items()}

        # Fragment
        if parsed.fragment:
            result["fragments"].append(parsed.fragment)

    except Exception as e:
        result["notes"].append(f"Parse error: {e}")

    # Deep link detection
    non_http = result["scheme"] not in ("", "http", "https",
                                        "ftp", "ftps", "file")
    if non_http and result["scheme"]:
        result["deep_link"] = True
        result["notes"].append(
            f"Deep link / custom scheme: {result['scheme']}://")

    # Base64 in params
    b64_re = re.compile(r"[A-Za-z0-9+/=]{16,}")
    b64url_re = re.compile(r"[A-Za-z0-9\-_]{16,}")
    for key, val in result["params"].items():
        val_str = str(val)
        for m in b64_re.findall(val_str) + b64url_re.findall(val_str):
            try:
                dec = base64.b64decode(m + "==")
                if len(dec) > 2:
                    txt = dec.decode("utf-8", errors="replace")
                    result["base64_in_params"][key] = \
                        f"{m[:30]}… → {txt[:60]}"
            except Exception:
                pass

    # JWT detection in params and path
    jwt_re = re.compile(
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
    full_url = result["decoded"]
    for m in jwt_re.finditer(full_url):
        parts = m.group().split(".")
        try:
            payload = base64.urlsafe_b64decode(
                parts[1] + "==").decode("utf-8", errors="replace")
            result["jwt_found"].append(
                {"token_preview": m.group()[:40] + "…",
                 "payload_preview": payload[:120]})
        except Exception:
            result["jwt_found"].append(
                {"token_preview": m.group()[:40] + "…",
                 "payload_preview": "?"})

    # Sensitive param detection
    sensitive_keys = {
        "password", "passwd", "pass", "pwd", "secret",
        "token", "access_token", "api_key", "apikey",
        "auth", "authorization", "key", "pin", "code",
        "session", "sessionid", "sid", "ssn", "credit_card",
    }
    for key in result["params"]:
        if key.lower() in sensitive_keys:
            result["sensitive"].append(key)

    return result


# =============================================================================
# TAB BUILDERS
# =============================================================================

def _build_tab_hashid(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_hashid_info"),
              wraplength=900).pack(fill="x", **pad)

    inp_frame = ttk.LabelFrame(f, text=self._("lbl_hashid_input"))
    inp_frame.pack(fill="x", **pad)
    self.hashid_input_var = tk.StringVar()
    inp_row = ttk.Frame(inp_frame)
    inp_row.pack(fill="x", padx=4, pady=4)
    ttk.Entry(inp_row, textvariable=self.hashid_input_var,
              width=80, font=("Consolas", 10)).pack(
        side="left", padx=4, fill="x", expand=True)
    tk.Button(inp_row, text=self._("btn_hashid_run"),
              bg=self.theme["run_bg"], fg=self.theme["run_fg"],
              font=("Arial", 10, "bold"),
              command=self.run_hashid).pack(side="left", padx=4)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    tk.Button(btn_row, text=self._("btn_hashid_file"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.run_hashid_file).pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(
                  self.txt_hashid_log)).pack(side="left", padx=4)

    self.progress_hashid = ttk.Progressbar(
        f, mode="determinate", length=600)
    self.progress_hashid.pack(fill="x", **pad)

    self.txt_hashid_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=20)
    self.txt_hashid_log.pack(fill="both", expand=True, **pad)


def run_hashid(self):
    h = self.hashid_input_var.get().strip()
    if not h:
        messagebox.showwarning("", self._("msg_no_input"))
        return
    matches = identify_hash(h)
    self.log_to(self.txt_hashid_log,
                f"\n[Hash] Input: {h[:80]}")
    self.log_to(self.txt_hashid_log,
                f"[Hash] Length: {len(h)} chars")
    self.log_to(self.txt_hashid_log, "─" * 60)
    for m in matches:
        self.log_to(self.txt_hashid_log,
                    f"  Type:   {m['type']}")
        self.log_to(self.txt_hashid_log,
                    f"  Info:   {m['info']}")
        self.log_to(self.txt_hashid_log, "")


def run_hashid_file(self):
    path = filedialog.askopenfilename(
        filetypes=[("txt", "*.txt;*.lst"), ("All", "*.*")])
    if not path:
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.set_progress(self.progress_hashid, 0, len(lines))
        for i, h in enumerate(lines):
            matches = identify_hash(h)
            types = ", ".join(m["type"] for m in matches)
            self.log_to(self.txt_hashid_log,
                        f"{h[:50]:50s}  →  {types}")
            if i % 100 == 0:
                self.set_progress(
                    self.progress_hashid, i, len(lines))
        self.set_progress(
            self.progress_hashid, len(lines), len(lines))
        self.log_to(self.txt_hashid_log,
                    f"\n[Hash] Done. {len(lines)} hashes analyzed.")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_bfuafu(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_bfuafu_info"),
              wraplength=900).pack(fill="x", **pad)

    file_frame = ttk.LabelFrame(f, text=self._("lbl_bfuafu_zip"))
    file_frame.pack(fill="x", **pad)
    self._make_file_row(file_frame, self.bfuafu_zip_path,
                        self._browse_bfuafu, "bfuafu")

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_run_bfuafu = tk.Button(
        btn_row, text=self._("btn_bfuafu_run"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_bfuafu)
    self.btn_run_bfuafu.pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(
                  self.txt_bfuafu_log)).pack(side="left", padx=4)

    # Verdict display
    verdict_frame = ttk.LabelFrame(f, text="Verdict")
    verdict_frame.pack(fill="x", **pad)
    self.bfuafu_verdict_var = tk.StringVar(value="—")
    self.bfuafu_verdict_lbl = tk.Label(
        verdict_frame, textvariable=self.bfuafu_verdict_var,
        font=("Arial", 14, "bold"), anchor="w", pady=6)
    self.bfuafu_verdict_lbl.pack(fill="x", padx=10)

    self.progress_bfuafu = ttk.Progressbar(
        f, mode="indeterminate", length=600)
    self.progress_bfuafu.pack(fill="x", **pad)

    self.txt_bfuafu_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=16)
    self.txt_bfuafu_log.pack(fill="both", expand=True, **pad)


def _browse_bfuafu(self):
    p = filedialog.askopenfilename(
        filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
    if p:
        self.bfuafu_zip_path.set(p)
        self.config_mgr.add_recent("bfuafu", p)
        self._rebuild_recent_menu()


def run_bfuafu(self):
    path = self.bfuafu_zip_path.get().strip()
    if not path:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    self.btn_run_bfuafu.config(state="disabled")
    self.progress_bfuafu.start(10)
    self.bfuafu_verdict_var.set("Analyzing...")

    def log(m): self.log_to(self.txt_bfuafu_log, m)

    try:
        log(f"\n[BFU/AFU] Scanning: {path}")
        result = check_bfu_afu(path, log_cb=log)

        verdict = result["verdict"]
        conf    = result["confidence"]
        self.bfuafu_verdict_var.set(
            f"{verdict}  (confidence: {conf}%)")

        # Color verdict
        color = "#005500" if "AFU" in verdict else "#cc0000"
        if "partial" in verdict:
            color = "#c8a000"
        self.bfuafu_verdict_lbl.config(foreground=color)

        log(f"\n{'='*60}")
        log(f"VERDICT: {verdict}")
        log(f"Confidence: {conf}%")
        log(f"Total files in ZIP: {result['total_files']}")
        log(f"SQLite/DB files found: {result['db_files']}")
        log(f"\nAFU databases found ({len(result['afu_dbs_found'])}):")
        for db in result["afu_dbs_found"]:
            log(f"  ✓ {db}")
        if result["afu_dbs_missing"]:
            log(f"\nMissing databases ({len(result['afu_dbs_missing'])}):")
            for db in result["afu_dbs_missing"][:5]:
                log(f"  ✗ {db}")
        if result["keychain_found"]:
            log(f"\nKeychain files found:")
            for kc in result["keychain_found"]:
                log(f"  🔑 {kc}")
        if result["lockdown_found"]:
            log(f"\nLockdown files found:")
            for ld in result["lockdown_found"]:
                log(f"  🔒 {ld}")
        log(f"\nNotes:")
        for note in result["notes"]:
            log(f"  • {note}")
        log(f"{'='*60}")

    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.progress_bfuafu.stop()
        self.btn_run_bfuafu.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_lockdown(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_lockdown_info"),
              wraplength=900).pack(fill="x", **pad)

    file_frame = ttk.LabelFrame(f, text=self._("lbl_lockdown_zip"))
    file_frame.pack(fill="x", **pad)
    self._make_file_row(file_frame, self.lockdown_zip_path,
                        self._browse_lockdown, "lockdown")

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_run_lockdown = tk.Button(
        btn_row, text=self._("btn_lockdown_run"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_lockdown_parse)
    self.btn_run_lockdown.pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_lockdown_csv"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.export_lockdown_csv).pack(
        side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(
                  self.txt_lockdown_log)).pack(side="left", padx=4)

    self.progress_lockdown = ttk.Progressbar(
        f, mode="indeterminate", length=600)
    self.progress_lockdown.pack(fill="x", **pad)

    # Treeview for results
    tree_frame = ttk.Frame(f)
    tree_frame.pack(fill="x", **pad)
    cols = ("file", "UDID", "DeviceName", "ProductType",
            "BuildVersion", "HostName", "HostID")
    self.lockdown_tree = ttk.Treeview(
        tree_frame, columns=cols, show="headings", height=8)
    widths = {"file": 200, "UDID": 150, "DeviceName": 120,
              "ProductType": 80, "BuildVersion": 80,
              "HostName": 120, "HostID": 120}
    for col in cols:
        self.lockdown_tree.heading(col, text=col)
        self.lockdown_tree.column(col, width=widths.get(col, 100))
    hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                        command=self.lockdown_tree.xview)
    vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                        command=self.lockdown_tree.yview)
    self.lockdown_tree.configure(xscrollcommand=hsb.set,
                                 yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    hsb.pack(side="bottom", fill="x")
    self.lockdown_tree.pack(fill="x")

    self.txt_lockdown_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=8)
    self.txt_lockdown_log.pack(fill="both", expand=True, **pad)
    self._lockdown_results: list = []


def _browse_lockdown(self):
    p = filedialog.askopenfilename(
        filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
    if p:
        self.lockdown_zip_path.set(p)
        self.config_mgr.add_recent("lockdown", p)
        self._rebuild_recent_menu()


def run_lockdown_parse(self):
    path = self.lockdown_zip_path.get().strip()
    if not path:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    self.btn_run_lockdown.config(state="disabled")
    self.progress_lockdown.start(10)
    self.lockdown_tree.delete(*self.lockdown_tree.get_children())

    def log(m): self.log_to(self.txt_lockdown_log, m)

    try:
        self._lockdown_results = parse_lockdown_certs(
            path, log_cb=log)
        cols = ("file", "UDID", "DeviceName", "ProductType",
                "BuildVersion", "HostName", "HostID")
        for rec in self._lockdown_results:
            self.lockdown_tree.insert(
                "", "end",
                values=tuple(rec.get(c, "")[:60] for c in cols))
        log(f"\n[Lockdown] Found {len(self._lockdown_results)} records.")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.progress_lockdown.stop()
        self.btn_run_lockdown.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


def export_lockdown_csv(self):
    if not self._lockdown_results:
        messagebox.showwarning("", "No data. Run parse first.")
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv")])
    if not out:
        return
    keys = ["file", "UDID", "DeviceName", "ProductType",
            "BuildVersion", "WiFiAddress", "BluetoothAddress",
            "UniqueChipID", "HostName", "HostID",
            "PairedDate", "raw_keys"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(self._lockdown_results)
    messagebox.showinfo("", self._("report_saved").format(path=out))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_leet(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_leet_info"),
              wraplength=900).pack(fill="x", **pad)

    # Input
    inp_frame = ttk.LabelFrame(f, text=self._("lbl_leet_input"))
    inp_frame.pack(fill="x", **pad)
    self.txt_leet_input = scrolledtext.ScrolledText(
        inp_frame, height=4, font=("Consolas", 10))
    self.txt_leet_input.pack(fill="x", padx=4, pady=4)

    file_row = ttk.Frame(f)
    file_row.pack(fill="x", **pad)
    ttk.Label(file_row, text=self._("lbl_leet_file")).pack(
        side="left")
    self._make_file_row(file_row, self.leet_file_path,
                        self._browse_leet_file, None)

    # Level selector
    lvl_frame = ttk.LabelFrame(f, text=self._("lbl_leet_level"))
    lvl_frame.pack(fill="x", **pad)
    self.leet_level_var = tk.StringVar(value="2")
    for val, key in [("1", "lbl_leet_lvl1"),
                     ("2", "lbl_leet_lvl2"),
                     ("3", "lbl_leet_lvl3")]:
        ttk.Radiobutton(lvl_frame, text=self._(key),
                        variable=self.leet_level_var,
                        value=val).pack(anchor="w", padx=8, pady=2)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_run_leet = tk.Button(
        btn_row, text=self._("btn_leet_run"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_leet_gen)
    self.btn_run_leet.pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_leet_save"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.save_leet_dict).pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=self._clear_leet).pack(side="left", padx=4)
    self.leet_count_lbl = ttk.Label(btn_row, text="")
    self.leet_count_lbl.pack(side="left", padx=10)

    self.progress_leet = ttk.Progressbar(
        f, mode="determinate", length=600)
    self.progress_leet.pack(fill="x", **pad)

    self.txt_leet_out = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=12)
    self.txt_leet_out.pack(fill="both", expand=True, **pad)
    self._leet_results: list = []


def _browse_leet_file(self):
    p = filedialog.askopenfilename(
        filetypes=[("txt", "*.txt;*.lst"), ("All", "*.*")])
    if p:
        self.leet_file_path.set(p)


def _clear_leet(self):
    self._clear_widget(self.txt_leet_out)
    self._leet_results = []
    self.leet_count_lbl.config(text="")


def run_leet_gen(self):
    # Get words from textbox or file
    words = []
    text_input = self.txt_leet_input.get("1.0", "end").strip()
    if text_input:
        words = [w.strip() for w in text_input.splitlines() if w.strip()]
    elif self.leet_file_path.get():
        try:
            with open(self.leet_file_path.get(),
                      encoding="utf-8", errors="replace") as f:
                words = [l.strip() for l in f if l.strip()]
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
            return
    if not words:
        messagebox.showwarning("", self._("msg_no_input"))
        return

    level = self.leet_level_var.get()
    self.btn_run_leet.config(state="disabled")
    self.set_progress(self.progress_leet, 0, len(words))
    self._leet_results = []

    try:
        self._clear_widget(self.txt_leet_out)
        for i, word in enumerate(words):
            variants = generate_leet_variants(word, level)
            self._leet_results.extend(variants)
            self.set_progress(self.progress_leet, i + 1, len(words))
            # Show first few
            if i < 3:
                for v in list(variants)[:10]:
                    self.txt_leet_out.insert("end", v + "\n")
                if len(variants) > 10:
                    self.txt_leet_out.insert(
                        "end",
                        f"  ... and {len(variants)-10} more for '{word}'\n")
        total = len(self._leet_results)
        self.leet_count_lbl.config(
            text=self._("lbl_leet_count").format(count=f"{total:,}"))
        self.log_to(self.txt_leet_out,
                    f"\n[Leet] Total variants: {total:,}")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.btn_run_leet.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


def save_leet_dict(self):
    if not self._leet_results:
        messagebox.showwarning("", "Generate first.")
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("txt", "*.txt")])
    if not out:
        return
    # Deduplicate before saving
    unique = list(dict.fromkeys(self._leet_results))
    with open(out, "w", encoding="utf-8") as f:
        for w in unique:
            f.write(w + "\n")
    messagebox.showinfo(
        "", self._("report_saved").format(path=out)
        + f"\n{len(unique):,} unique entries.")


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_timestamp(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_ts_info"),
              wraplength=900).pack(fill="x", **pad)

    inp_frame = ttk.LabelFrame(f, text=self._("lbl_ts_input"))
    inp_frame.pack(fill="x", **pad)
    inp_row = ttk.Frame(inp_frame)
    inp_row.pack(fill="x", padx=4, pady=4)
    self.ts_input_var = tk.StringVar()
    ttk.Entry(inp_row, textvariable=self.ts_input_var,
              width=40, font=("Consolas", 11)).pack(
        side="left", padx=4)
    tk.Button(inp_row, text=self._("btn_ts_run"),
              bg=self.theme["run_bg"], fg=self.theme["run_fg"],
              font=("Arial", 10, "bold"),
              command=self.run_ts_convert).pack(side="left", padx=4)
    tk.Button(inp_row, text="Now → Unix",
              command=self._ts_insert_now).pack(side="left", padx=4)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    tk.Button(btn_row, text=self._("btn_ts_file"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.run_ts_file).pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(
                  self.txt_ts_log)).pack(side="left", padx=4)

    self.progress_ts = ttk.Progressbar(
        f, mode="determinate", length=600)
    self.progress_ts.pack(fill="x", **pad)

    self.txt_ts_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=22)
    self.txt_ts_log.pack(fill="both", expand=True, **pad)


def _ts_insert_now(self):
    import time
    self.ts_input_var.set(str(int(time.time())))


def run_ts_convert(self):
    val = self.ts_input_var.get().strip()
    if not val:
        messagebox.showwarning("", self._("msg_no_input"))
        return
    results = convert_timestamp(val)
    self.log_to(self.txt_ts_log,
                f"\n[TS] Input: {val}")
    self.log_to(self.txt_ts_log, "─" * 70)
    for r in results:
        note = f"  {r.get('note', '')}" if r.get("note") else ""
        self.log_to(
            self.txt_ts_log,
            f"  {r['format']:<35} {r['utc']}{note}")
    self.log_to(self.txt_ts_log, "")


def run_ts_file(self):
    path = filedialog.askopenfilename(
        filetypes=[("txt/csv", "*.txt;*.csv;*.log"), ("All", "*.*")])
    if not path:
        return
    # Find all numeric sequences in file that look like timestamps
    ts_re = re.compile(r"\b(\d{9,19}(?:\.\d+)?)\b")
    found = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                for m in ts_re.finditer(line):
                    found.append((lineno, m.group()))
        self.set_progress(self.progress_ts, 0, len(found))
        self.log_to(self.txt_ts_log,
                    f"\n[TS File] Found {len(found)} timestamp candidates")
        for i, (lineno, val) in enumerate(found[:500]):
            results = convert_timestamp(val)
            # Show only plausible results
            plausible = [r for r in results if "✓" in r.get("note", "")]
            if plausible:
                best = plausible[0]
                self.log_to(
                    self.txt_ts_log,
                    f"  L{lineno:5d}: {val:>20}  →  "
                    f"{best['format']}: {best['utc']}")
            if i % 50 == 0:
                self.set_progress(
                    self.progress_ts, i, len(found))
        self.set_progress(
            self.progress_ts, len(found), len(found))
        if len(found) > 500:
            self.log_to(self.txt_ts_log,
                        f"  ... (showing first 500 of {len(found)})")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_urldecoder(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_url_info"),
              wraplength=900).pack(fill="x", **pad)

    inp_frame = ttk.LabelFrame(f, text=self._("lbl_url_input"))
    inp_frame.pack(fill="x", **pad)
    self.url_input_txt = scrolledtext.ScrolledText(
        inp_frame, height=4, font=("Consolas", 9))
    self.url_input_txt.pack(fill="x", padx=4, pady=4)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    tk.Button(btn_row, text=self._("btn_url_run"),
              bg=self.theme["run_bg"], fg=self.theme["run_fg"],
              font=("Arial", 10, "bold"),
              command=self.run_url_decode).pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_url_file"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.run_url_decode_file).pack(
        side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_url_clear"),
              command=self._clear_url).pack(side="left", padx=4)

    self.progress_url = ttk.Progressbar(
        f, mode="determinate", length=600)
    self.progress_url.pack(fill="x", **pad)

    out_frame = ttk.LabelFrame(f, text=self._("lbl_url_result"))
    out_frame.pack(fill="both", expand=True, **pad)
    self.txt_url_out = scrolledtext.ScrolledText(
        out_frame, font=("Consolas", 9), height=18)
    self.txt_url_out.pack(fill="both", expand=True, padx=4, pady=4)
    self.txt_url_out.tag_configure(
        "warn", foreground="#cc0000", font=("Consolas", 9, "bold"))
    self.txt_url_out.tag_configure(
        "good", foreground="#005500")


def _clear_url(self):
    self.url_input_txt.delete("1.0", "end")
    self._clear_widget(self.txt_url_out)


def _display_url_result(self, r: dict):
    w = self.txt_url_out
    w.insert("end", f"\n{'─'*70}\n")
    w.insert("end", f"Original:  {r['original'][:100]}\n")
    w.insert("end", f"Decoded:   {r['decoded'][:200]}\n")
    if r["scheme"]:
        tag = "warn" if r["deep_link"] else "good"
        w.insert("end",
                 f"Scheme:    {r['scheme']}  "
                 f"{'← DEEP LINK' if r['deep_link'] else ''}\n",
                 tag)
    if r["host"]:
        w.insert("end", f"Host:      {r['host']}\n")
    if r["path"]:
        w.insert("end", f"Path:      {r['path']}\n")
    if r["params"]:
        w.insert("end", "Parameters:\n")
        for k, v in r["params"].items():
            sensitive = k in r["sensitive"]
            tag = "warn" if sensitive else ""
            w.insert("end",
                     f"  {k} = {str(v)[:80]}"
                     f"{'  ⚠ SENSITIVE' if sensitive else ''}\n",
                     tag)
    if r["base64_in_params"]:
        w.insert("end", "Base64 in params:\n", "warn")
        for k, v in r["base64_in_params"].items():
            w.insert("end", f"  {k}: {v[:100]}\n", "warn")
    if r["jwt_found"]:
        w.insert("end", f"JWT tokens found: {len(r['jwt_found'])}\n",
                 "warn")
        for j in r["jwt_found"]:
            w.insert("end",
                     f"  {j['token_preview']}\n"
                     f"  payload: {j['payload_preview'][:80]}\n",
                     "warn")
    if r["notes"]:
        for note in r["notes"]:
            w.insert("end", f"  ℹ {note}\n")
    w.see("end")


def run_url_decode(self):
    raw = self.url_input_txt.get("1.0", "end").strip()
    if not raw:
        messagebox.showwarning("", self._("msg_no_input"))
        return
    for line in raw.splitlines():
        if line.strip():
            r = decode_url(line.strip())
            self._display_url_result(r)


def run_url_decode_file(self):
    path = filedialog.askopenfilename(
        filetypes=[("txt/log", "*.txt;*.log;*.csv"), ("All", "*.*")])
    if not path:
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.set_progress(self.progress_url, 0, len(lines))
        for i, line in enumerate(lines):
            r = decode_url(line)
            self._display_url_result(r)
            if i % 20 == 0:
                self.set_progress(self.progress_url, i, len(lines))
        self.set_progress(self.progress_url, len(lines), len(lines))
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))


# =============================================================================
# PATCH FUNCTION
# =============================================================================

def patch_v27(app_class, translations_dict: dict,
              layout_groups: list):
    """
    Apply v2.7 patch.
    Call after patch_app() and patch_layout_b().
    layout_groups = GROUPS list from b64toolkit_layout_b
    """
    import types

    # 1. Inject translations
    for lang, keys in V27_TRANSLATIONS.items():
        if lang in translations_dict:
            translations_dict[lang].update(keys)

    # 2. Inject methods
    method_map = {
        "_build_tab_hashid":     _build_tab_hashid,
        "run_hashid":            run_hashid,
        "run_hashid_file":       run_hashid_file,
        "_build_tab_bfuafu":     _build_tab_bfuafu,
        "_browse_bfuafu":        _browse_bfuafu,
        "run_bfuafu":            run_bfuafu,
        "_build_tab_lockdown":   _build_tab_lockdown,
        "_browse_lockdown":      _browse_lockdown,
        "run_lockdown_parse":    run_lockdown_parse,
        "export_lockdown_csv":   export_lockdown_csv,
        "_build_tab_leet":       _build_tab_leet,
        "_browse_leet_file":     _browse_leet_file,
        "_clear_leet":           _clear_leet,
        "run_leet_gen":          run_leet_gen,
        "save_leet_dict":        save_leet_dict,
        "_build_tab_timestamp":  _build_tab_timestamp,
        "_ts_insert_now":        _ts_insert_now,
        "run_ts_convert":        run_ts_convert,
        "run_ts_file":           run_ts_file,
        "_build_tab_urldecoder": _build_tab_urldecoder,
        "_clear_url":            _clear_url,
        "_display_url_result":   _display_url_result,
        "run_url_decode":        run_url_decode,
        "run_url_decode_file":   run_url_decode_file,
    }
    for name, func in method_map.items():
        setattr(app_class, name, func)

    # 3. Patch _build_notebook to init new state vars + add new tabs
    original_build_nb = app_class._build_notebook

    def new_build_nb_v27(self):
        # Init new state vars
        import tkinter as _tk
        self.bfuafu_zip_path   = _tk.StringVar()
        self.lockdown_zip_path = _tk.StringVar()
        self.leet_file_path    = _tk.StringVar()
        self.ts_input_var      = _tk.StringVar()
        self.hashid_input_var  = _tk.StringVar()
        self.leet_level_var    = _tk.StringVar(value="2")
        self._lockdown_results = []
        self._leet_results     = []

        original_build_nb(self)

        # Add new tabs to correct groups
        additions = {
            "group_analysis": [
                ("tab_hashid",    "_build_tab_hashid"),
                ("tab_bfuafu",    "_build_tab_bfuafu"),
                ("tab_lockdown",  "_build_tab_lockdown"),
            ],
            "group_dicts": [
                ("tab_leet",      "_build_tab_leet"),
            ],
            "group_tools": [
                ("tab_timestamp", "_build_tab_timestamp"),
                ("tab_urldecoder","_build_tab_urldecoder"),
            ],
        }

        for group_key, tabs in additions.items():
            inner_nb = self._sub_notebooks.get(group_key)
            if inner_nb is None:
                continue
            for tab_key, builder_name in tabs:
                label = self.T.get(tab_key, tab_key)
                frame = ttk.Frame(inner_nb)
                inner_nb.add(frame, text=label)
                self.tab_frames[tab_key] = frame
                getattr(self, builder_name)(frame)

    app_class._build_notebook = new_build_nb_v27

    # 4. Patch lang change to update new tab labels
    original_lang = app_class._on_lang_change

    def new_lang_v27(self, _=None):
        original_lang(self, _)
        new_tabs = {
            "group_analysis": ["tab_hashid", "tab_bfuafu", "tab_lockdown"],
            "group_dicts":    ["tab_leet"],
            "group_tools":    ["tab_timestamp", "tab_urldecoder"],
        }
        for group_key, tab_keys in new_tabs.items():
            inner_nb = self._sub_notebooks.get(group_key)
            if not inner_nb:
                continue
            # Get all tabs in this inner notebook
            all_tabs = list(inner_nb.tabs())
            tab_count = len(all_tabs)
            # New tabs are at the end
            n_new = len(tab_keys)
            start_idx = tab_count - n_new
            for i, tab_key in enumerate(tab_keys):
                try:
                    inner_nb.tab(start_idx + i,
                                 text=self.T.get(tab_key, tab_key))
                except Exception:
                    pass

    app_class._on_lang_change = new_lang_v27
