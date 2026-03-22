#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Base64 Forensic Toolkit v2.6 — NEW TABS EXTENSION
# Adds to v2.5:
#   Tab 10: SQLite Scanner (from ZIP or single file)
#   Tab 11: iOS Artifact Extractor (sms.db, KnowledgeC, CallHistory from ZIP)
#   Tab 12: Password Strength Analyzer
#   Tab 13: Dictionary Deduplicator + Merger
#   Tab 14: PDF Report Generator
#   Tab 15: Hex Viewer

import base64
import csv
import hashlib
import io
import os
import plistlib
import re
import sqlite3
import struct
import tempfile
import tkinter as tk
import zipfile
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ─────────────────────────────────────────────────────────────────────────────
# NEW TRANSLATION KEYS  (injected into each language in TRANSLATIONS)
# ─────────────────────────────────────────────────────────────────────────────
NEW_TRANSLATION_KEYS = {
    "PL": {
        "tab_sqlite":    "SQLite Scanner",
        "tab_ios":       "iOS Artefakty",
        "tab_pwstrength":"Siła hasła",
        "tab_dedup":     "Dedupl. słowników",
        "tab_pdf":       "Raport PDF",
        "tab_hex":       "Hex Viewer",
        # sqlite
        "lbl_sqlite_zip":    "Plik ZIP (FFS) lub baza SQLite:",
        "lbl_sqlite_info":   "Skanuje wszystkie bazy SQLite w pliku ZIP lub pojedynczą bazę .db.\nSzuka Base64, JWT i PIN-ów w każdej kolumnie każdej tabeli.",
        "btn_run_sqlite":    "Skanuj SQLite",
        # ios artifacts
        "lbl_ios_zip":       "Plik ZIP (FFS z iPhone):",
        "lbl_ios_info":      "Ekstrahuje artefakty iOS z pliku ZIP:\nsms.db → wiadomości, KnowledgeC.db → aktywność, CallHistory → połączenia.\nEksportuje każdy artefakt do osobnego pliku CSV.",
        "btn_run_ios":       "Ekstrahuj artefakty",
        "btn_ios_export":    "Eksportuj CSV",
        # password strength
        "lbl_pw_input":      "Hasło do analizy:",
        "lbl_pw_file":       "Lub plik haseł (jedno/linia):",
        "lbl_pw_info":       "Analiza siły hasła: entropia, długość, klasy znaków, ocena.",
        "btn_run_pw":        "Analizuj",
        "btn_run_pw_file":   "Analizuj plik",
        "lbl_strength_very_weak":   "Bardzo słabe",
        "lbl_strength_weak":        "Słabe",
        "lbl_strength_medium":      "Średnie",
        "lbl_strength_strong":      "Silne",
        "lbl_strength_very_strong": "Bardzo silne",
        # dedup
        "lbl_dedup_info":    "Wczytaj wiele plików TXT (słowniki haseł), scal je i usuń duplikaty.\nOpcjonalnie posortuj alfabetycznie lub według długości.",
        "btn_dedup_add":     "Dodaj pliki",
        "btn_dedup_clear":   "Wyczyść listę",
        "btn_dedup_run":     "Scal i deduplikuj",
        "lbl_sort_alpha":    "Sortuj alfabetycznie",
        "lbl_sort_length":   "Sortuj według długości",
        "lbl_sort_none":     "Bez sortowania",
        "lbl_dedup_files":   "Pliki do scalenia:",
        # pdf
        "lbl_pdf_info":      "Generuj raport PDF z wybranego pliku TXT lub CSV.\nGotowy do dołączenia do opinii biegłego.",
        "lbl_pdf_source":    "Plik źródłowy (TXT/CSV):",
        "lbl_pdf_title":     "Tytuł raportu:",
        "lbl_pdf_expert":    "Biegły / Expert:",
        "lbl_pdf_case":      "Sygnatura akt / Case no.:",
        "lbl_pdf_notes":     "Uwagi / Notes:",
        "btn_gen_pdf":       "Generuj PDF",
        # hex viewer
        "lbl_hex_info":      "Prosty hex viewer z wyszukiwarką.\nWczytaj dowolny plik binarny lub tekstowy.",
        "lbl_hex_search":    "Szukaj (hex lub tekst):",
        "lbl_hex_offset":    "Przejdź do offsetu (hex):",
        "btn_hex_open":      "Otwórz plik",
        "btn_hex_search":    "Szukaj",
        "btn_hex_goto":      "Idź do",
        "btn_hex_next":      "Następny",
        "lbl_hex_found":     "Znaleziono: {count} wystąpień",
        "lbl_hex_not_found": "Nie znaleziono.",
        "msg_hex_big_file":  "Plik jest większy niż 50 MB. Wczytać pierwsze 50 MB?",
    },
    "EN": {
        "tab_sqlite":    "SQLite Scanner",
        "tab_ios":       "iOS Artifacts",
        "tab_pwstrength":"Password Strength",
        "tab_dedup":     "Dict Deduplicator",
        "tab_pdf":       "PDF Report",
        "tab_hex":       "Hex Viewer",
        "lbl_sqlite_zip":    "ZIP file (FFS) or SQLite database:",
        "lbl_sqlite_info":   "Scans all SQLite databases in a ZIP file or a single .db file.\nSearches every column of every table for Base64, JWT and PINs.",
        "btn_run_sqlite":    "Scan SQLite",
        "lbl_ios_zip":       "ZIP file (iPhone FFS):",
        "lbl_ios_info":      "Extracts iOS artifacts from a ZIP file:\nsms.db → messages, KnowledgeC.db → activity, CallHistory → calls.\nExports each artifact to a separate CSV file.",
        "btn_run_ios":       "Extract artifacts",
        "btn_ios_export":    "Export CSV",
        "lbl_pw_input":      "Password to analyze:",
        "lbl_pw_file":       "Or password file (one/line):",
        "lbl_pw_info":       "Password strength analysis: entropy, length, character classes, score.",
        "btn_run_pw":        "Analyze",
        "btn_run_pw_file":   "Analyze file",
        "lbl_strength_very_weak":   "Very Weak",
        "lbl_strength_weak":        "Weak",
        "lbl_strength_medium":      "Medium",
        "lbl_strength_strong":      "Strong",
        "lbl_strength_very_strong": "Very Strong",
        "lbl_dedup_info":    "Load multiple TXT files (password dictionaries), merge and deduplicate.\nOptionally sort alphabetically or by length.",
        "btn_dedup_add":     "Add files",
        "btn_dedup_clear":   "Clear list",
        "btn_dedup_run":     "Merge & deduplicate",
        "lbl_sort_alpha":    "Sort alphabetically",
        "lbl_sort_length":   "Sort by length",
        "lbl_sort_none":     "No sorting",
        "lbl_dedup_files":   "Files to merge:",
        "lbl_pdf_info":      "Generate a PDF report from a TXT or CSV file.\nReady to attach to an expert opinion.",
        "lbl_pdf_source":    "Source file (TXT/CSV):",
        "lbl_pdf_title":     "Report title:",
        "lbl_pdf_expert":    "Expert / Author:",
        "lbl_pdf_case":      "Case number / Signature:",
        "lbl_pdf_notes":     "Notes:",
        "btn_gen_pdf":       "Generate PDF",
        "lbl_hex_info":      "Simple hex viewer with search.\nLoad any binary or text file.",
        "lbl_hex_search":    "Search (hex or text):",
        "lbl_hex_offset":    "Go to offset (hex):",
        "btn_hex_open":      "Open file",
        "btn_hex_search":    "Search",
        "btn_hex_goto":      "Go to",
        "btn_hex_next":      "Next",
        "lbl_hex_found":     "Found: {count} occurrence(s)",
        "lbl_hex_not_found": "Not found.",
        "msg_hex_big_file":  "File is larger than 50 MB. Load first 50 MB?",
    },
    "DE": {
        "tab_sqlite":    "SQLite Scanner",
        "tab_ios":       "iOS Artefakte",
        "tab_pwstrength":"Passwortstärke",
        "tab_dedup":     "Wörterbuch-Dedup.",
        "tab_pdf":       "PDF-Bericht",
        "tab_hex":       "Hex Viewer",
        "lbl_sqlite_zip":    "ZIP-Datei (FFS) oder SQLite-Datenbank:",
        "lbl_sqlite_info":   "Scannt alle SQLite-Datenbanken in einer ZIP-Datei.\nSucht in jeder Spalte nach Base64, JWT und PINs.",
        "btn_run_sqlite":    "SQLite scannen",
        "lbl_ios_zip":       "ZIP-Datei (iPhone FFS):",
        "lbl_ios_info":      "Extrahiert iOS-Artefakte aus einer ZIP-Datei:\nsms.db → Nachrichten, KnowledgeC → Aktivität, CallHistory → Anrufe.",
        "btn_run_ios":       "Artefakte extrahieren",
        "btn_ios_export":    "CSV exportieren",
        "lbl_pw_input":      "Passwort analysieren:",
        "lbl_pw_file":       "Oder Passwortdatei (eine/Zeile):",
        "lbl_pw_info":       "Passwortstärke: Entropie, Länge, Zeichenklassen, Bewertung.",
        "btn_run_pw":        "Analysieren",
        "btn_run_pw_file":   "Datei analysieren",
        "lbl_strength_very_weak":   "Sehr schwach",
        "lbl_strength_weak":        "Schwach",
        "lbl_strength_medium":      "Mittel",
        "lbl_strength_strong":      "Stark",
        "lbl_strength_very_strong": "Sehr stark",
        "lbl_dedup_info":    "Mehrere TXT-Dateien laden, zusammenführen und deduplizieren.",
        "btn_dedup_add":     "Dateien hinzufügen",
        "btn_dedup_clear":   "Liste leeren",
        "btn_dedup_run":     "Zusammenführen & deduplizieren",
        "lbl_sort_alpha":    "Alphabetisch sortieren",
        "lbl_sort_length":   "Nach Länge sortieren",
        "lbl_sort_none":     "Keine Sortierung",
        "lbl_dedup_files":   "Dateien zum Zusammenführen:",
        "lbl_pdf_info":      "PDF-Bericht aus TXT- oder CSV-Datei erstellen.",
        "lbl_pdf_source":    "Quelldatei (TXT/CSV):",
        "lbl_pdf_title":     "Berichtstitel:",
        "lbl_pdf_expert":    "Sachverständiger:",
        "lbl_pdf_case":      "Aktenzeichen:",
        "lbl_pdf_notes":     "Anmerkungen:",
        "btn_gen_pdf":       "PDF erstellen",
        "lbl_hex_info":      "Einfacher Hex-Viewer mit Suche.",
        "lbl_hex_search":    "Suchen (Hex oder Text):",
        "lbl_hex_offset":    "Zum Offset gehen (Hex):",
        "btn_hex_open":      "Datei öffnen",
        "btn_hex_search":    "Suchen",
        "btn_hex_goto":      "Gehe zu",
        "btn_hex_next":      "Nächste",
        "lbl_hex_found":     "Gefunden: {count} Treffer",
        "lbl_hex_not_found": "Nicht gefunden.",
        "msg_hex_big_file":  "Datei > 50 MB. Erste 50 MB laden?",
    },
    "FR": {
        "tab_sqlite":    "Scanner SQLite",
        "tab_ios":       "Artefacts iOS",
        "tab_pwstrength":"Force du mot de passe",
        "tab_dedup":     "Dédup. dictionnaire",
        "tab_pdf":       "Rapport PDF",
        "tab_hex":       "Hex Viewer",
        "lbl_sqlite_zip":    "Fichier ZIP (FFS) ou base SQLite :",
        "lbl_sqlite_info":   "Analyse toutes les bases SQLite dans un ZIP.\nRecherche Base64, JWT et PINs dans chaque colonne.",
        "btn_run_sqlite":    "Scanner SQLite",
        "lbl_ios_zip":       "Fichier ZIP (FFS iPhone) :",
        "lbl_ios_info":      "Extrait les artefacts iOS d'un fichier ZIP.",
        "btn_run_ios":       "Extraire les artefacts",
        "btn_ios_export":    "Exporter CSV",
        "lbl_pw_input":      "Mot de passe à analyser :",
        "lbl_pw_file":       "Ou fichier de mots de passe :",
        "lbl_pw_info":       "Analyse de la force : entropie, longueur, classes de caractères.",
        "btn_run_pw":        "Analyser",
        "btn_run_pw_file":   "Analyser fichier",
        "lbl_strength_very_weak":   "Très faible",
        "lbl_strength_weak":        "Faible",
        "lbl_strength_medium":      "Moyen",
        "lbl_strength_strong":      "Fort",
        "lbl_strength_very_strong": "Très fort",
        "lbl_dedup_info":    "Charger plusieurs fichiers TXT, fusionner et dédupliquer.",
        "btn_dedup_add":     "Ajouter fichiers",
        "btn_dedup_clear":   "Vider la liste",
        "btn_dedup_run":     "Fusionner et dédupliquer",
        "lbl_sort_alpha":    "Tri alphabétique",
        "lbl_sort_length":   "Tri par longueur",
        "lbl_sort_none":     "Sans tri",
        "lbl_dedup_files":   "Fichiers à fusionner :",
        "lbl_pdf_info":      "Générer un rapport PDF depuis un fichier TXT ou CSV.",
        "lbl_pdf_source":    "Fichier source (TXT/CSV) :",
        "lbl_pdf_title":     "Titre du rapport :",
        "lbl_pdf_expert":    "Expert / Auteur :",
        "lbl_pdf_case":      "Numéro de dossier :",
        "lbl_pdf_notes":     "Notes :",
        "btn_gen_pdf":       "Générer PDF",
        "lbl_hex_info":      "Visionneur hex simple avec recherche.",
        "lbl_hex_search":    "Rechercher (hex ou texte) :",
        "lbl_hex_offset":    "Aller à l'offset (hex) :",
        "btn_hex_open":      "Ouvrir fichier",
        "btn_hex_search":    "Rechercher",
        "btn_hex_goto":      "Aller à",
        "btn_hex_next":      "Suivant",
        "lbl_hex_found":     "Trouvé : {count} occurrence(s)",
        "lbl_hex_not_found": "Non trouvé.",
        "msg_hex_big_file":  "Fichier > 50 Mo. Charger les 50 premiers Mo ?",
    },
    "ES": {
        "tab_sqlite":    "Scanner SQLite",
        "tab_ios":       "Artefactos iOS",
        "tab_pwstrength":"Fuerza de contraseña",
        "tab_dedup":     "Dedup. diccionario",
        "tab_pdf":       "Informe PDF",
        "tab_hex":       "Visor Hex",
        "lbl_sqlite_zip":    "Archivo ZIP (FFS) o base de datos SQLite:",
        "lbl_sqlite_info":   "Escanea todas las bases SQLite en un ZIP.\nBusca Base64, JWT y PINs en cada columna.",
        "btn_run_sqlite":    "Escanear SQLite",
        "lbl_ios_zip":       "Archivo ZIP (FFS iPhone):",
        "lbl_ios_info":      "Extrae artefactos iOS de un archivo ZIP.",
        "btn_run_ios":       "Extraer artefactos",
        "btn_ios_export":    "Exportar CSV",
        "lbl_pw_input":      "Contraseña a analizar:",
        "lbl_pw_file":       "O archivo de contraseñas:",
        "lbl_pw_info":       "Análisis de fuerza: entropía, longitud, clases de caracteres.",
        "btn_run_pw":        "Analizar",
        "btn_run_pw_file":   "Analizar archivo",
        "lbl_strength_very_weak":   "Muy débil",
        "lbl_strength_weak":        "Débil",
        "lbl_strength_medium":      "Media",
        "lbl_strength_strong":      "Fuerte",
        "lbl_strength_very_strong": "Muy fuerte",
        "lbl_dedup_info":    "Cargar varios archivos TXT, combinar y deduplicar.",
        "btn_dedup_add":     "Agregar archivos",
        "btn_dedup_clear":   "Limpiar lista",
        "btn_dedup_run":     "Combinar y deduplicar",
        "lbl_sort_alpha":    "Ordenar alfabéticamente",
        "lbl_sort_length":   "Ordenar por longitud",
        "lbl_sort_none":     "Sin ordenar",
        "lbl_dedup_files":   "Archivos a combinar:",
        "lbl_pdf_info":      "Generar informe PDF desde TXT o CSV.",
        "lbl_pdf_source":    "Archivo fuente (TXT/CSV):",
        "lbl_pdf_title":     "Título del informe:",
        "lbl_pdf_expert":    "Perito / Autor:",
        "lbl_pdf_case":      "Número de caso:",
        "lbl_pdf_notes":     "Notas:",
        "btn_gen_pdf":       "Generar PDF",
        "lbl_hex_info":      "Visor hex simple con búsqueda.",
        "lbl_hex_search":    "Buscar (hex o texto):",
        "lbl_hex_offset":    "Ir a offset (hex):",
        "btn_hex_open":      "Abrir archivo",
        "btn_hex_search":    "Buscar",
        "btn_hex_goto":      "Ir a",
        "btn_hex_next":      "Siguiente",
        "lbl_hex_found":     "Encontrado: {count} ocurrencia(s)",
        "lbl_hex_not_found": "No encontrado.",
        "msg_hex_big_file":  "Archivo > 50 MB. ¿Cargar primeros 50 MB?",
    },
    "IT": {
        "tab_sqlite":    "Scanner SQLite",
        "tab_ios":       "Artefatti iOS",
        "tab_pwstrength":"Forza password",
        "tab_dedup":     "Dedup. dizionario",
        "tab_pdf":       "Report PDF",
        "tab_hex":       "Hex Viewer",
        "lbl_sqlite_zip":    "File ZIP (FFS) o database SQLite:",
        "lbl_sqlite_info":   "Scansiona tutti i database SQLite in un file ZIP.\nCerca Base64, JWT e PIN in ogni colonna.",
        "btn_run_sqlite":    "Scansiona SQLite",
        "lbl_ios_zip":       "File ZIP (FFS iPhone):",
        "lbl_ios_info":      "Estrae artefatti iOS da un file ZIP.",
        "btn_run_ios":       "Estrai artefatti",
        "btn_ios_export":    "Esporta CSV",
        "lbl_pw_input":      "Password da analizzare:",
        "lbl_pw_file":       "O file password:",
        "lbl_pw_info":       "Analisi forza: entropia, lunghezza, classi caratteri.",
        "btn_run_pw":        "Analizza",
        "btn_run_pw_file":   "Analizza file",
        "lbl_strength_very_weak":   "Molto debole",
        "lbl_strength_weak":        "Debole",
        "lbl_strength_medium":      "Media",
        "lbl_strength_strong":      "Forte",
        "lbl_strength_very_strong": "Molto forte",
        "lbl_dedup_info":    "Carica più file TXT, unisci e deduplica.",
        "btn_dedup_add":     "Aggiungi file",
        "btn_dedup_clear":   "Svuota lista",
        "btn_dedup_run":     "Unisci e deduplica",
        "lbl_sort_alpha":    "Ordina alfabeticamente",
        "lbl_sort_length":   "Ordina per lunghezza",
        "lbl_sort_none":     "Nessun ordinamento",
        "lbl_dedup_files":   "File da unire:",
        "lbl_pdf_info":      "Genera report PDF da file TXT o CSV.",
        "lbl_pdf_source":    "File sorgente (TXT/CSV):",
        "lbl_pdf_title":     "Titolo report:",
        "lbl_pdf_expert":    "Perito / Autore:",
        "lbl_pdf_case":      "Numero caso:",
        "lbl_pdf_notes":     "Note:",
        "btn_gen_pdf":       "Genera PDF",
        "lbl_hex_info":      "Semplice hex viewer con ricerca.",
        "lbl_hex_search":    "Cerca (hex o testo):",
        "lbl_hex_offset":    "Vai all'offset (hex):",
        "btn_hex_open":      "Apri file",
        "btn_hex_search":    "Cerca",
        "btn_hex_goto":      "Vai a",
        "btn_hex_next":      "Successivo",
        "lbl_hex_found":     "Trovato: {count} occorrenza/e",
        "lbl_hex_not_found": "Non trovato.",
        "msg_hex_big_file":  "File > 50 MB. Caricare i primi 50 MB?",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# SQLite Scanner helpers
# ─────────────────────────────────────────────────────────────────────────────

import math
import string
from collections import Counter


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in cnt.values())


_RE_B64  = re.compile(r"[A-Za-z0-9+/=]{8,}")
_RE_B64U = re.compile(r"[A-Za-z0-9\-_]{8,}")
_RE_JWT  = re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
_RE_D4   = re.compile(r"(?<!\d)\d{4}(?!\d)")
_RE_D6   = re.compile(r"(?<!\d)\d{6}(?!\d)")


def _classify_value(val: str) -> list:
    tags = []
    for m in _RE_JWT.finditer(val):
        tags.append(("JWT", m.group()))
    for m in _RE_B64.finditer(val):
        try:
            dec = base64.b64decode(m.group() + "==")
            if len(dec) >= 2:
                tags.append(("BASE64", m.group()[:40]))
        except Exception:
            pass
    for m in _RE_D6.finditer(val):
        tags.append(("PIN6", m.group()))
    for m in _RE_D4.finditer(val):
        tags.append(("PIN4", m.group()))
    return tags


def scan_sqlite_db(db_bytes: bytes, source_name: str) -> list:
    """Scan a SQLite database bytes for Base64/JWT/PIN findings."""
    results = []
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
    tmp.write(db_bytes)
    tmp.close()
    try:
        con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
        cur = con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for tbl in tables:
            try:
                cur2 = con.execute(f'SELECT * FROM "{tbl}" LIMIT 2000')
                cols = [d[0] for d in cur2.description]
                for row in cur2.fetchall():
                    for col, cell in zip(cols, row):
                        if cell is None:
                            continue
                        if isinstance(cell, bytes):
                            val = base64.b64encode(cell).decode()
                            tags = _classify_value(val)
                            if tags:
                                for tag, match in tags:
                                    results.append({
                                        "source": source_name,
                                        "table": tbl,
                                        "column": col,
                                        "type": tag,
                                        "value": match,
                                        "raw_preview": cell[:32].hex(),
                                    })
                        else:
                            val = str(cell)
                            tags = _classify_value(val)
                            for tag, match in tags:
                                results.append({
                                    "source": source_name,
                                    "table": tbl,
                                    "column": col,
                                    "type": tag,
                                    "value": match,
                                    "raw_preview": val[:60],
                                })
            except Exception:
                pass
        con.close()
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
    return results


def scan_sqlite_from_zip(zip_path: str,
                         progress_cb=None,
                         log_cb=None) -> list:
    """Open ZIP, find all .db/.sqlite files, scan each."""
    all_results = []
    log = log_cb or (lambda m: None)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            db_entries = [i for i in zf.infolist()
                          if not i.is_dir() and
                          any(i.filename.lower().endswith(ext)
                              for ext in (".db", ".sqlite", ".sqlitedb",
                                          ".storedata", ".db-wal", ".db-shm"))]
            # skip -wal and -shm (they're journal files)
            db_entries = [i for i in db_entries
                          if not i.filename.lower().endswith(("-wal", "-shm"))]
            log(f"[SQLite] Found {len(db_entries)} database files in ZIP")
            for idx, info in enumerate(db_entries):
                if progress_cb:
                    progress_cb(idx, len(db_entries))
                log(f"[SQLite] Scanning: {info.filename}")
                try:
                    data = zf.read(info.filename)
                    if not data[:16].startswith(b"SQLite format 3"):
                        continue
                    res = scan_sqlite_db(data, info.filename)
                    all_results.extend(res)
                    log(f"[SQLite]   → {len(res)} findings")
                except Exception as e:
                    log(f"[SQLite]   ERROR: {e}")
            if progress_cb:
                progress_cb(len(db_entries), len(db_entries))
    except Exception as e:
        log(f"[SQLite] Cannot open ZIP: {e}")
    return all_results


def scan_sqlite_single(db_path: str, log_cb=None) -> list:
    log = log_cb or (lambda m: None)
    try:
        with open(db_path, "rb") as f:
            data = f.read()
        if not data[:16].startswith(b"SQLite format 3"):
            log("[SQLite] Not a SQLite file.")
            return []
        return scan_sqlite_db(data, os.path.basename(db_path))
    except Exception as e:
        log(f"[SQLite] Error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# iOS Artifact Extractor helpers
# ─────────────────────────────────────────────────────────────────────────────

IOS_DB_PROFILES = {
    "sms.db": "messages",
    "chat.db": "messages",
    "KnowledgeC.db": "knowledgec",
    "History.db": "safari",
    "call_history.db": "callhistory",
    "CallHistory.storedata": "callhistory",
    "NoteStore.sqlite": "notes",
    "notes.sqlite": "notes",
    "Calendar.sqlitedb": "calendar",
}


def _extract_messages(con: sqlite3.Connection) -> list:
    rows = []
    for sql in [
        "SELECT date, address, text, is_from_me FROM message ORDER BY date DESC LIMIT 5000",
        "SELECT date, address, text FROM message ORDER BY date DESC LIMIT 5000",
    ]:
        try:
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description]
            for r in cur.fetchall():
                rows.append(dict(zip(cols, r)))
            return rows
        except Exception:
            continue
    return rows


def _extract_knowledgec(con: sqlite3.Connection) -> list:
    rows = []
    try:
        cur = con.execute(
            "SELECT ZOBJECT.ZSTREAMNAME, ZOBJECT.ZSTARTDATE, "
            "ZOBJECT.ZENDDATE, ZOBJECT.ZVALUESTRING, "
            "ZOBJECT.ZVALUEDOUBLE "
            "FROM ZOBJECT ORDER BY ZOBJECT.ZSTARTDATE DESC LIMIT 5000"
        )
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            rows.append(dict(zip(cols, r)))
    except Exception:
        pass
    return rows


def _extract_callhistory(con: sqlite3.Connection) -> list:
    rows = []
    for sql in [
        "SELECT ZADDRESS, ZDATE, ZDURATION, ZANSWERED, ZCALLTYPE FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 5000",
        "SELECT ZADDRESS, ZDATE, ZDURATION, ZANSWERED FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 5000",
        "SELECT address, date, duration, answered FROM call ORDER BY date DESC LIMIT 5000",
    ]:
        try:
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description]
            for r in cur.fetchall():
                rows.append(dict(zip(cols, r)))
            return rows
        except Exception:
            continue
    return rows


def _extract_notes(con: sqlite3.Connection) -> list:
    rows = []
    try:
        cur = con.execute(
            "SELECT ZNOTE.ZTITLE, ZNOTE.ZCREATIONDATE, "
            "ZNOTEBODY.ZCONTENT "
            "FROM ZNOTE LEFT JOIN ZNOTEBODY "
            "ON ZNOTE.Z_PK = ZNOTEBODY.ZNOTE "
            "ORDER BY ZNOTE.ZCREATIONDATE DESC LIMIT 1000"
        )
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            rows.append(dict(zip(cols, r)))
    except Exception:
        pass
    return rows


def _extract_calendar(con: sqlite3.Connection) -> list:
    rows = []
    try:
        cur = con.execute(
            "SELECT ZTITLE, ZSTARTDATE, ZENDDATE, ZLOCATION "
            "FROM ZCALNEVENT ORDER BY ZSTARTDATE DESC LIMIT 2000"
        )
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            rows.append(dict(zip(cols, r)))
    except Exception:
        pass
    return rows


def _extract_safari(con: sqlite3.Connection) -> list:
    rows = []
    try:
        cur = con.execute(
            "SELECT hi.url, hv.visit_time "
            "FROM history_visits hv "
            "JOIN history_items hi ON hv.history_item = hi.id "
            "ORDER BY hv.visit_time DESC LIMIT 5000"
        )
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            rows.append(dict(zip(cols, r)))
    except Exception:
        pass
    return rows


_PROFILE_EXTRACTORS = {
    "messages":   _extract_messages,
    "knowledgec": _extract_knowledgec,
    "callhistory": _extract_callhistory,
    "notes":      _extract_notes,
    "calendar":   _extract_calendar,
    "safari":     _extract_safari,
}


def extract_ios_artifacts_from_zip(zip_path: str,
                                   out_dir: str,
                                   progress_cb=None,
                                   log_cb=None) -> dict:
    """
    Returns dict: profile_name -> list of row dicts
    Also saves CSV files to out_dir.
    """
    log = log_cb or (lambda m: None)
    all_artifacts: dict = {}
    saved_files = []

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            candidates = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                bname = os.path.basename(info.filename)
                if bname in IOS_DB_PROFILES:
                    candidates.append(info)

            log(f"[iOS] Found {len(candidates)} known artifact databases in ZIP")
            if progress_cb:
                progress_cb(0, len(candidates))

            for idx, info in enumerate(candidates):
                bname = os.path.basename(info.filename)
                profile = IOS_DB_PROFILES[bname]
                extractor = _PROFILE_EXTRACTORS.get(profile)
                if not extractor:
                    continue
                log(f"[iOS] Extracting {bname} ({profile}) ...")
                try:
                    data = zf.read(info.filename)
                    tmp = tempfile.NamedTemporaryFile(
                        delete=False, suffix=".sqlite")
                    tmp.write(data)
                    tmp.close()
                    con = sqlite3.connect(
                        f"file:{tmp.name}?mode=ro", uri=True)
                    rows = extractor(con)
                    con.close()
                    os.unlink(tmp.name)

                    if rows:
                        if profile not in all_artifacts:
                            all_artifacts[profile] = []
                        all_artifacts[profile].extend(rows)
                        log(f"[iOS]   → {len(rows)} rows")
                    else:
                        log(f"[iOS]   → 0 rows")
                except Exception as e:
                    log(f"[iOS]   ERROR: {e}")
                if progress_cb:
                    progress_cb(idx + 1, len(candidates))

    except Exception as e:
        log(f"[iOS] Cannot open ZIP: {e}")
        return {}

    # Save CSVs
    for profile, rows in all_artifacts.items():
        if not rows:
            continue
        fname = os.path.join(
            out_dir,
            f"ios_{profile}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        try:
            keys = list(rows[0].keys())
            with open(fname, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                w.writeheader()
                for row in rows:
                    safe = {k: (str(v)[:500] if v is not None else "")
                            for k, v in row.items()}
                    w.writerow(safe)
            saved_files.append(fname)
            log(f"[iOS] Saved: {fname} ({len(rows)} rows)")
        except Exception as e:
            log(f"[iOS] CSV save error: {e}")

    return all_artifacts


# ─────────────────────────────────────────────────────────────────────────────
# Password Strength helpers
# ─────────────────────────────────────────────────────────────────────────────

def analyze_password_strength(pw: str) -> dict:
    length = len(pw)
    has_lower  = bool(re.search(r"[a-z]", pw))
    has_upper  = bool(re.search(r"[A-Z]", pw))
    has_digit  = bool(re.search(r"\d", pw))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", pw))
    has_space  = " " in pw

    charset = 0
    if has_lower:   charset += 26
    if has_upper:   charset += 26
    if has_digit:   charset += 10
    if has_special: charset += 32
    if has_space:   charset += 1
    charset = max(charset, 1)

    entropy_bits = length * math.log2(charset) if length > 0 else 0
    shannon = _shannon_entropy(pw.encode("utf-8"))

    # Score 0–100
    score = 0
    score += min(length * 4, 40)
    if has_lower:   score += 10
    if has_upper:   score += 10
    if has_digit:   score += 10
    if has_special: score += 20
    if has_space:   score += 5
    if length >= 16: score += 5
    score = min(score, 100)

    if score < 20:
        level = "very_weak"
    elif score < 40:
        level = "weak"
    elif score < 60:
        level = "medium"
    elif score < 80:
        level = "strong"
    else:
        level = "very_strong"

    classes = []
    if has_lower:   classes.append("lowercase")
    if has_upper:   classes.append("uppercase")
    if has_digit:   classes.append("digits")
    if has_special: classes.append("special")
    if has_space:   classes.append("space")

    return {
        "password":      pw,
        "length":        length,
        "charset_size":  charset,
        "entropy_bits":  round(entropy_bits, 2),
        "shannon":       round(shannon, 4),
        "score":         score,
        "level":         level,
        "classes":       classes,
        "has_lower":     has_lower,
        "has_upper":     has_upper,
        "has_digit":     has_digit,
        "has_special":   has_special,
    }


STRENGTH_COLORS = {
    "very_weak":   "#cc0000",
    "weak":        "#e05000",
    "medium":      "#c8a000",
    "strong":      "#2a7a2a",
    "very_strong": "#005500",
}


# ─────────────────────────────────────────────────────────────────────────────
# PDF Report Generator (no external libs — pure Python reportlab-free approach
# using a minimal PDF writer)
# ─────────────────────────────────────────────────────────────────────────────

class _MinimalPDF:
    """Minimal PDF writer — no external dependencies."""

    def __init__(self):
        self._objects: list[bytes] = []
        self._offsets: list[int] = []
        self._pages: list[int] = []
        self._buf = io.BytesIO()
        self._buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    def _add_obj(self, content: bytes) -> int:
        n = len(self._objects) + 1
        self._offsets.append(self._buf.tell())
        self._buf.write(f"{n} 0 obj\n".encode())
        self._buf.write(content)
        self._buf.write(b"\nendobj\n")
        self._objects.append(content)
        return n

    @staticmethod
    def _escape(s: str) -> bytes:
        s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        return s.encode("latin-1", errors="replace")

    def _text_stream(self, lines: list[str],
                     font_size: int = 9,
                     title: str = "",
                     page_w: float = 595,
                     page_h: float = 842) -> tuple[int, int]:
        """Render lines as a PDF page stream. Returns (page_obj_n, stream_obj_n)."""
        margin_x, margin_y = 40, 40
        line_h = font_size + 3
        max_lines_per_page = int((page_h - 2 * margin_y) / line_h)
        usable_w = page_w - 2 * margin_x

        # font object
        font_obj = self._add_obj(
            b"<< /Type /Font /Subtype /Type1 "
            b"/BaseFont /Courier /Encoding /WinAnsiEncoding >>"
        )
        font_bold = self._add_obj(
            b"<< /Type /Font /Subtype /Type1 "
            b"/BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>"
        )

        page_obj_ids = []
        chunks = [lines[i:i + max_lines_per_page]
                  for i in range(0, max(len(lines), 1), max_lines_per_page)]
        if not chunks:
            chunks = [[]]

        for page_idx, chunk in enumerate(chunks):
            stream_parts = [b"BT\n"]
            y = page_h - margin_y

            # Title on first page
            if page_idx == 0 and title:
                stream_parts.append(
                    f"/F2 12 Tf\n{margin_x} {y} Td\n"
                    f"({self._escape(title[:80]).decode('latin-1')}) Tj\n".encode()
                )
                y -= 20
                stream_parts.append(
                    f"/F1 {font_size} Tf\n"
                    f"{margin_x} {y} Td\n"
                    f"{line_h} TL\n".encode()
                )
            else:
                stream_parts.append(
                    f"/F1 {font_size} Tf\n"
                    f"{margin_x} {y} Td\n"
                    f"{line_h} TL\n".encode()
                )

            for line in chunk:
                safe = line.replace("\t", "    ")
                # Truncate to fit page width (~1 char = 5.4 pt for Courier 9)
                max_chars = int(usable_w / (font_size * 0.6))
                if len(safe) > max_chars:
                    safe = safe[:max_chars - 3] + "..."
                escaped = self._escape(safe).decode("latin-1")
                stream_parts.append(f"({escaped}) '\n".encode())

            stream_parts.append(b"ET\n")
            stream_data = b"".join(stream_parts)

            stream_obj = self._add_obj(
                f"<< /Length {len(stream_data)} >>\nstream\n".encode()
                + stream_data
                + b"\nendstream"
            )

            page_res = (
                f"<< /Type /Page /MediaBox [0 0 {page_w} {page_h}] "
                f"/Contents {stream_obj} 0 R "
                f"/Resources << /Font << /F1 {font_obj} 0 R "
                f"/F2 {font_bold} 0 R >> >> "
                f"/Parent {{PAGES}} 0 R >>"
            ).encode()
            page_obj_ids.append(page_res)

        # We'll fix /Parent after adding pages node
        page_refs = []
        real_page_ids = []
        for pr in page_obj_ids:
            pid = self._add_obj(pr)
            real_page_ids.append(pid)
            page_refs.append(f"{pid} 0 R")

        self._pages.extend(real_page_ids)
        return real_page_ids[0], len(real_page_ids)

    def generate(self, lines: list[str], title: str,
                 expert: str, case_no: str, notes: str) -> bytes:
        # Header lines
        header = [
            f"Base64 Forensic Toolkit v2.6 — Expert Report",
            f"Title:    {title}",
            f"Expert:   {expert}",
            f"Case no.: {case_no}",
            f"Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Notes:    {notes}",
            "─" * 80,
            "",
        ] + lines

        # Add pages
        self._text_stream(header, font_size=9, title=title)

        # Pages dict
        page_list = " ".join(f"{pid} 0 R" for pid in self._pages)
        pages_obj = self._add_obj(
            f"<< /Type /Pages /Kids [{page_list}] "
            f"/Count {len(self._pages)} >>".encode()
        )

        # Fix /Parent references in page objects
        raw = self._buf.getvalue().decode("latin-1")
        raw = raw.replace("{PAGES}", str(pages_obj))
        self._buf = io.BytesIO(raw.encode("latin-1"))

        # Catalog
        catalog_obj = self._add_obj(
            f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode()
        )

        # xref
        xref_pos = self._buf.tell()
        n_objects = len(self._objects) + 1
        self._buf.write(f"xref\n0 {n_objects}\n".encode())
        self._buf.write(b"0000000000 65535 f \n")
        for off in self._offsets:
            self._buf.write(f"{off:010d} 00000 n \n".encode())
        self._buf.write(
            f"trailer\n<< /Size {n_objects} /Root {catalog_obj} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n".encode()
        )
        return self._buf.getvalue()


def generate_pdf_report(source_path: str, out_path: str,
                        title: str, expert: str,
                        case_no: str, notes: str) -> bool:
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f.readlines()]
        pdf = _MinimalPDF()
        data = pdf.generate(lines, title, expert, case_no, notes)
        with open(out_path, "wb") as f:
            f.write(data)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Hex Viewer helpers
# ─────────────────────────────────────────────────────────────────────────────

MAX_HEX_BYTES = 50 * 1024 * 1024  # 50 MB


def format_hex_dump(data: bytes,
                    start_offset: int = 0,
                    bytes_per_row: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i:i + bytes_per_row]
        offset_str = f"{start_offset + i:08x}"
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        hex_str = hex_str.ljust(bytes_per_row * 3 - 1)
        ascii_str = "".join(
            chr(b) if 32 <= b < 127 else "." for b in chunk
        )
        lines.append(f"{offset_str}  {hex_str}  |{ascii_str}|")
    return "\n".join(lines)


def search_hex(data: bytes, pattern: str) -> list[int]:
    """Search for hex string (e.g. '4D5A') or text in data. Returns offsets."""
    pattern = pattern.strip()
    if not pattern:
        return []
    # Try hex pattern first
    hex_clean = pattern.replace(" ", "").replace("0x", "").replace("0X", "")
    if re.fullmatch(r"[0-9A-Fa-f]+", hex_clean) and len(hex_clean) % 2 == 0:
        needle = bytes.fromhex(hex_clean)
    else:
        # Treat as text
        needle = pattern.encode("utf-8", errors="replace")
    offsets = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos == -1:
            break
        offsets.append(pos)
        start = pos + 1
        if len(offsets) > 10000:
            break
    return offsets


# ─────────────────────────────────────────────────────────────────────────────
# NEW TAB BUILDERS  (mixed into App class via monkey-patch)
# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_sqlite(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_sqlite_info"),
              wraplength=900).pack(fill="x", **pad)

    file_frame = ttk.LabelFrame(f, text=self._("lbl_sqlite_zip"))
    file_frame.pack(fill="x", **pad)
    self._make_file_row(file_frame, self.sqlite_scan_path,
                        self._browse_sqlite, "sqlite")

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_run_sqlite = tk.Button(
        btn_row, text=self._("btn_run_sqlite"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_sqlite_scan)
    self.btn_run_sqlite.pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(self.txt_sqlite_log)
              ).pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_export_csv"),
              bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
              command=self.export_sqlite_csv).pack(side="left", padx=4)

    self.progress_sqlite = ttk.Progressbar(f, mode="determinate", length=600)
    self.progress_sqlite.pack(fill="x", **pad)

    self.txt_sqlite_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=20)
    self.txt_sqlite_log.pack(fill="both", expand=True, **pad)


def _browse_sqlite(self):
    p = filedialog.askopenfilename(
        filetypes=[("ZIP / SQLite", "*.zip;*.db;*.sqlite;*.sqlitedb"),
                   ("All", "*.*")])
    if p:
        self.sqlite_scan_path.set(p)
        self.config_mgr.add_recent("sqlite", p)
        self._rebuild_recent_menu()


def run_sqlite_scan(self):
    path = self.sqlite_scan_path.get().strip()
    if not path:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    self.btn_run_sqlite.config(state="disabled")
    self.set_status("SQLite scan...")
    self.set_progress(self.progress_sqlite, 0)
    self._sqlite_results = []

    def prog(v, t): self.set_progress(self.progress_sqlite, v, t or 1)
    def log(m):    self.log_to(self.txt_sqlite_log, m)

    try:
        if path.lower().endswith(".zip"):
            self._sqlite_results = scan_sqlite_from_zip(
                path, progress_cb=prog, log_cb=log)
        else:
            self._sqlite_results = scan_sqlite_single(path, log_cb=log)
        log(f"\n[SQLite] Total findings: {len(self._sqlite_results)}")
        # Show summary
        by_type: dict = {}
        for r in self._sqlite_results:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        for t, c in sorted(by_type.items()):
            log(f"  {t}: {c}")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.btn_run_sqlite.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


def export_sqlite_csv(self):
    if not hasattr(self, "_sqlite_results") or not self._sqlite_results:
        messagebox.showwarning("", "No results. Run scan first.")
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv")])
    if not out:
        return
    keys = ["source", "table", "column", "type", "value", "raw_preview"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(self._sqlite_results)
    messagebox.showinfo("", self._("report_saved").format(path=out))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_ios(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_ios_info"),
              wraplength=900).pack(fill="x", **pad)

    file_frame = ttk.LabelFrame(f, text=self._("lbl_ios_zip"))
    file_frame.pack(fill="x", **pad)
    self._make_file_row(file_frame, self.ios_zip_path,
                        self._browse_ios_zip, "ios")

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_run_ios = tk.Button(
        btn_row, text=self._("btn_run_ios"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_ios_extract)
    self.btn_run_ios.pack(side="left", padx=4)
    tk.Button(btn_row, text=self._("btn_clear"),
              command=lambda: self._clear_widget(self.txt_ios_log)
              ).pack(side="left", padx=4)

    self.progress_ios = ttk.Progressbar(f, mode="determinate", length=600)
    self.progress_ios.pack(fill="x", **pad)

    self.txt_ios_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=20)
    self.txt_ios_log.pack(fill="both", expand=True, **pad)


def _browse_ios_zip(self):
    p = filedialog.askopenfilename(
        filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
    if p:
        self.ios_zip_path.set(p)
        self.config_mgr.add_recent("ios", p)
        self._rebuild_recent_menu()


def run_ios_extract(self):
    path = self.ios_zip_path.get().strip()
    if not path:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    out_dir = filedialog.askdirectory(title="Select output folder for CSVs")
    if not out_dir:
        return

    self.btn_run_ios.config(state="disabled")
    self.set_status("Extracting iOS artifacts...")
    self.set_progress(self.progress_ios, 0)

    def prog(v, t): self.set_progress(self.progress_ios, v, t or 1)
    def log(m):    self.log_to(self.txt_ios_log, m)

    try:
        results = extract_ios_artifacts_from_zip(
            path, out_dir, progress_cb=prog, log_cb=log)
        total = sum(len(v) for v in results.values())
        log(f"\n[iOS] Extraction complete. Total rows: {total}")
        for profile, rows in results.items():
            log(f"  {profile}: {len(rows)} rows")
        messagebox.showinfo("iOS Artifacts",
                            f"Done. {total} total rows extracted.\n"
                            f"CSVs saved to: {out_dir}")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.btn_run_ios.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_pwstrength(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_pw_info"),
              wraplength=900).pack(fill="x", **pad)

    # Single password
    single_frame = ttk.LabelFrame(f, text=self._("lbl_pw_input"))
    single_frame.pack(fill="x", **pad)
    pw_row = ttk.Frame(single_frame)
    pw_row.pack(fill="x", padx=4, pady=4)
    self.pw_entry_var = tk.StringVar()
    self.pw_entry = ttk.Entry(pw_row, textvariable=self.pw_entry_var,
                              width=50, show="")
    self.pw_entry.pack(side="left", padx=4)
    # Strength meter bar
    self.pw_strength_bar = ttk.Progressbar(
        pw_row, mode="determinate", length=200, maximum=100)
    self.pw_strength_bar.pack(side="left", padx=8)
    self.pw_strength_lbl = ttk.Label(pw_row, text="—", width=14)
    self.pw_strength_lbl.pack(side="left")
    # Live update
    self.pw_entry_var.trace_add("write", self._pw_live_update)

    tk.Button(single_frame, text=self._("btn_run_pw"),
              bg=self.theme["run_bg"], fg=self.theme["run_fg"],
              command=self.run_pw_analysis).pack(
        anchor="w", padx=6, pady=4)

    # File mode
    file_frame = ttk.LabelFrame(f, text=self._("lbl_pw_file"))
    file_frame.pack(fill="x", **pad)
    self._make_file_row(file_frame, self.pw_file_path,
                        self._browse_pw_file, None)
    btn_row2 = ttk.Frame(file_frame)
    btn_row2.pack(fill="x", padx=4, pady=4)
    self.btn_run_pw_file = tk.Button(
        btn_row2, text=self._("btn_run_pw_file"),
        bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
        command=self.run_pw_file_analysis)
    self.btn_run_pw_file.pack(side="left", padx=4)
    tk.Button(btn_row2, text=self._("btn_export_csv"),
              command=self.export_pw_csv).pack(side="left", padx=4)
    tk.Button(btn_row2, text=self._("btn_clear"),
              command=lambda: self._clear_widget(self.txt_pw_log)
              ).pack(side="left", padx=4)

    self.progress_pw = ttk.Progressbar(f, mode="determinate", length=600)
    self.progress_pw.pack(fill="x", **pad)

    self.txt_pw_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=16)
    self.txt_pw_log.pack(fill="both", expand=True, **pad)
    self._pw_results: list = []


def _pw_live_update(self, *_):
    pw = self.pw_entry_var.get()
    if not pw:
        self.pw_strength_bar["value"] = 0
        self.pw_strength_lbl.config(text="—")
        return
    result = analyze_password_strength(pw)
    self.pw_strength_bar["value"] = result["score"]
    level_key = f"lbl_strength_{result['level']}"
    level_text = self.T.get(level_key, result["level"])
    color = STRENGTH_COLORS.get(result["level"], "#000000")
    self.pw_strength_lbl.config(text=level_text, foreground=color)


def _browse_pw_file(self):
    p = filedialog.askopenfilename(
        filetypes=[("txt", "*.txt;*.lst;*.dic"), ("All", "*.*")])
    if p:
        self.pw_file_path.set(p)


def run_pw_analysis(self):
    pw = self.pw_entry_var.get()
    if not pw:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    r = analyze_password_strength(pw)
    level_key = f"lbl_strength_{r['level']}"
    level_text = self.T.get(level_key, r["level"])
    lines = [
        f"Password:      {pw}",
        f"Length:        {r['length']}",
        f"Charset size:  {r['charset_size']} chars",
        f"Entropy:       {r['entropy_bits']} bits",
        f"Shannon:       {r['shannon']}",
        f"Char classes:  {', '.join(r['classes']) or 'none'}",
        f"Score:         {r['score']}/100",
        f"Strength:      {level_text}",
        "─" * 50,
    ]
    for line in lines:
        self.log_to(self.txt_pw_log, line)


def run_pw_file_analysis(self):
    path = self.pw_file_path.get().strip()
    if not path:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    self.btn_run_pw_file.config(state="disabled")
    self.set_status("Analyzing passwords...")
    self._pw_results = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f.readlines()]
        self.set_progress(self.progress_pw, 0, len(lines))
        for i, pw in enumerate(lines):
            if not pw:
                continue
            self._pw_results.append(analyze_password_strength(pw))
            if i % 1000 == 0:
                self.set_progress(self.progress_pw, i, len(lines))
        self.set_progress(self.progress_pw, len(lines), len(lines))

        # Summary
        by_level: dict = {}
        for r in self._pw_results:
            by_level[r["level"]] = by_level.get(r["level"], 0) + 1
        self.log_to(self.txt_pw_log,
                    f"\n[PW] Analyzed: {len(self._pw_results)} passwords")
        for lvl in ["very_weak", "weak", "medium", "strong", "very_strong"]:
            c = by_level.get(lvl, 0)
            if c:
                key = f"lbl_strength_{lvl}"
                self.log_to(self.txt_pw_log,
                            f"  {self.T.get(key, lvl)}: {c}")
        avg_score = (sum(r["score"] for r in self._pw_results)
                     / len(self._pw_results)) if self._pw_results else 0
        self.log_to(self.txt_pw_log, f"  Avg score: {avg_score:.1f}/100")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.btn_run_pw_file.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


def export_pw_csv(self):
    if not self._pw_results:
        messagebox.showwarning("", "No results. Run analysis first.")
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV", "*.csv")])
    if not out:
        return
    keys = ["password", "length", "charset_size", "entropy_bits",
            "shannon", "score", "level", "classes"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in self._pw_results:
            row = dict(r)
            row["classes"] = ", ".join(row["classes"])
            w.writerow(row)
    messagebox.showinfo("", self._("report_saved").format(path=out))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_dedup(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_dedup_info"),
              wraplength=900).pack(fill="x", **pad)

    list_frame = ttk.LabelFrame(f, text=self._("lbl_dedup_files"))
    list_frame.pack(fill="x", **pad)
    lf_row = ttk.Frame(list_frame)
    lf_row.pack(fill="x", padx=4, pady=2)
    tk.Button(lf_row, text=self._("btn_dedup_add"),
              command=self.dedup_add_files).pack(side="left", padx=4)
    tk.Button(lf_row, text=self._("btn_dedup_clear"),
              command=self.dedup_clear_list).pack(side="left", padx=4)
    self.dedup_listbox = tk.Listbox(list_frame, height=5,
                                    font=("Consolas", 9))
    self.dedup_listbox.pack(fill="x", padx=4, pady=4)

    # Sort option
    sort_frame = ttk.LabelFrame(f, text="Sort")
    sort_frame.pack(fill="x", **pad)
    self.dedup_sort_var = tk.StringVar(value="none")
    for val, key in [("none", "lbl_sort_none"),
                     ("alpha", "lbl_sort_alpha"),
                     ("length", "lbl_sort_length")]:
        ttk.Radiobutton(sort_frame, text=self._(key),
                        variable=self.dedup_sort_var,
                        value=val).pack(side="left", padx=8)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_dedup_run = tk.Button(
        btn_row, text=self._("btn_dedup_run"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_dedup)
    self.btn_dedup_run.pack(side="left", padx=4)

    self.progress_dedup = ttk.Progressbar(f, mode="determinate", length=600)
    self.progress_dedup.pack(fill="x", **pad)

    self.txt_dedup_log = scrolledtext.ScrolledText(
        f, font=("Consolas", 9), height=14)
    self.txt_dedup_log.pack(fill="both", expand=True, **pad)
    self._dedup_files: list = []


def dedup_add_files(self):
    paths = filedialog.askopenfilenames(
        filetypes=[("txt", "*.txt;*.lst;*.dic"), ("All", "*.*")])
    for p in paths:
        if p not in self._dedup_files:
            self._dedup_files.append(p)
            self.dedup_listbox.insert("end", os.path.basename(p))


def dedup_clear_list(self):
    self._dedup_files.clear()
    self.dedup_listbox.delete(0, "end")


def run_dedup(self):
    if not self._dedup_files:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("txt", "*.txt")])
    if not out:
        return
    self.btn_dedup_run.config(state="disabled")
    self.set_status("Deduplicating...")
    try:
        all_words: set = set()
        total_lines = 0
        self.set_progress(self.progress_dedup, 0, len(self._dedup_files))
        for i, path in enumerate(self._dedup_files):
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    w = line.rstrip("\n")
                    if w:
                        all_words.add(w)
                        total_lines += 1
            self.set_progress(self.progress_dedup, i + 1,
                              len(self._dedup_files))

        sort_mode = self.dedup_sort_var.get()
        word_list = list(all_words)
        if sort_mode == "alpha":
            word_list.sort()
        elif sort_mode == "length":
            word_list.sort(key=len)

        with open(out, "w", encoding="utf-8") as f:
            for w in word_list:
                f.write(w + "\n")

        removed = total_lines - len(word_list)
        self.log_to(self.txt_dedup_log,
                    f"[Dedup] Files: {len(self._dedup_files)} | "
                    f"Lines read: {total_lines:,} | "
                    f"Unique: {len(word_list):,} | "
                    f"Removed: {removed:,} | "
                    f"Sort: {sort_mode}")
        self.log_to(self.txt_dedup_log,
                    self._("report_saved").format(path=out))
        messagebox.showinfo("",
                            f"Done.\n"
                            f"Unique entries: {len(word_list):,}\n"
                            f"Duplicates removed: {removed:,}\n"
                            f"Saved: {out}")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.btn_dedup_run.config(state="normal")
        self.set_status(self._("lbl_status_ready"))


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_pdf(self, f):
    pad = {"padx": 6, "pady": 4}
    ttk.Label(f, text=self._("lbl_pdf_info"),
              wraplength=900).pack(fill="x", **pad)

    src_frame = ttk.LabelFrame(f, text=self._("lbl_pdf_source"))
    src_frame.pack(fill="x", **pad)
    self._make_file_row(src_frame, self.pdf_source_path,
                        self._browse_pdf_source, None)

    meta_frame = ttk.LabelFrame(f, text="Metadata")
    meta_frame.pack(fill="x", **pad)

    def _meta_row(parent, label_key, var):
        row = ttk.Frame(parent)
        row.pack(fill="x", padx=4, pady=2)
        ttk.Label(row, text=self._(label_key), width=22,
                  anchor="w").pack(side="left")
        ttk.Entry(row, textvariable=var, width=60).pack(side="left", padx=4)

    _meta_row(meta_frame, "lbl_pdf_title",  self.pdf_title_var)
    _meta_row(meta_frame, "lbl_pdf_expert", self.pdf_expert_var)
    _meta_row(meta_frame, "lbl_pdf_case",   self.pdf_case_var)

    notes_frame = ttk.LabelFrame(f, text=self._("lbl_pdf_notes"))
    notes_frame.pack(fill="x", **pad)
    self.pdf_notes_txt = tk.Text(notes_frame, height=3,
                                 font=("Arial", 9))
    self.pdf_notes_txt.pack(fill="x", padx=4, pady=4)

    btn_row = ttk.Frame(f)
    btn_row.pack(fill="x", **pad)
    self.btn_gen_pdf = tk.Button(
        btn_row, text=self._("btn_gen_pdf"),
        bg=self.theme["run_bg"], fg=self.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=self.run_generate_pdf)
    self.btn_gen_pdf.pack(side="left", padx=4)

    self.progress_pdf = ttk.Progressbar(f, mode="indeterminate", length=400)
    self.progress_pdf.pack(side="left", padx=8)

    self.pdf_status_lbl = ttk.Label(f, text="")
    self.pdf_status_lbl.pack(fill="x", **pad)


def _browse_pdf_source(self):
    p = filedialog.askopenfilename(
        filetypes=[("TXT/CSV", "*.txt;*.csv;*.log"), ("All", "*.*")])
    if p:
        self.pdf_source_path.set(p)


def run_generate_pdf(self):
    src = self.pdf_source_path.get().strip()
    if not src:
        messagebox.showwarning("", self._("msg_no_file"))
        return
    out = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF", "*.pdf")],
        initialfile=os.path.splitext(
            os.path.basename(src))[0] + "_report.pdf")
    if not out:
        return

    self.btn_gen_pdf.config(state="disabled")
    self.progress_pdf.start(10)

    title  = self.pdf_title_var.get().strip() or "Forensic Report"
    expert = self.pdf_expert_var.get().strip()
    case   = self.pdf_case_var.get().strip()
    notes  = self.pdf_notes_txt.get("1.0", "end").strip()

    ok = generate_pdf_report(src, out, title, expert, case, notes)
    self.progress_pdf.stop()
    self.btn_gen_pdf.config(state="normal")

    if ok:
        self.pdf_status_lbl.config(text=f"✓ {out}")
        messagebox.showinfo("PDF",
                            self._("report_saved").format(path=out))
    else:
        messagebox.showerror(self._("msg_error"), "PDF generation failed.")


# ─────────────────────────────────────────────────────────────────────────────

def _build_tab_hex(self, f):
    pad = {"padx": 6, "pady": 3}
    ttk.Label(f, text=self._("lbl_hex_info"),
              wraplength=900).pack(fill="x", **pad)

    top_row = ttk.Frame(f)
    top_row.pack(fill="x", **pad)
    tk.Button(top_row, text=self._("btn_hex_open"),
              bg=self.theme["run_bg"], fg=self.theme["run_fg"],
              font=("Arial", 10, "bold"),
              command=self.hex_open_file).pack(side="left", padx=4)
    self.hex_file_lbl = ttk.Label(top_row, text="—", anchor="w")
    self.hex_file_lbl.pack(side="left", fill="x", expand=True, padx=4)

    search_row = ttk.Frame(f)
    search_row.pack(fill="x", **pad)
    ttk.Label(search_row,
              text=self._("lbl_hex_search")).pack(side="left")
    self.hex_search_var = tk.StringVar()
    ttk.Entry(search_row, textvariable=self.hex_search_var,
              width=30).pack(side="left", padx=4)
    tk.Button(search_row, text=self._("btn_hex_search"),
              command=self.hex_do_search).pack(side="left", padx=2)
    self.btn_hex_next = tk.Button(
        search_row, text=self._("btn_hex_next"),
        command=self.hex_next_result, state="disabled")
    self.btn_hex_next.pack(side="left", padx=2)
    self.hex_found_lbl = ttk.Label(search_row, text="")
    self.hex_found_lbl.pack(side="left", padx=8)

    goto_row = ttk.Frame(f)
    goto_row.pack(fill="x", **pad)
    ttk.Label(goto_row,
              text=self._("lbl_hex_offset")).pack(side="left")
    self.hex_offset_var = tk.StringVar(value="0")
    ttk.Entry(goto_row, textvariable=self.hex_offset_var,
              width=12).pack(side="left", padx=4)
    tk.Button(goto_row, text=self._("btn_hex_goto"),
              command=self.hex_goto_offset).pack(side="left", padx=2)

    # Bytes per row selector
    ttk.Label(goto_row, text="  Bytes/row:").pack(side="left", padx=(12, 2))
    self.hex_bpr_var = tk.StringVar(value="16")
    ttk.Combobox(goto_row, textvariable=self.hex_bpr_var,
                 values=["8", "16", "32"], width=4,
                 state="readonly").pack(side="left")
    tk.Button(goto_row, text="Refresh",
              command=self.hex_refresh_view).pack(side="left", padx=4)

    self.progress_hex = ttk.Progressbar(f, mode="indeterminate", length=400)
    self.progress_hex.pack(fill="x", padx=6, pady=2)

    self.txt_hex = scrolledtext.ScrolledText(
        f, font=("Courier", 9), height=24, wrap="none")
    self.txt_hex.pack(fill="both", expand=True, **pad)
    self.txt_hex.tag_configure("hit", background="#ffdd00",
                               foreground="#000000")
    self._hex_data: bytes = b""
    self._hex_hits: list = []
    self._hex_hit_idx: int = 0


def hex_open_file(self):
    p = filedialog.askopenfilename(filetypes=[("All", "*.*")])
    if not p:
        return
    size = os.path.getsize(p)
    if size > MAX_HEX_BYTES:
        if not messagebox.askyesno("", self._("msg_hex_big_file")):
            return
    self.progress_hex.start(10)
    try:
        with open(p, "rb") as f:
            self._hex_data = f.read(MAX_HEX_BYTES)
        self.hex_file_lbl.config(
            text=f"{p}  ({len(self._hex_data):,} bytes)")
        self._hex_hits = []
        self._hex_hit_idx = 0
        self.hex_found_lbl.config(text="")
        self.btn_hex_next.config(state="disabled")
        bpr = int(self.hex_bpr_var.get())
        dump = format_hex_dump(self._hex_data, bytes_per_row=bpr)
        self.txt_hex.config(state="normal")
        self.txt_hex.delete("1.0", "end")
        self.txt_hex.insert("1.0", dump)
        self.txt_hex.config(state="disabled")
    except Exception as e:
        messagebox.showerror(self._("msg_error"), str(e))
    finally:
        self.progress_hex.stop()


def hex_refresh_view(self):
    if not self._hex_data:
        return
    bpr = int(self.hex_bpr_var.get())
    dump = format_hex_dump(self._hex_data, bytes_per_row=bpr)
    self.txt_hex.config(state="normal")
    self.txt_hex.delete("1.0", "end")
    self.txt_hex.insert("1.0", dump)
    self.txt_hex.config(state="disabled")


def hex_do_search(self):
    if not self._hex_data:
        return
    pattern = self.hex_search_var.get()
    self._hex_hits = search_hex(self._hex_data, pattern)
    self._hex_hit_idx = 0
    if self._hex_hits:
        self.hex_found_lbl.config(
            text=self._("lbl_hex_found").format(count=len(self._hex_hits)))
        self.btn_hex_next.config(state="normal")
        self._hex_highlight_hit(0)
    else:
        self.hex_found_lbl.config(text=self._("lbl_hex_not_found"))
        self.btn_hex_next.config(state="disabled")


def hex_next_result(self):
    if not self._hex_hits:
        return
    self._hex_hit_idx = (self._hex_hit_idx + 1) % len(self._hex_hits)
    self._hex_highlight_hit(self._hex_hit_idx)


def _hex_highlight_hit(self, idx: int):
    if not self._hex_hits:
        return
    offset = self._hex_hits[idx]
    bpr = int(self.hex_bpr_var.get())
    # Calculate line number in hex dump
    line_no = offset // bpr + 1
    self.txt_hex.config(state="normal")
    self.txt_hex.tag_remove("hit", "1.0", "end")
    line_start = f"{line_no}.0"
    line_end = f"{line_no}.end"
    self.txt_hex.tag_add("hit", line_start, line_end)
    self.txt_hex.see(line_start)
    self.txt_hex.config(state="disabled")
    self.hex_found_lbl.config(
        text=f"[{idx + 1}/{len(self._hex_hits)}] offset 0x{offset:08x}")


def hex_goto_offset(self):
    if not self._hex_data:
        return
    try:
        offset = int(self.hex_offset_var.get().strip(), 16)
    except ValueError:
        try:
            offset = int(self.hex_offset_var.get().strip())
        except ValueError:
            return
    bpr = int(self.hex_bpr_var.get())
    line_no = offset // bpr + 1
    self.txt_hex.see(f"{line_no}.0")
    self.txt_hex.config(state="normal")
    self.txt_hex.tag_remove("hit", "1.0", "end")
    self.txt_hex.tag_add("hit", f"{line_no}.0", f"{line_no}.end")
    self.txt_hex.config(state="disabled")


# ─────────────────────────────────────────────────────────────────────────────
# PATCH FUNCTION — call this with App instance before mainloop
# ─────────────────────────────────────────────────────────────────────────────

def patch_app(app_class, translations_dict: dict):
    """
    Inject new translation keys, new state vars, new tab builders
    and new methods into the App class and TRANSLATIONS dict.
    """

    # 1. Inject translations
    for lang, keys in NEW_TRANSLATION_KEYS.items():
        if lang in translations_dict:
            translations_dict[lang].update(keys)

    # 2. Inject new state variables before _build_notebook is called.
    # StringVars must exist before tab builders reference them.
    original_build_nb_for_vars = app_class._build_notebook

    def _build_notebook_with_vars(self):
        self.sqlite_scan_path  = tk.StringVar()
        self.ios_zip_path      = tk.StringVar()
        self.pw_file_path      = tk.StringVar()
        self.pdf_source_path   = tk.StringVar()
        self.pdf_title_var     = tk.StringVar(
            value="Forensic Report \u2014 Base64 Analysis")
        self.pdf_expert_var    = tk.StringVar(
            value=self.config_mgr.get("pdf_expert"))
        self.pdf_case_var      = tk.StringVar(
            value=self.config_mgr.get("pdf_case"))
        self._sqlite_results   = []
        self._pw_results       = []
        self._dedup_files      = []
        self._hex_data         = b""
        self._hex_hits         = []
        self._hex_hit_idx      = 0
        self.pw_entry_var      = tk.StringVar()
        self.dedup_sort_var    = tk.StringVar(value="none")
        self.hex_search_var    = tk.StringVar()
        self.hex_offset_var    = tk.StringVar(value="0")
        self.hex_bpr_var       = tk.StringVar(value="16")
        original_build_nb_for_vars(self)

    app_class._build_notebook = _build_notebook_with_vars

    # 3. Inject new tab builders and action methods
    method_map = {
        "_build_tab_sqlite":    _build_tab_sqlite,
        "_browse_sqlite":       _browse_sqlite,
        "run_sqlite_scan":      run_sqlite_scan,
        "export_sqlite_csv":    export_sqlite_csv,

        "_build_tab_ios":       _build_tab_ios,
        "_browse_ios_zip":      _browse_ios_zip,
        "run_ios_extract":      run_ios_extract,

        "_build_tab_pwstrength": _build_tab_pwstrength,
        "_pw_live_update":      _pw_live_update,
        "_browse_pw_file":      _browse_pw_file,
        "run_pw_analysis":      run_pw_analysis,
        "run_pw_file_analysis": run_pw_file_analysis,
        "export_pw_csv":        export_pw_csv,

        "_build_tab_dedup":     _build_tab_dedup,
        "dedup_add_files":      dedup_add_files,
        "dedup_clear_list":     dedup_clear_list,
        "run_dedup":            run_dedup,

        "_build_tab_pdf":       _build_tab_pdf,
        "_browse_pdf_source":   _browse_pdf_source,
        "run_generate_pdf":     run_generate_pdf,

        "_build_tab_hex":       _build_tab_hex,
        "hex_open_file":        hex_open_file,
        "hex_refresh_view":     hex_refresh_view,
        "hex_do_search":        hex_do_search,
        "hex_next_result":      hex_next_result,
        "_hex_highlight_hit":   _hex_highlight_hit,
        "hex_goto_offset":      hex_goto_offset,
    }
    for name, func in method_map.items():
        setattr(app_class, name, func)

    # 4. Patch _build_notebook to add 6 new tabs
    original_build_nb = app_class._build_notebook

    def new_build_notebook(self):
        original_build_nb(self)
        new_tab_defs = [
            ("tab_sqlite",    "_build_tab_sqlite"),
            ("tab_ios",       "_build_tab_ios"),
            ("tab_pwstrength","_build_tab_pwstrength"),
            ("tab_dedup",     "_build_tab_dedup"),
            ("tab_pdf",       "_build_tab_pdf"),
            ("tab_hex",       "_build_tab_hex"),
        ]
        for key, builder_name in new_tab_defs:
            frame = ttk.Frame(self.notebook)
            self.tab_frames[key] = frame
            self.notebook.add(frame, text=self.T.get(key, key))
            getattr(self, builder_name)(frame)

    app_class._build_notebook = new_build_notebook

    # 5. Patch _on_lang_change to also update new tab labels
    original_lang_change = app_class._on_lang_change

    def new_lang_change(self, _=None):
        original_lang_change(self, _)
        new_tab_keys = [
            "tab_sqlite", "tab_ios", "tab_pwstrength",
            "tab_dedup", "tab_pdf", "tab_hex",
        ]
        # New tabs start at index 9 (after 9 existing tabs)
        for i, key in enumerate(new_tab_keys, start=9):
            try:
                self.notebook.tab(i, text=self.T.get(key, key))
            except Exception:
                pass

    app_class._on_lang_change = new_lang_change

    # 6. Patch _save_config for new fields
    original_save = app_class._save_config

    def new_save_config(self):
        original_save(self)
        self.config_mgr.set("pdf_expert",
                            self.pdf_expert_var.get()
                            if hasattr(self, "pdf_expert_var") else "")
        self.config_mgr.set("pdf_case",
                            self.pdf_case_var.get()
                            if hasattr(self, "pdf_case_var") else "")
        self.config_mgr.save()

    app_class._save_config = new_save_config
