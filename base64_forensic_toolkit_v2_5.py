#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Base64 Forensic Toolkit v2.5
# Laboratorium Elektroniki / Krystian Zarzecki
#
# NEW in v2.5:
#   + Keychain.plist decoder (GrayKey) -> table view + CSV export
#   + JWT detector & payload decoder (Tab 6)
#   + Birthday dictionary generator (DDMM/MMDD/DDMMRR/YYYYMMDD etc.)
#   + Entropy analysis — detect encrypted/compressed blocks
#   + Dark mode toggle
#   + config.ini — persist settings between sessions
#   + Recent files history (last 10 per input)
#   + Progress bar on ALL operations
#   + Multilanguage: PL / EN / DE / FR / ES / IT

import base64
import configparser
import hashlib
import json
import math
import os
import plistlib
import random
import re
import string
import tkinter as tk
import zipfile
from collections import Counter
from datetime import datetime, date
from tkinter import filedialog, messagebox, scrolledtext, ttk

VERSION = "2.5"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "b64toolkit.ini")
MAX_RECENT = 10

# =============================================================================
# TRANSLATIONS
# =============================================================================
TRANSLATIONS = {
    "PL": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Parser PIN Base64",
        "tab_dictgen": "Generator słownika PIN",
        "tab_converter": "Konwerter TXT/Base64",
        "tab_live": "Encoder/Decoder Live",
        "tab_research": "Analiza badawcza",
        "tab_keychain": "Keychain Decoder",
        "tab_jwt": "Analizator JWT",
        "tab_birthday": "Słownik dat urodzenia",
        "tab_entropy": "Analiza entropii",
        "btn_browse": "Wybierz plik",
        "btn_run": "Uruchom",
        "btn_clear": "Wyczyść",
        "btn_load_dict": "Załaduj słownik",
        "btn_export_csv": "Eksportuj CSV",
        "lbl_file": "Plik:",
        "lbl_status_ready": "Gotowy",
        "lbl_dict_builtin": "Wbudowany słownik PIN (4/6 cyfr)",
        "lbl_dict_file": "Słownik z pliku",
        "lbl_search_4": "Szukaj 4-cyfrowych (0000–9999)",
        "lbl_search_6": "Szukaj 6-cyfrowych (000000–999999)",
        "lbl_pin_from": "PIN od:",
        "lbl_pin_to": "do:",
        "lbl_format_plain": "Lista PIN (czysty TXT)",
        "lbl_format_b64": "Słownik Base64 → PIN",
        "lbl_random_order": "Losowa kolejność (random shuffle)",
        "lbl_parts": "Podziel na pliki:",
        "lbl_dark_mode": "Ciemny motyw",
        "lbl_language": "Język / Language:",
        "lbl_recent": "Ostatnie pliki:",
        "lbl_entropy_threshold": "Próg entropii (0–8):",
        "lbl_block_size": "Rozmiar bloku (bajty):",
        "lbl_birthday_dob": "Data urodzenia (RRRR-MM-DD):",
        "lbl_birthday_formats": "Formaty do generowania:",
        "lbl_jwt_file": "Plik do analizy JWT:",
        "lbl_keychain_file": "Plik keychain.plist:",
        "msg_no_file": "Najpierw wybierz plik.",
        "msg_no_range": "Zaznacz co najmniej jeden zakres (4 lub 6 cyfr).",
        "msg_done": "Zakończono.",
        "msg_error": "Błąd",
        "msg_confirm_gen": "Zostanie wygenerowanych ~{count} PIN-ów w {parts} plikach.\nSzacowany rozmiar: ~{mb:.1f} MB\nKontynuować?",
        "msg_random_too_big": "Zbyt dużo PIN-ów do losowego generowania (max 5 000 000).",
        "msg_no_dict_file": "Nie załadowano słownika z pliku.",
        "report_saved": "Raport zapisany do: {path}",
        "analysis_done": "Analiza zakończona.",
        "lbl_t2b_group": "Tekst → Base64 (plik)",
        "lbl_b2t_group": "Base64 → Tekst (plik)",
        "btn_t2b_run": "Konwertuj Tekst → Base64 i zapisz",
        "btn_b2t_run": "Konwertuj Base64 → Tekst i zapisz",
        "lbl_live_info": "Wklej tekst lub Base64 w górnym polu, następnie użyj przycisków.",
        "btn_live_encode": "Tekst → Base64",
        "btn_live_decode": "Base64 → Tekst",
        "btn_live_swap": "↕ Zamień",
        "lbl_single_file": "Analiza pojedynczego pliku",
        "lbl_zip_group": "Analiza archiwum ZIP / FFS",
        "btn_run_zip": "Uruchom (ZIP)",
        "lbl_kc_info": "Wczytaj plik keychain.plist z GrayKey lub innego narzędzia forensic.\nTabela pokazuje klasy genp/inet/keys/cert z zdekodowanymi polami.",
        "lbl_filter": "Filtr:",
        "lbl_class": "Klasa:",
        "lbl_jwt_info": "Analiza JWT (JSON Web Token) w pliku tekstowym.\nWykrywa tokeny eyJ..., dekoduje nagłówek + payload.\nDziała na plikach keychain, dump, FFS, log.",
        "lbl_bday_info": "Generator słownika z dat urodzenia.\nGeneruje wzorce datowe (DDMM, MMDD, DDMMYYYY itd.) jako czysty TXT i/lub słownik Base64.\nPrzydatne do odzyskiwania haseł opartych na datach.",
        "lbl_entropy_info": "Analiza entropii — wykrywa bloki zaszyfrowane/skompresowane.\nWysoka entropia (>7.2) → prawdopodobnie dane zaszyfrowane lub skompresowane.",
        "lbl_options": "Opcje",
        "lbl_dictionary": "Słownik",
        "lbl_length": "Długość PIN",
        "lbl_format": "Format wyjściowy",
        "lbl_input": "Wejście",
        "lbl_output": "Wyjście",
        "status_analyzing_pin": "Analiza PIN w toku...",
        "status_analyzing": "Analiza w toku...",
        "status_analyzing_zip": "Analiza ZIP w toku...",
        "log_t2b": "Tekst→Base64: {total} linii, {err} błędów → {path}",
        "log_b2t": "Base64→Tekst: {total} linii, {err} błędów → {path}",
        "msg_no_format": "Zaznacz przynajmniej jeden format wyjściowy.",
        "msg_invalid_date": "Nieprawidłowy format daty. Użyj YYYY-MM-DD.",
        "msg_no_bday_format": "Zaznacz przynajmniej jeden format daty.",
        "msg_no_kc_data": "Brak danych do eksportu.",
        "msg_invalid_entropy": "Nieprawidłowy próg lub rozmiar bloku.",
    },
    "EN": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Base64 PIN Parser",
        "tab_dictgen": "PIN Dictionary Generator",
        "tab_converter": "TXT/Base64 Converter",
        "tab_live": "Live Encoder/Decoder",
        "tab_research": "Research Analysis",
        "tab_keychain": "Keychain Decoder",
        "tab_jwt": "JWT Analyzer",
        "tab_birthday": "Birthday Dictionary",
        "tab_entropy": "Entropy Analysis",
        "btn_browse": "Browse",
        "btn_run": "Run",
        "btn_clear": "Clear",
        "btn_load_dict": "Load dictionary",
        "btn_export_csv": "Export CSV",
        "lbl_file": "File:",
        "lbl_status_ready": "Ready",
        "lbl_dict_builtin": "Built-in PIN dict (4/6 digits)",
        "lbl_dict_file": "Dictionary from file",
        "lbl_search_4": "Search 4-digit (0000–9999)",
        "lbl_search_6": "Search 6-digit (000000–999999)",
        "lbl_pin_from": "PIN length from:",
        "lbl_pin_to": "to:",
        "lbl_format_plain": "Plain PIN list (TXT)",
        "lbl_format_b64": "Base64 → PIN dictionary",
        "lbl_random_order": "Random order (shuffle)",
        "lbl_parts": "Split into files:",
        "lbl_dark_mode": "Dark mode",
        "lbl_language": "Language:",
        "lbl_recent": "Recent files:",
        "lbl_entropy_threshold": "Entropy threshold (0–8):",
        "lbl_block_size": "Block size (bytes):",
        "lbl_birthday_dob": "Date of birth (YYYY-MM-DD):",
        "lbl_birthday_formats": "Formats to generate:",
        "lbl_jwt_file": "File for JWT analysis:",
        "lbl_keychain_file": "keychain.plist file:",
        "msg_no_file": "Please select a file first.",
        "msg_no_range": "Select at least one range (4 or 6 digits).",
        "msg_done": "Done.",
        "msg_error": "Error",
        "msg_confirm_gen": "Will generate ~{count} PINs in {parts} file(s).\nEstimated size: ~{mb:.1f} MB\nContinue?",
        "msg_random_too_big": "Too many PINs for random generation (max 5,000,000).",
        "msg_no_dict_file": "No dictionary file loaded.",
        "report_saved": "Report saved to: {path}",
        "analysis_done": "Analysis complete.",
        "lbl_t2b_group": "Text → Base64 (file)",
        "lbl_b2t_group": "Base64 → Text (file)",
        "btn_t2b_run": "Convert Text → Base64 and save",
        "btn_b2t_run": "Convert Base64 → Text and save",
        "lbl_live_info": "Paste text or Base64 in the top field, then use the buttons below.",
        "btn_live_encode": "Text → Base64",
        "btn_live_decode": "Base64 → Text",
        "btn_live_swap": "↕ Swap",
        "lbl_single_file": "Single file analysis",
        "lbl_zip_group": "ZIP / FFS archive analysis",
        "btn_run_zip": "Run (ZIP)",
        "lbl_kc_info": "Load keychain.plist from GrayKey or other forensic tool.\nTable shows genp/inet/keys/cert classes with decoded fields.",
        "lbl_filter": "Filter:",
        "lbl_class": "Class:",
        "lbl_jwt_info": "JWT (JSON Web Token) analysis in a text file.\nDetects eyJ... tokens, decodes header + payload.\nWorks on keychain, dump, FFS, log files.",
        "lbl_bday_info": "Birthday dictionary generator.\nGenerates date patterns (DDMM, MMDD, DDMMYYYY etc.) as plain TXT and/or Base64 dict.\nUseful for recovering date-based passwords.",
        "lbl_entropy_info": "Entropy analysis — detects encrypted/compressed blocks.\nHigh entropy (>7.2) → likely encrypted or compressed data.",
        "lbl_options": "Options",
        "lbl_dictionary": "Dictionary",
        "lbl_length": "PIN Length",
        "lbl_format": "Output format",
        "lbl_input": "Input",
        "lbl_output": "Output",
        "status_analyzing_pin": "PIN analysis in progress...",
        "status_analyzing": "Analysis in progress...",
        "status_analyzing_zip": "ZIP analysis in progress...",
        "log_t2b": "Text→Base64: {total} lines, {err} errors → {path}",
        "log_b2t": "Base64→Text: {total} lines, {err} errors → {path}",
        "msg_no_format": "Select at least one output format.",
        "msg_invalid_date": "Invalid date format. Use YYYY-MM-DD.",
        "msg_no_bday_format": "Select at least one date format.",
        "msg_no_kc_data": "No data to export.",
        "msg_invalid_entropy": "Invalid threshold or block size.",
    },
    "DE": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Base64 PIN Parser",
        "tab_dictgen": "PIN-Wörterbuch-Generator",
        "tab_converter": "TXT/Base64-Konverter",
        "tab_live": "Live Encoder/Decoder",
        "tab_research": "Forschungsanalyse",
        "tab_keychain": "Keychain Decoder",
        "tab_jwt": "JWT Analyzer",
        "tab_birthday": "Geburtsdatum-Wörterbuch",
        "tab_entropy": "Entropieanalyse",
        "btn_browse": "Datei wählen",
        "btn_run": "Ausführen",
        "btn_clear": "Löschen",
        "btn_load_dict": "Wörterbuch laden",
        "btn_export_csv": "CSV exportieren",
        "lbl_file": "Datei:",
        "lbl_status_ready": "Bereit",
        "lbl_dict_builtin": "Eingebautes PIN-Wörterbuch (4/6 Ziffern)",
        "lbl_dict_file": "Wörterbuch aus Datei",
        "lbl_search_4": "4-stellige suchen (0000–9999)",
        "lbl_search_6": "6-stellige suchen (000000–999999)",
        "lbl_pin_from": "PIN-Länge von:",
        "lbl_pin_to": "bis:",
        "lbl_format_plain": "Einfache PIN-Liste (TXT)",
        "lbl_format_b64": "Base64 → PIN-Wörterbuch",
        "lbl_random_order": "Zufällige Reihenfolge (shuffle)",
        "lbl_parts": "In Dateien aufteilen:",
        "lbl_dark_mode": "Dunkles Design",
        "lbl_language": "Sprache:",
        "lbl_recent": "Letzte Dateien:",
        "lbl_entropy_threshold": "Entropieschwelle (0–8):",
        "lbl_block_size": "Blockgröße (Bytes):",
        "lbl_birthday_dob": "Geburtsdatum (JJJJ-MM-TT):",
        "lbl_birthday_formats": "Zu generierende Formate:",
        "lbl_jwt_file": "Datei für JWT-Analyse:",
        "lbl_keychain_file": "keychain.plist Datei:",
        "msg_no_file": "Bitte zuerst eine Datei auswählen.",
        "msg_no_range": "Mindestens einen Bereich auswählen (4 oder 6 Ziffern).",
        "msg_done": "Fertig.",
        "msg_error": "Fehler",
        "msg_confirm_gen": "Es werden ~{count} PINs in {parts} Datei(en) generiert.\nGeschätzte Größe: ~{mb:.1f} MB\nFortfahren?",
        "msg_random_too_big": "Zu viele PINs für zufällige Generierung (max 5.000.000).",
        "msg_no_dict_file": "Kein Wörterbuch geladen.",
        "report_saved": "Bericht gespeichert unter: {path}",
        "analysis_done": "Analyse abgeschlossen.",
        "lbl_t2b_group": "Text → Base64 (Datei)",
        "lbl_b2t_group": "Base64 → Text (Datei)",
        "btn_t2b_run": "Text → Base64 konvertieren und speichern",
        "btn_b2t_run": "Base64 → Text konvertieren und speichern",
        "lbl_live_info": "Text oder Base64 in das obere Feld einfügen, dann Schaltflächen verwenden.",
        "btn_live_encode": "Text → Base64",
        "btn_live_decode": "Base64 → Text",
        "btn_live_swap": "↕ Tauschen",
        "lbl_single_file": "Einzeldateianalyse",
        "lbl_zip_group": "ZIP / FFS Archivanalyse",
        "btn_run_zip": "Ausführen (ZIP)",
        "lbl_kc_info": "keychain.plist von GrayKey oder anderem Forensik-Tool laden.\nTabelle zeigt genp/inet/keys/cert Klassen mit dekodierten Feldern.",
        "lbl_filter": "Filter:",
        "lbl_class": "Klasse:",
        "lbl_jwt_info": "JWT (JSON Web Token) Analyse in einer Textdatei.\nErkennt eyJ... Token, dekodiert Header + Payload.",
        "lbl_bday_info": "Geburtsdatum-Wörterbuch-Generator.\nErzeugt Datumsmuster (TTMM, MMTT, TTMMJJJJ usw.) als TXT und/oder Base64.",
        "lbl_entropy_info": "Entropieanalyse — erkennt verschlüsselte/komprimierte Blöcke.\nHohe Entropie (>7.2) → wahrscheinlich verschlüsselte Daten.",
        "lbl_options": "Optionen",
        "lbl_dictionary": "Wörterbuch",
        "lbl_length": "PIN-Länge",
        "lbl_format": "Ausgabeformat",
        "lbl_input": "Eingabe",
        "lbl_output": "Ausgabe",
        "status_analyzing_pin": "PIN-Analyse läuft...",
        "status_analyzing": "Analyse läuft...",
        "status_analyzing_zip": "ZIP-Analyse läuft...",
        "log_t2b": "Text→Base64: {total} Zeilen, {err} Fehler → {path}",
        "log_b2t": "Base64→Text: {total} Zeilen, {err} Fehler → {path}",
        "msg_no_format": "Mindestens ein Ausgabeformat auswählen.",
        "msg_invalid_date": "Ungültiges Datumsformat. Bitte JJJJ-MM-TT verwenden.",
        "msg_no_bday_format": "Mindestens ein Datumsformat auswählen.",
        "msg_no_kc_data": "Keine Daten zum Exportieren.",
        "msg_invalid_entropy": "Ungültige Schwelle oder Blockgröße.",
    },
    "FR": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Parseur PIN Base64",
        "tab_dictgen": "Générateur de dictionnaire PIN",
        "tab_converter": "Convertisseur TXT/Base64",
        "tab_live": "Encodeur/Décodeur Live",
        "tab_research": "Analyse de recherche",
        "tab_keychain": "Décodeur Keychain",
        "tab_jwt": "Analyseur JWT",
        "tab_birthday": "Dictionnaire de dates de naissance",
        "tab_entropy": "Analyse d'entropie",
        "btn_browse": "Parcourir",
        "btn_run": "Exécuter",
        "btn_clear": "Effacer",
        "btn_load_dict": "Charger dictionnaire",
        "btn_export_csv": "Exporter CSV",
        "lbl_file": "Fichier :",
        "lbl_status_ready": "Prêt",
        "lbl_dict_builtin": "Dictionnaire PIN intégré (4/6 chiffres)",
        "lbl_dict_file": "Dictionnaire depuis fichier",
        "lbl_search_4": "Chercher 4 chiffres (0000–9999)",
        "lbl_search_6": "Chercher 6 chiffres (000000–999999)",
        "lbl_pin_from": "Longueur PIN de :",
        "lbl_pin_to": "à :",
        "lbl_format_plain": "Liste PIN simple (TXT)",
        "lbl_format_b64": "Dictionnaire Base64 → PIN",
        "lbl_random_order": "Ordre aléatoire (shuffle)",
        "lbl_parts": "Diviser en fichiers :",
        "lbl_dark_mode": "Mode sombre",
        "lbl_language": "Langue :",
        "lbl_recent": "Fichiers récents :",
        "lbl_entropy_threshold": "Seuil d'entropie (0–8) :",
        "lbl_block_size": "Taille de bloc (octets) :",
        "lbl_birthday_dob": "Date de naissance (AAAA-MM-JJ) :",
        "lbl_birthday_formats": "Formats à générer :",
        "lbl_jwt_file": "Fichier pour analyse JWT :",
        "lbl_keychain_file": "Fichier keychain.plist :",
        "msg_no_file": "Veuillez d'abord sélectionner un fichier.",
        "msg_no_range": "Sélectionnez au moins une plage (4 ou 6 chiffres).",
        "msg_done": "Terminé.",
        "msg_error": "Erreur",
        "msg_confirm_gen": "Génération de ~{count} PINs en {parts} fichier(s).\nTaille estimée : ~{mb:.1f} Mo\nContinuer ?",
        "msg_random_too_big": "Trop de PINs pour une génération aléatoire (max 5 000 000).",
        "msg_no_dict_file": "Aucun dictionnaire chargé.",
        "report_saved": "Rapport sauvegardé dans : {path}",
        "analysis_done": "Analyse terminée.",
        "lbl_t2b_group": "Texte → Base64 (fichier)",
        "lbl_b2t_group": "Base64 → Texte (fichier)",
        "btn_t2b_run": "Convertir Texte → Base64 et sauvegarder",
        "btn_b2t_run": "Convertir Base64 → Texte et sauvegarder",
        "lbl_live_info": "Collez du texte ou du Base64 dans le champ supérieur, puis utilisez les boutons.",
        "btn_live_encode": "Texte → Base64",
        "btn_live_decode": "Base64 → Texte",
        "btn_live_swap": "↕ Échanger",
        "lbl_single_file": "Analyse d'un fichier unique",
        "lbl_zip_group": "Analyse d'archive ZIP / FFS",
        "btn_run_zip": "Exécuter (ZIP)",
        "lbl_kc_info": "Chargez keychain.plist depuis GrayKey ou un autre outil forensique.\nLe tableau affiche les classes genp/inet/keys/cert avec les champs décodés.",
        "lbl_filter": "Filtre :",
        "lbl_class": "Classe :",
        "lbl_jwt_info": "Analyse JWT (JSON Web Token) dans un fichier texte.\nDétecte les tokens eyJ..., décode l'en-tête + la charge utile.",
        "lbl_bday_info": "Générateur de dictionnaire de dates de naissance.\nGénère des motifs de date (JJMM, MMJJ, JJMMAAAA, etc.) en TXT et/ou Base64.",
        "lbl_entropy_info": "Analyse d'entropie — détecte les blocs chiffrés/compressés.\nEntropie élevée (>7.2) → données probablement chiffrées.",
        "lbl_options": "Options",
        "lbl_dictionary": "Dictionnaire",
        "lbl_length": "Longueur PIN",
        "lbl_format": "Format de sortie",
        "lbl_input": "Entrée",
        "lbl_output": "Sortie",
        "status_analyzing_pin": "Analyse PIN en cours...",
        "status_analyzing": "Analyse en cours...",
        "status_analyzing_zip": "Analyse ZIP en cours...",
        "log_t2b": "Texte→Base64 : {total} lignes, {err} erreurs → {path}",
        "log_b2t": "Base64→Texte : {total} lignes, {err} erreurs → {path}",
        "msg_no_format": "Sélectionnez au moins un format de sortie.",
        "msg_invalid_date": "Format de date invalide. Utilisez AAAA-MM-JJ.",
        "msg_no_bday_format": "Sélectionnez au moins un format de date.",
        "msg_no_kc_data": "Aucune donnée à exporter.",
        "msg_invalid_entropy": "Seuil ou taille de bloc invalide.",
    },
    "ES": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Analizador PIN Base64",
        "tab_dictgen": "Generador de diccionario PIN",
        "tab_converter": "Convertidor TXT/Base64",
        "tab_live": "Codificador/Decodificador Live",
        "tab_research": "Análisis de investigación",
        "tab_keychain": "Decodificador Keychain",
        "tab_jwt": "Analizador JWT",
        "tab_birthday": "Diccionario de fechas de nacimiento",
        "tab_entropy": "Análisis de entropía",
        "btn_browse": "Examinar",
        "btn_run": "Ejecutar",
        "btn_clear": "Limpiar",
        "btn_load_dict": "Cargar diccionario",
        "btn_export_csv": "Exportar CSV",
        "lbl_file": "Archivo:",
        "lbl_status_ready": "Listo",
        "lbl_dict_builtin": "Diccionario PIN integrado (4/6 dígitos)",
        "lbl_dict_file": "Diccionario desde archivo",
        "lbl_search_4": "Buscar 4 dígitos (0000–9999)",
        "lbl_search_6": "Buscar 6 dígitos (000000–999999)",
        "lbl_pin_from": "Longitud PIN desde:",
        "lbl_pin_to": "hasta:",
        "lbl_format_plain": "Lista PIN simple (TXT)",
        "lbl_format_b64": "Diccionario Base64 → PIN",
        "lbl_random_order": "Orden aleatorio (shuffle)",
        "lbl_parts": "Dividir en archivos:",
        "lbl_dark_mode": "Modo oscuro",
        "lbl_language": "Idioma:",
        "lbl_recent": "Archivos recientes:",
        "lbl_entropy_threshold": "Umbral de entropía (0–8):",
        "lbl_block_size": "Tamaño de bloque (bytes):",
        "lbl_birthday_dob": "Fecha de nacimiento (AAAA-MM-DD):",
        "lbl_birthday_formats": "Formatos a generar:",
        "lbl_jwt_file": "Archivo para análisis JWT:",
        "lbl_keychain_file": "Archivo keychain.plist:",
        "msg_no_file": "Primero seleccione un archivo.",
        "msg_no_range": "Seleccione al menos un rango (4 o 6 dígitos).",
        "msg_done": "Listo.",
        "msg_error": "Error",
        "msg_confirm_gen": "Se generarán ~{count} PINs en {parts} archivo(s).\nTamaño estimado: ~{mb:.1f} MB\n¿Continuar?",
        "msg_random_too_big": "Demasiados PINs para generación aleatoria (máx. 5 000 000).",
        "msg_no_dict_file": "No se ha cargado ningún diccionario.",
        "report_saved": "Informe guardado en: {path}",
        "analysis_done": "Análisis completado.",
        "lbl_t2b_group": "Texto → Base64 (archivo)",
        "lbl_b2t_group": "Base64 → Texto (archivo)",
        "btn_t2b_run": "Convertir Texto → Base64 y guardar",
        "btn_b2t_run": "Convertir Base64 → Texto y guardar",
        "lbl_live_info": "Pegue texto o Base64 en el campo superior y use los botones.",
        "btn_live_encode": "Texto → Base64",
        "btn_live_decode": "Base64 → Texto",
        "btn_live_swap": "↕ Intercambiar",
        "lbl_single_file": "Análisis de archivo único",
        "lbl_zip_group": "Análisis de archivo ZIP / FFS",
        "btn_run_zip": "Ejecutar (ZIP)",
        "lbl_kc_info": "Cargue keychain.plist desde GrayKey u otra herramienta forense.\nLa tabla muestra clases genp/inet/keys/cert con campos decodificados.",
        "lbl_filter": "Filtro:",
        "lbl_class": "Clase:",
        "lbl_jwt_info": "Análisis JWT (JSON Web Token) en un archivo de texto.\nDetecta tokens eyJ..., decodifica encabezado + carga útil.",
        "lbl_bday_info": "Generador de diccionario de fechas de nacimiento.\nGenera patrones de fecha (DDMM, MMDD, DDMMAAAA, etc.) como TXT y/o Base64.",
        "lbl_entropy_info": "Análisis de entropía — detecta bloques cifrados/comprimidos.\nEntropía alta (>7.2) → datos probablemente cifrados.",
        "lbl_options": "Opciones",
        "lbl_dictionary": "Diccionario",
        "lbl_length": "Longitud PIN",
        "lbl_format": "Formato de salida",
        "lbl_input": "Entrada",
        "lbl_output": "Salida",
        "status_analyzing_pin": "Análisis PIN en curso...",
        "status_analyzing": "Análisis en curso...",
        "status_analyzing_zip": "Análisis ZIP en curso...",
        "log_t2b": "Texto→Base64: {total} líneas, {err} errores → {path}",
        "log_b2t": "Base64→Texto: {total} líneas, {err} errores → {path}",
        "msg_no_format": "Seleccione al menos un formato de salida.",
        "msg_invalid_date": "Formato de fecha no válido. Use AAAA-MM-DD.",
        "msg_no_bday_format": "Seleccione al menos un formato de fecha.",
        "msg_no_kc_data": "No hay datos para exportar.",
        "msg_invalid_entropy": "Umbral o tamaño de bloque no válido.",
    },
    "IT": {
        "app_title": "Base64 Forensic Toolkit",
        "tab_parser": "Parser PIN Base64",
        "tab_dictgen": "Generatore dizionario PIN",
        "tab_converter": "Convertitore TXT/Base64",
        "tab_live": "Encoder/Decoder Live",
        "tab_research": "Analisi di ricerca",
        "tab_keychain": "Decodificatore Keychain",
        "tab_jwt": "Analizzatore JWT",
        "tab_birthday": "Dizionario date di nascita",
        "tab_entropy": "Analisi entropia",
        "btn_browse": "Sfoglia",
        "btn_run": "Esegui",
        "btn_clear": "Pulisci",
        "btn_load_dict": "Carica dizionario",
        "btn_export_csv": "Esporta CSV",
        "lbl_file": "File:",
        "lbl_status_ready": "Pronto",
        "lbl_dict_builtin": "Dizionario PIN integrato (4/6 cifre)",
        "lbl_dict_file": "Dizionario da file",
        "lbl_search_4": "Cerca 4 cifre (0000–9999)",
        "lbl_search_6": "Cerca 6 cifre (000000–999999)",
        "lbl_pin_from": "Lunghezza PIN da:",
        "lbl_pin_to": "a:",
        "lbl_format_plain": "Lista PIN semplice (TXT)",
        "lbl_format_b64": "Dizionario Base64 → PIN",
        "lbl_random_order": "Ordine casuale (shuffle)",
        "lbl_parts": "Dividi in file:",
        "lbl_dark_mode": "Modalità scura",
        "lbl_language": "Lingua:",
        "lbl_recent": "File recenti:",
        "lbl_entropy_threshold": "Soglia entropia (0–8):",
        "lbl_block_size": "Dimensione blocco (byte):",
        "lbl_birthday_dob": "Data di nascita (AAAA-MM-GG):",
        "lbl_birthday_formats": "Formati da generare:",
        "lbl_jwt_file": "File per analisi JWT:",
        "lbl_keychain_file": "File keychain.plist:",
        "msg_no_file": "Seleziona prima un file.",
        "msg_no_range": "Seleziona almeno un intervallo (4 o 6 cifre).",
        "msg_done": "Completato.",
        "msg_error": "Errore",
        "msg_confirm_gen": "Verranno generati ~{count} PIN in {parts} file.\nDimensione stimata: ~{mb:.1f} MB\nContinuare?",
        "msg_random_too_big": "Troppi PIN per la generazione casuale (max 5.000.000).",
        "msg_no_dict_file": "Nessun dizionario caricato.",
        "report_saved": "Report salvato in: {path}",
        "analysis_done": "Analisi completata.",
        "lbl_t2b_group": "Testo → Base64 (file)",
        "lbl_b2t_group": "Base64 → Testo (file)",
        "btn_t2b_run": "Converti Testo → Base64 e salva",
        "btn_b2t_run": "Converti Base64 → Testo e salva",
        "lbl_live_info": "Incolla testo o Base64 nel campo superiore, poi usa i pulsanti.",
        "btn_live_encode": "Testo → Base64",
        "btn_live_decode": "Base64 → Testo",
        "btn_live_swap": "↕ Scambia",
        "lbl_single_file": "Analisi file singolo",
        "lbl_zip_group": "Analisi archivio ZIP / FFS",
        "btn_run_zip": "Esegui (ZIP)",
        "lbl_kc_info": "Carica keychain.plist da GrayKey o altro strumento forense.\nLa tabella mostra le classi genp/inet/keys/cert con campi decodificati.",
        "lbl_filter": "Filtro:",
        "lbl_class": "Classe:",
        "lbl_jwt_info": "Analisi JWT (JSON Web Token) in un file di testo.\nRileva token eyJ..., decodifica intestazione + payload.",
        "lbl_bday_info": "Generatore di dizionario date di nascita.\nGenera pattern di date (GGMM, MMGG, GGMMAAAA, ecc.) come TXT e/o Base64.",
        "lbl_entropy_info": "Analisi entropia — rileva blocchi cifrati/compressi.\nAlta entropia (>7.2) → dati probabilmente cifrati.",
        "lbl_options": "Opzioni",
        "lbl_dictionary": "Dizionario",
        "lbl_length": "Lunghezza PIN",
        "lbl_format": "Formato output",
        "lbl_input": "Ingresso",
        "lbl_output": "Uscita",
        "status_analyzing_pin": "Analisi PIN in corso...",
        "status_analyzing": "Analisi in corso...",
        "status_analyzing_zip": "Analisi ZIP in corso...",
        "log_t2b": "Testo→Base64: {total} righe, {err} errori → {path}",
        "log_b2t": "Base64→Testo: {total} righe, {err} errori → {path}",
        "msg_no_format": "Seleziona almeno un formato di output.",
        "msg_invalid_date": "Formato data non valido. Usa AAAA-MM-GG.",
        "msg_no_bday_format": "Seleziona almeno un formato di data.",
        "msg_no_kc_data": "Nessun dato da esportare.",
        "msg_invalid_entropy": "Soglia o dimensione blocco non valida.",
    },
}

THEMES = {
    "light": {
        "bg": "#f0f0f0", "fg": "#000000",
        "entry_bg": "#ffffff", "entry_fg": "#000000",
        "text_bg": "#ffffff", "text_fg": "#000000",
        "btn_bg": "#e0e0e0", "btn_fg": "#000000",
        "run_bg": "#2a7a2a", "run_fg": "#ffffff",
        "blue_bg": "#2a5a9a", "blue_fg": "#ffffff",
        "frame_bg": "#f0f0f0",
        "status_bg": "#d0d0d0",
        "hit_color": "#005500",
    },
    "dark": {
        "bg": "#1e1e1e", "fg": "#d4d4d4",
        "entry_bg": "#2d2d2d", "entry_fg": "#d4d4d4",
        "text_bg": "#1a1a1a", "text_fg": "#c8c8c8",
        "btn_bg": "#3c3c3c", "btn_fg": "#d4d4d4",
        "run_bg": "#1a5c1a", "run_fg": "#ffffff",
        "blue_bg": "#1a3a6a", "blue_fg": "#ffffff",
        "frame_bg": "#252526",
        "status_bg": "#007acc",
        "hit_color": "#4ec94e",
    },
}


# =============================================================================
# CONFIG
# =============================================================================
class Config:
    def __init__(self):
        self.cfg = configparser.ConfigParser()
        self.defaults = {
            "language": "EN",
            "dark_mode": "0",
            "pin_min": "4",
            "pin_max": "6",
            "pin_parts": "1",
            "pin_plain": "1",
            "pin_b64": "0",
            "pin_random": "0",
            "entropy_threshold": "7.2",
            "entropy_block": "256",
            "recent_parser": "",
            "recent_research": "",
            "recent_keychain": "",
            "recent_jwt": "",
            "recent_birthday": "",
            "recent_entropy": "",
        }
        self.load()

    def load(self):
        self.cfg.read(CONFIG_FILE, encoding="utf-8")
        if "app" not in self.cfg:
            self.cfg["app"] = {}

    def get(self, key: str) -> str:
        return self.cfg["app"].get(key, self.defaults.get(key, ""))

    def set(self, key: str, value: str):
        self.cfg["app"][key] = value

    def save(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                self.cfg.write(f)
        except Exception:
            pass

    def get_recent(self, key: str) -> list:
        raw = self.get(f"recent_{key}")
        if not raw:
            return []
        return [p for p in raw.split("|") if p]

    def add_recent(self, key: str, path: str):
        lst = self.get_recent(key)
        if path in lst:
            lst.remove(path)
        lst.insert(0, path)
        lst = lst[:MAX_RECENT]
        self.set(f"recent_{key}", "|".join(lst))


# =============================================================================
# HELPERS
# =============================================================================
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = Counter(data)
    ln = len(data)
    return -sum((c / ln) * math.log2(c / ln) for c in cnt.values())


def compute_file_hashes(path: str) -> dict:
    hashes = {"md5": "ERROR", "sha256": "ERROR", "size": 0}
    try:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
        hashes["size"] = size
    except Exception:
        pass
    return hashes


def classify_decoded(decoded_bytes: bytes) -> str:
    try:
        decoded_text = decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return "binary"
    total_len = len(decoded_text)
    if total_len == 0:
        return "binary"
    if total_len <= 10 and decoded_text.isdigit():
        if total_len == 4:
            return "pin4"
        if total_len == 6:
            return "pin6"
        return "digits"
    printable_ratio = sum(1 for c in decoded_text if c in string.printable) / total_len
    if printable_ratio > 0.85:
        return "printable"
    return "binary"


def build_pin_map(digit_len: int) -> dict:
    mapping = {}
    for i in range(10 ** digit_len):
        s = str(i).zfill(digit_len)
        enc = base64.b64encode(s.encode()).decode()
        enc_s = enc.rstrip("=")
        mapping[enc] = s
        mapping[enc_s] = s
    return mapping


def generate_birthday_strings(dob: date) -> dict:
    """Return dict of format_name -> list_of_strings for a given date."""
    d = f"{dob.day:02d}"
    m = f"{dob.month:02d}"
    y4 = f"{dob.year:04d}"
    y2 = y4[2:]
    results = {
        "DDMM":     [d + m],
        "MMDD":     [m + d],
        "DDMMYYYY": [d + m + y4],
        "MMDDYYYY": [m + d + y4],
        "YYYYMMDD": [y4 + m + d],
        "DDMMYY":   [d + m + y2],
        "MMDDYY":   [m + d + y2],
        "YYMMDD":   [y2 + m + d],
        "DDMMY":    [d + m + y4[-1]],
        "DMYYYY":   [str(dob.day) + str(dob.month) + y4],
        "YYYY":     [y4],
        "DDMMYYYY_rev": [y4 + m + d],
        "D_M_YYYY": [f"{dob.day}.{dob.month}.{dob.year}".replace(".", "")],
    }
    # Also add reversed variants
    extras = {}
    for k, lst in results.items():
        extras[k + "_rev"] = [s[::-1] for s in lst]
    results.update(extras)
    return results


# =============================================================================
# MAIN APP
# =============================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.config_mgr = Config()
        self.lang = self.config_mgr.get("language") or "EN"
        self.dark_mode = self.config_mgr.get("dark_mode") == "1"
        self.theme = THEMES["dark"] if self.dark_mode else THEMES["light"]
        self.T = TRANSLATIONS[self.lang]

        self.title(f"{self.T['app_title']} v{VERSION}")
        self.geometry("1280x860")
        self.configure(bg=self.theme["bg"])

        # App icon — load from same directory as the script or frozen EXE
        try:
            import sys as _sys
            _base = getattr(_sys, "_MEIPASS",
                            os.path.dirname(os.path.abspath(__file__)))
            _ico = os.path.join(_base, "app_icon.ico")
            if os.path.exists(_ico):
                self.iconbitmap(_ico)
        except Exception:
            pass

        # State
        self.map_4: dict = {}
        self.map_6: dict = {}
        self.custom_dict_map: dict = {}
        self.custom_dict_path = tk.StringVar()
        self.custom_dict_info = tk.StringVar(value="—")
        self.dict_source_var = tk.StringVar(value="builtin")

        self.input_path = tk.StringVar()
        self.txt_to_b64_path = tk.StringVar()
        self.b64_to_txt_path = tk.StringVar()
        self.research_input_path = tk.StringVar()
        self.zip_research_path = tk.StringVar()
        self.keychain_path = tk.StringVar()
        self.jwt_path = tk.StringVar()
        self.entropy_path = tk.StringVar()
        self.birthday_path = tk.StringVar()

        self.pin_min_len_var = tk.StringVar(value=self.config_mgr.get("pin_min"))
        self.pin_max_len_var = tk.StringVar(value=self.config_mgr.get("pin_max"))
        self.pin_parts_var = tk.StringVar(value=self.config_mgr.get("pin_parts"))
        self.pin_gen_plain_var = tk.BooleanVar(value=self.config_mgr.get("pin_plain") == "1")
        self.pin_gen_b64_var = tk.BooleanVar(value=self.config_mgr.get("pin_b64") == "1")
        self.pin_random_order_var = tk.BooleanVar(value=self.config_mgr.get("pin_random") == "1")

        self.var_4 = tk.BooleanVar(value=True)
        self.var_6 = tk.BooleanVar(value=True)

        self.entropy_threshold_var = tk.StringVar(value=self.config_mgr.get("entropy_threshold"))
        self.entropy_block_var = tk.StringVar(value=self.config_mgr.get("entropy_block"))

        self.status_var = tk.StringVar(value=self.T["lbl_status_ready"])
        self.dark_var = tk.BooleanVar(value=self.dark_mode)
        self.lang_var = tk.StringVar(value=self.lang)

        # Birthday format vars
        self.bday_formats = {
            "DDMM": tk.BooleanVar(value=True),
            "MMDD": tk.BooleanVar(value=True),
            "DDMMYYYY": tk.BooleanVar(value=True),
            "MMDDYYYY": tk.BooleanVar(value=True),
            "YYYYMMDD": tk.BooleanVar(value=True),
            "DDMMYY": tk.BooleanVar(value=True),
            "MMDDYY": tk.BooleanVar(value=True),
            "YYMMDD": tk.BooleanVar(value=True),
            "YYYY": tk.BooleanVar(value=True),
        }
        self.bday_dob_var = tk.StringVar(value="1990-01-01")
        self.bday_b64_var = tk.BooleanVar(value=True)
        self.bday_plain_var = tk.BooleanVar(value=True)

        # keychain table data
        self._keychain_rows: list = []

        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()
        self._apply_theme()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------------------------------------------------------------------------
    def _(self, key: str) -> str:
        return self.T.get(key, key)

    def _on_close(self):
        self._save_config()
        self.destroy()

    def _save_config(self):
        self.config_mgr.set("language", self.lang_var.get())
        self.config_mgr.set("dark_mode", "1" if self.dark_var.get() else "0")
        self.config_mgr.set("pin_min", self.pin_min_len_var.get())
        self.config_mgr.set("pin_max", self.pin_max_len_var.get())
        self.config_mgr.set("pin_parts", self.pin_parts_var.get())
        self.config_mgr.set("pin_plain", "1" if self.pin_gen_plain_var.get() else "0")
        self.config_mgr.set("pin_b64", "1" if self.pin_gen_b64_var.get() else "0")
        self.config_mgr.set("pin_random", "1" if self.pin_random_order_var.get() else "0")
        self.config_mgr.set("entropy_threshold", self.entropy_threshold_var.get())
        self.config_mgr.set("entropy_block", self.entropy_block_var.get())
        self.config_mgr.save()

    # -------------------------------------------------------------------------
    # Toolbar
    # -------------------------------------------------------------------------
    def _build_toolbar(self):
        tb = tk.Frame(self, relief="flat", bd=1)
        tb.pack(fill="x", side="top")
        self._toolbar = tb

        tk.Label(tb, text=self._("lbl_language")).pack(side="left", padx=(8, 2))
        lang_combo = ttk.Combobox(tb, textvariable=self.lang_var,
                                  values=list(TRANSLATIONS.keys()), width=5, state="readonly")
        lang_combo.pack(side="left", padx=2)
        lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        tk.Checkbutton(tb, text=self._("lbl_dark_mode"), variable=self.dark_var,
                       command=self._on_theme_toggle).pack(side="left", padx=10)

        # Recent files menu
        self._recent_btn = tk.Menubutton(tb, text=self._("lbl_recent"),
                                         relief="raised")
        self._recent_btn.pack(side="left", padx=4)
        self._recent_menu = tk.Menu(self._recent_btn, tearoff=0)
        self._recent_btn["menu"] = self._recent_menu
        self._rebuild_recent_menu()

    def _rebuild_recent_menu(self):
        self._recent_menu.delete(0, "end")
        for key in ["parser", "research", "keychain", "jwt", "birthday", "entropy"]:
            items = self.config_mgr.get_recent(key)
            if items:
                self._recent_menu.add_cascade(
                    label=f"[{key}]",
                    menu=self._make_recent_submenu(key, items)
                )

    def _make_recent_submenu(self, key: str, items: list) -> tk.Menu:
        sub = tk.Menu(self._recent_menu, tearoff=0)
        var_map = {
            "parser": self.input_path,
            "research": self.research_input_path,
            "keychain": self.keychain_path,
            "jwt": self.jwt_path,
            "birthday": self.birthday_path,
            "entropy": self.entropy_path,
        }
        for item in items:
            sub.add_command(
                label=os.path.basename(item),
                command=lambda p=item, v=var_map.get(key): v.set(p) if v else None
            )
        return sub

    def _on_lang_change(self, _=None):
        new_lang = self.lang_var.get()
        if new_lang not in TRANSLATIONS:
            return
        self.lang = new_lang
        self.T = TRANSLATIONS[self.lang]
        # Save immediately so restart picks it up
        self.config_mgr.set("language", self.lang)
        self.config_mgr.save()
        # Rebuild notebook tab labels on the fly
        tab_keys = [
            "tab_parser", "tab_dictgen", "tab_converter", "tab_live",
            "tab_research", "tab_keychain", "tab_jwt", "tab_birthday", "tab_entropy"
        ]
        for i, key in enumerate(tab_keys):
            try:
                self.notebook.tab(i, text=self.T.get(key, key))
            except Exception:
                pass
        # Update toolbar label
        self.set_status(self.T["lbl_status_ready"])

    def _on_theme_toggle(self):
        self.dark_mode = self.dark_var.get()
        self.theme = THEMES["dark"] if self.dark_mode else THEMES["light"]
        self._apply_theme()

    def _apply_theme(self):
        th = self.theme
        self.configure(bg=th["bg"])
        if hasattr(self, "_toolbar"):
            self._toolbar.configure(bg=th["bg"])
        if hasattr(self, "_statusbar"):
            self._statusbar.configure(bg=th["status_bg"])
        # Style ttk
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=th["bg"])
        style.configure("TNotebook.Tab", background=th["btn_bg"], foreground=th["fg"])
        style.map("TNotebook.Tab", background=[("selected", th["frame_bg"])])
        style.configure("TFrame", background=th["bg"])
        style.configure("TLabelframe", background=th["bg"], foreground=th["fg"])
        style.configure("TLabelframe.Label", background=th["bg"], foreground=th["fg"])
        style.configure("TCheckbutton", background=th["bg"], foreground=th["fg"])
        style.configure("TRadiobutton", background=th["bg"], foreground=th["fg"])
        style.configure("TLabel", background=th["bg"], foreground=th["fg"])
        style.configure("Treeview", background=th["text_bg"], foreground=th["text_fg"],
                        fieldbackground=th["text_bg"])
        style.configure("Treeview.Heading", background=th["btn_bg"], foreground=th["fg"])
        style.configure("TProgressbar", troughcolor=th["bg"])

    # -------------------------------------------------------------------------
    # Notebook
    # -------------------------------------------------------------------------
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=4, pady=2)

        self.tab_frames = {}
        tab_keys = [
            "tab_parser", "tab_dictgen", "tab_converter", "tab_live",
            "tab_research", "tab_keychain", "tab_jwt", "tab_birthday", "tab_entropy"
        ]
        builders = [
            self._build_tab_parser,
            self._build_tab_dictgen,
            self._build_tab_converter,
            self._build_tab_live,
            self._build_tab_research,
            self._build_tab_keychain,
            self._build_tab_jwt,
            self._build_tab_birthday,
            self._build_tab_entropy,
        ]
        for key, builder in zip(tab_keys, builders):
            frame = ttk.Frame(self.notebook)
            self.tab_frames[key] = frame
            self.notebook.add(frame, text=self.T[key])
            builder(frame)

    # -------------------------------------------------------------------------
    # Status bar
    # -------------------------------------------------------------------------
    def _build_statusbar(self):
        sb = tk.Frame(self, relief="sunken", bd=1)
        sb.pack(fill="x", side="bottom")
        self._statusbar = sb

        self.progress = ttk.Progressbar(sb, mode="determinate", length=300)
        self.progress.pack(side="right", padx=6, pady=2)

        tk.Label(sb, textvariable=self.status_var, anchor="w").pack(
            side="left", fill="x", expand=True, padx=6)

    # =========================================================================
    # TAB 1 — Parser PIN
    # =========================================================================
    def _build_tab_parser(self, f):
        pad = {"padx": 6, "pady": 3}

        file_frame = ttk.LabelFrame(f, text=self._("lbl_file"))
        file_frame.pack(fill="x", **pad)
        self._make_file_row(file_frame, self.input_path,
                            self._browse_parser, "parser")

        opt_frame = ttk.LabelFrame(f, text=self._("lbl_options"))
        opt_frame.pack(fill="x", **pad)
        ttk.Checkbutton(opt_frame, text=self._("lbl_search_4"),
                        variable=self.var_4).pack(side="left", **pad)
        ttk.Checkbutton(opt_frame, text=self._("lbl_search_6"),
                        variable=self.var_6).pack(side="left", **pad)

        dict_frame = ttk.LabelFrame(f, text=self._("lbl_dictionary"))
        dict_frame.pack(fill="x", **pad)
        ttk.Radiobutton(dict_frame, text=self._("lbl_dict_builtin"),
                        variable=self.dict_source_var, value="builtin").pack(side="left", **pad)
        ttk.Radiobutton(dict_frame, text=self._("lbl_dict_file"),
                        variable=self.dict_source_var, value="file").pack(side="left", **pad)

        df2 = ttk.Frame(f)
        df2.pack(fill="x", **pad)
        tk.Button(df2, text=self._("btn_load_dict"),
                  command=self.load_custom_dict).pack(side="left", **pad)
        ttk.Label(df2, textvariable=self.custom_dict_info).pack(
            side="left", fill="x", expand=True, **pad)

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        self.btn_run_pin = tk.Button(btn_row, text=self._("btn_run"),
                                     bg=self.theme["run_bg"], fg=self.theme["run_fg"],
                                     font=("Arial", 10, "bold"),
                                     command=self.run_analysis)
        self.btn_run_pin.pack(side="left", **pad)
        tk.Button(btn_row, text=self._("btn_clear"),
                  command=self.clear_parser_log).pack(side="left", **pad)

        self.progress_parser = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_parser.pack(fill="x", **pad)

        self.txt_log = scrolledtext.ScrolledText(f, font=("Consolas", 9), height=16)
        self.txt_log.pack(fill="both", expand=True, **pad)

    def _browse_parser(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt;*.log;*.plist;*.xml"), ("All", "*.*")])
        if path:
            self.input_path.set(path)
            self.config_mgr.add_recent("parser", path)
            self._rebuild_recent_menu()

    # =========================================================================
    # TAB 2 — Dict Generator
    # =========================================================================
    def _build_tab_dictgen(self, f):
        pad = {"padx": 6, "pady": 3}

        len_frame = ttk.LabelFrame(f, text=self._("lbl_length"))
        len_frame.pack(fill="x", **pad)
        ttk.Label(len_frame, text=self._("lbl_pin_from")).pack(side="left", **pad)
        ttk.Spinbox(len_frame, from_=4, to=10, width=4,
                    textvariable=self.pin_min_len_var).pack(side="left", **pad)
        ttk.Label(len_frame, text=self._("lbl_pin_to")).pack(side="left", **pad)
        ttk.Spinbox(len_frame, from_=4, to=10, width=4,
                    textvariable=self.pin_max_len_var).pack(side="left", **pad)

        fmt_frame = ttk.LabelFrame(f, text=self._("lbl_format"))
        fmt_frame.pack(fill="x", **pad)
        ttk.Checkbutton(fmt_frame, text=self._("lbl_format_plain"),
                        variable=self.pin_gen_plain_var).pack(side="left", **pad)
        ttk.Checkbutton(fmt_frame, text=self._("lbl_format_b64"),
                        variable=self.pin_gen_b64_var).pack(side="left", **pad)

        rnd_frame = ttk.Frame(f)
        rnd_frame.pack(fill="x", **pad)
        ttk.Checkbutton(rnd_frame, text=self._("lbl_random_order"),
                        variable=self.pin_random_order_var).pack(side="left", **pad)

        split_frame = ttk.Frame(f)
        split_frame.pack(fill="x", **pad)
        ttk.Label(split_frame, text=self._("lbl_parts")).pack(side="left", **pad)
        ttk.Spinbox(split_frame, from_=1, to=20, width=4,
                    textvariable=self.pin_parts_var).pack(side="left", **pad)

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        self.btn_run_dict_gen = tk.Button(btn_row, text=self._("btn_run"),
                                          bg=self.theme["run_bg"], fg=self.theme["run_fg"],
                                          font=("Arial", 10, "bold"),
                                          command=self.run_dict_generation)
        self.btn_run_dict_gen.pack(side="left", **pad)

        self.progress_dictgen = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_dictgen.pack(fill="x", **pad)

        self.txt_dictgen_log = scrolledtext.ScrolledText(f, height=12,
                                                         font=("Consolas", 9))
        self.txt_dictgen_log.pack(fill="both", expand=True, **pad)

    # =========================================================================
    # TAB 3 — Converter
    # =========================================================================
    def _build_tab_converter(self, f):
        pad = {"padx": 6, "pady": 4}

        t2b = ttk.LabelFrame(f, text=self._("lbl_t2b_group"))
        t2b.pack(fill="x", **pad)
        self._make_file_row(t2b, self.txt_to_b64_path, self._browse_t2b, None)
        tk.Button(t2b, text=self._("btn_t2b_run"),
                  bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
                  command=self.run_txt_to_b64).pack(anchor="w", padx=6, pady=4)

        b2t = ttk.LabelFrame(f, text=self._("lbl_b2t_group"))
        b2t.pack(fill="x", **pad)
        self._make_file_row(b2t, self.b64_to_txt_path, self._browse_b2t, None)
        tk.Button(b2t, text=self._("btn_b2t_run"),
                  bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
                  command=self.run_b64_to_txt).pack(anchor="w", padx=6, pady=4)

        self.progress_conv = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_conv.pack(fill="x", **pad)

        self.txt_conv_log = scrolledtext.ScrolledText(f, height=10, font=("Consolas", 9))
        self.txt_conv_log.pack(fill="both", expand=True, **pad)

    def _browse_t2b(self):
        p = filedialog.askopenfilename(filetypes=[("txt", "*.txt;*.log"), ("All", "*.*")])
        if p:
            self.txt_to_b64_path.set(p)

    def _browse_b2t(self):
        p = filedialog.askopenfilename(filetypes=[("txt", "*.txt;*.log"), ("All", "*.*")])
        if p:
            self.b64_to_txt_path.set(p)

    # =========================================================================
    # TAB 4 — Live encoder/decoder
    # =========================================================================
    def _build_tab_live(self, f):
        pad = {"padx": 6, "pady": 3}
        info = self._("lbl_live_info")
        ttk.Label(f, text=info).pack(fill="x", **pad)

        top_frame = ttk.LabelFrame(f, text=self._("lbl_input"))
        top_frame.pack(fill="both", expand=True, **pad)
        self.txt_live_in = scrolledtext.ScrolledText(top_frame, height=7,
                                                     font=("Consolas", 9))
        self.txt_live_in.pack(fill="both", expand=True, padx=4, pady=4)

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        for lbl, cmd in [
            (self._("btn_live_encode"), self.live_encode),
            (self._("btn_live_decode"), self.live_decode),
            (self._("btn_live_swap"), self.live_swap),
            (self._("btn_clear"), self.live_clear),
        ]:
            tk.Button(btn_row, text=lbl,
                      bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
                      command=cmd).pack(side="left", padx=4)

        bot_frame = ttk.LabelFrame(f, text=self._("lbl_output"))
        bot_frame.pack(fill="both", expand=True, **pad)
        self.txt_live_out = scrolledtext.ScrolledText(bot_frame, height=7,
                                                      font=("Consolas", 9))
        self.txt_live_out.pack(fill="both", expand=True, padx=4, pady=4)

    # =========================================================================
    # TAB 5 — Research analysis
    # =========================================================================
    def _build_tab_research(self, f):
        pad = {"padx": 6, "pady": 4}

        single = ttk.LabelFrame(f, text=self._("lbl_single_file"))
        single.pack(fill="x", **pad)
        self._make_file_row(single, self.research_input_path,
                            self._browse_research, "research")
        self.btn_run_research = tk.Button(
            single, text=self._("btn_run"),
            bg=self.theme["run_bg"], fg=self.theme["run_fg"],
            font=("Arial", 10, "bold"),
            command=self.run_research_analysis)
        self.btn_run_research.pack(anchor="w", padx=6, pady=4)

        zip_grp = ttk.LabelFrame(f, text=self._("lbl_zip_group"))
        zip_grp.pack(fill="x", **pad)
        self._make_file_row(zip_grp, self.zip_research_path,
                            self._browse_zip_research, None)
        self.btn_run_zip = tk.Button(
            zip_grp, text=self._("btn_run_zip"),
            bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
            font=("Arial", 10, "bold"),
            command=self.run_zip_research_analysis)
        self.btn_run_zip.pack(anchor="w", padx=6, pady=4)

        self.progress_research = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_research.pack(fill="x", **pad)

        self.txt_research_log = scrolledtext.ScrolledText(f, height=14,
                                                          font=("Consolas", 9))
        self.txt_research_log.pack(fill="both", expand=True, **pad)

    def _browse_research(self):
        p = filedialog.askopenfilename(filetypes=[("All", "*.*")])
        if p:
            self.research_input_path.set(p)
            self.config_mgr.add_recent("research", p)
            self._rebuild_recent_menu()

    def _browse_zip_research(self):
        p = filedialog.askopenfilename(filetypes=[("ZIP", "*.zip"), ("All", "*.*")])
        if p:
            self.zip_research_path.set(p)

    # =========================================================================
    # TAB 6 — Keychain Decoder
    # =========================================================================
    def _build_tab_keychain(self, f):
        pad = {"padx": 6, "pady": 4}

        info = self._("lbl_kc_info")
        ttk.Label(f, text=info, wraplength=900).pack(fill="x", **pad)

        file_frame = ttk.LabelFrame(f, text=self._("lbl_keychain_file"))
        file_frame.pack(fill="x", **pad)
        self._make_file_row(file_frame, self.keychain_path,
                            self._browse_keychain, "keychain")

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        tk.Button(btn_row, text=self._("btn_run") + " (Parse)",
                  bg=self.theme["run_bg"], fg=self.theme["run_fg"],
                  font=("Arial", 10, "bold"),
                  command=self.run_keychain_parse).pack(side="left", padx=4)
        tk.Button(btn_row, text=self._("btn_export_csv"),
                  bg=self.theme["blue_bg"], fg=self.theme["blue_fg"],
                  command=self.export_keychain_csv).pack(side="left", padx=4)

        # Filter
        flt_row = ttk.Frame(f)
        flt_row.pack(fill="x", **pad)
        ttk.Label(flt_row, text=self._("lbl_filter")).pack(side="left")
        self.kc_filter_var = tk.StringVar()
        self.kc_filter_var.trace_add("write", self._filter_keychain)
        ttk.Entry(flt_row, textvariable=self.kc_filter_var, width=40).pack(
            side="left", padx=4)
        ttk.Label(flt_row, text=self._("lbl_class")).pack(side="left", padx=(10, 2))
        self.kc_class_var = tk.StringVar(value="all")
        ttk.Combobox(flt_row, textvariable=self.kc_class_var,
                     values=["all", "genp", "inet", "keys", "cert"],
                     width=8, state="readonly").pack(side="left")
        self.kc_class_var.trace_add("write", self._filter_keychain)

        self.progress_kc = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_kc.pack(fill="x", **pad)

        # Treeview
        tree_frame = ttk.Frame(f)
        tree_frame.pack(fill="both", expand=True, **pad)

        cols = ("class", "agrp", "svce", "acct", "v_data_hex",
                "v_data_b64", "v_data_text", "pdmn", "cdat", "mdat")
        self.kc_tree = ttk.Treeview(tree_frame, columns=cols,
                                    show="headings", height=16)
        col_widths = {
            "class": 60, "agrp": 160, "svce": 160, "acct": 120,
            "v_data_hex": 120, "v_data_b64": 120, "v_data_text": 160,
            "pdmn": 60, "cdat": 100, "mdat": 100,
        }
        for col in cols:
            self.kc_tree.heading(col, text=col)
            self.kc_tree.column(col, width=col_widths.get(col, 100), minwidth=40)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.kc_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                            command=self.kc_tree.xview)
        self.kc_tree.configure(yscrollcommand=vsb.set,
                               xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.kc_tree.pack(fill="both", expand=True)

    def _browse_keychain(self):
        p = filedialog.askopenfilename(
            filetypes=[("plist", "*.plist"), ("All", "*.*")])
        if p:
            self.keychain_path.set(p)
            self.config_mgr.add_recent("keychain", p)
            self._rebuild_recent_menu()

    # =========================================================================
    # TAB 7 — JWT Analyzer
    # =========================================================================
    def _build_tab_jwt(self, f):
        pad = {"padx": 6, "pady": 4}

        info = self._("lbl_jwt_info")
        ttk.Label(f, text=info, wraplength=900).pack(fill="x", **pad)

        file_frame = ttk.LabelFrame(f, text=self._("lbl_jwt_file"))
        file_frame.pack(fill="x", **pad)
        self._make_file_row(file_frame, self.jwt_path,
                            self._browse_jwt, "jwt")

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        self.btn_run_jwt = tk.Button(btn_row, text=self._("btn_run"),
                                     bg=self.theme["run_bg"], fg=self.theme["run_fg"],
                                     font=("Arial", 10, "bold"),
                                     command=self.run_jwt_analysis)
        self.btn_run_jwt.pack(side="left", padx=4)
        tk.Button(btn_row, text=self._("btn_clear"),
                  command=lambda: self._clear_widget(self.txt_jwt_log)).pack(
            side="left", padx=4)

        self.progress_jwt = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_jwt.pack(fill="x", **pad)

        self.txt_jwt_log = scrolledtext.ScrolledText(f, height=22,
                                                     font=("Consolas", 9))
        self.txt_jwt_log.pack(fill="both", expand=True, **pad)

    def _browse_jwt(self):
        p = filedialog.askopenfilename(filetypes=[("All", "*.*")])
        if p:
            self.jwt_path.set(p)
            self.config_mgr.add_recent("jwt", p)
            self._rebuild_recent_menu()

    # =========================================================================
    # TAB 8 — Birthday Dictionary
    # =========================================================================
    def _build_tab_birthday(self, f):
        pad = {"padx": 6, "pady": 3}

        info = self._("lbl_bday_info")
        ttk.Label(f, text=info, wraplength=900).pack(fill="x", **pad)

        dob_frame = ttk.LabelFrame(f, text=self._("lbl_birthday_dob"))
        dob_frame.pack(fill="x", **pad)
        ttk.Entry(dob_frame, textvariable=self.bday_dob_var, width=16).pack(
            side="left", **pad)
        ttk.Label(dob_frame, text="YYYY-MM-DD").pack(side="left")

        fmt_outer = ttk.LabelFrame(f, text=self._("lbl_birthday_formats"))
        fmt_outer.pack(fill="x", **pad)
        fmt_grid = ttk.Frame(fmt_outer)
        fmt_grid.pack(fill="x", **pad)
        row_n, col_n = 0, 0
        for fmt in self.bday_formats:
            ttk.Checkbutton(fmt_grid, text=fmt,
                            variable=self.bday_formats[fmt]).grid(
                row=row_n, column=col_n, sticky="w", padx=6)
            col_n += 1
            if col_n > 4:
                col_n = 0
                row_n += 1

        out_fmt = ttk.Frame(f)
        out_fmt.pack(fill="x", **pad)
        ttk.Checkbutton(out_fmt, text=self._("lbl_format_plain"),
                        variable=self.bday_plain_var).pack(side="left", **pad)
        ttk.Checkbutton(out_fmt, text=self._("lbl_format_b64"),
                        variable=self.bday_b64_var).pack(side="left", **pad)

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        self.btn_run_bday = tk.Button(btn_row, text=self._("btn_run"),
                                      bg=self.theme["run_bg"], fg=self.theme["run_fg"],
                                      font=("Arial", 10, "bold"),
                                      command=self.run_birthday_gen)
        self.btn_run_bday.pack(side="left", padx=4)
        tk.Button(btn_row, text=self._("btn_clear"),
                  command=lambda: self._clear_widget(self.txt_bday_log)).pack(
            side="left", padx=4)

        self.progress_bday = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_bday.pack(fill="x", **pad)

        self.txt_bday_log = scrolledtext.ScrolledText(f, height=16,
                                                      font=("Consolas", 9))
        self.txt_bday_log.pack(fill="both", expand=True, **pad)

    # =========================================================================
    # TAB 9 — Entropy Analysis
    # =========================================================================
    def _build_tab_entropy(self, f):
        pad = {"padx": 6, "pady": 4}

        info = self._("lbl_entropy_info")
        ttk.Label(f, text=info, wraplength=900).pack(fill="x", **pad)

        file_frame = ttk.LabelFrame(f, text=self._("lbl_file"))
        file_frame.pack(fill="x", **pad)
        self._make_file_row(file_frame, self.entropy_path,
                            self._browse_entropy, "entropy")

        params = ttk.Frame(f)
        params.pack(fill="x", **pad)
        ttk.Label(params, text=self._("lbl_entropy_threshold")).pack(
            side="left", **pad)
        ttk.Entry(params, textvariable=self.entropy_threshold_var,
                  width=8).pack(side="left", **pad)
        ttk.Label(params, text=self._("lbl_block_size")).pack(
            side="left", padx=(12, 2))
        ttk.Entry(params, textvariable=self.entropy_block_var,
                  width=8).pack(side="left", **pad)

        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", **pad)
        self.btn_run_entropy = tk.Button(btn_row, text=self._("btn_run"),
                                         bg=self.theme["run_bg"],
                                         fg=self.theme["run_fg"],
                                         font=("Arial", 10, "bold"),
                                         command=self.run_entropy_analysis)
        self.btn_run_entropy.pack(side="left", padx=4)
        tk.Button(btn_row, text=self._("btn_clear"),
                  command=lambda: self._clear_widget(self.txt_entropy_log)).pack(
            side="left", padx=4)

        self.progress_entropy = ttk.Progressbar(f, mode="determinate", length=600)
        self.progress_entropy.pack(fill="x", **pad)

        self.txt_entropy_log = scrolledtext.ScrolledText(f, height=20,
                                                         font=("Consolas", 9))
        self.txt_entropy_log.pack(fill="both", expand=True, **pad)

    def _browse_entropy(self):
        p = filedialog.askopenfilename(filetypes=[("All", "*.*")])
        if p:
            self.entropy_path.set(p)
            self.config_mgr.add_recent("entropy", p)
            self._rebuild_recent_menu()

    # =========================================================================
    # COMMON WIDGET HELPER
    # =========================================================================
    def _make_file_row(self, parent, var: tk.StringVar,
                       browse_cmd, recent_key: str | None):
        row = ttk.Frame(parent)
        row.pack(fill="x", padx=4, pady=2)
        tk.Button(row, text=self._("btn_browse"),
                  command=browse_cmd).pack(side="left", padx=4)
        ttk.Label(row, textvariable=var, anchor="w").pack(
            side="left", fill="x", expand=True, padx=4)

    def _clear_widget(self, widget):
        widget.delete("1.0", "end")

    def log_to(self, widget, msg: str):
        widget.insert("end", msg + "\n")
        widget.see("end")
        self.update_idletasks()

    def set_status(self, msg: str):
        self.status_var.set(msg)
        self.update_idletasks()

    def set_progress(self, bar, value: int, maximum: int = 100):
        bar.config(maximum=maximum, value=value)
        self.update_idletasks()

    # =========================================================================
    # PARSER PIN LOGIC
    # =========================================================================
    def load_custom_dict(self):
        path = filedialog.askopenfilename(
            filetypes=[("txt", "*.txt;*.dic;*.lst"), ("All", "*.*")])
        if not path:
            return
        new_map = {}
        total = parsed = errors = 0
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    total += 1
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for sep in [" -> ", ":", " "]:
                        if sep in line:
                            parts = line.split(sep, 1)
                            key = parts[0].strip()
                            val = parts[1].strip() if len(parts) > 1 else ""
                            try:
                                base64.b64decode(key + "==")
                                new_map[key] = val
                                new_map[key.rstrip("=")] = val
                                parsed += 1
                            except Exception:
                                errors += 1
                            break
                    else:
                        try:
                            base64.b64decode(line + "==")
                            new_map[line] = line
                            parsed += 1
                        except Exception:
                            errors += 1
            self.custom_dict_map = new_map
            self.custom_dict_path.set(path)
            self.custom_dict_info.set(
                f"{os.path.basename(path)} | entries: {len(new_map)} | "
                f"ok: {parsed} | err: {errors}")
            self.log_to(self.txt_log,
                        f"[Dict] Loaded: {len(new_map)} entries from {path}")
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))

    def clear_parser_log(self):
        self.txt_log.delete("1.0", "end")

    def run_analysis(self):
        path = self.input_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        use_4, use_6 = self.var_4.get(), self.var_6.get()
        dict_mode = self.dict_source_var.get()

        if dict_mode == "builtin":
            if not use_4 and not use_6:
                messagebox.showwarning("", self._("msg_no_range"))
                return
            if use_4 and not self.map_4:
                self.set_status("Building 4-digit map...")
                self.map_4 = build_pin_map(4)
            if use_6 and not self.map_6:
                self.set_status("Building 6-digit map...")
                self.map_6 = build_pin_map(6)
        elif dict_mode == "file":
            if not self.custom_dict_map:
                messagebox.showwarning("", self._("msg_no_dict_file"))
                return

        self.btn_run_pin.config(state="disabled")
        self.set_status(self._("status_analyzing_pin"))
        self.set_progress(self.progress_parser, 0)
        self.log_to(self.txt_log, "\n--- ANALIZA PIN START ---")

        try:
            active_map = {}
            if dict_mode == "builtin":
                if use_4:
                    active_map.update(self.map_4)
                if use_6:
                    active_map.update(self.map_6)
            else:
                active_map = self.custom_dict_map

            self._analyze_pin(path, active_map)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_pin.config(state="normal")
            self.log_to(self.txt_log, "--- ANALIZA PIN KONIEC ---")
            self.set_status(self._("lbl_status_ready"))

    def _analyze_pin(self, path: str, active_map: dict):
        candidate_re = re.compile(r"[A-Za-z0-9+/=]{4,64}")
        # Also handle Base64URL
        candidate_url_re = re.compile(r"[A-Za-z0-9\-_]{4,64}")

        out_path = os.path.splitext(path)[0] + "_base64_pin_hits.txt"
        file_hashes = compute_file_hashes(path)
        file_size = file_hashes["size"]
        total_hits = 0
        unique_hits = {}
        total_tokens = 0
        processed = 0

        self.set_progress(self.progress_parser, 0, file_size or 1)

        with open(out_path, "w", encoding="utf-8") as out_f:
            out_f.write(f"# Base64 Forensic Toolkit v{VERSION} — PIN Analysis\n")
            out_f.write(f"# File: {path}\n")
            out_f.write(f"# MD5: {file_hashes['md5']}\n")
            out_f.write(f"# SHA-256: {file_hashes['sha256']}\n")
            out_f.write(f"# Date: {datetime.now().isoformat(timespec='seconds')}\n\n")

            with open(path, encoding="utf-8", errors="replace") as in_f:
                for lineno, line in enumerate(in_f, 1):
                    processed += len(line.encode("utf-8"))
                    if lineno % 500 == 0:
                        self.set_progress(self.progress_parser, processed, file_size or 1)

                    candidates = set(candidate_re.findall(line))
                    # Normalize Base64URL
                    for m in candidate_url_re.findall(line):
                        norm = m.replace("-", "+").replace("_", "/")
                        candidates.add(norm)

                    for cand in candidates:
                        total_tokens += 1
                        val = active_map.get(cand)
                        if val is not None:
                            total_hits += 1
                            unique_hits[cand] = val
                            msg = f"[HIT] L{lineno}: {cand} = {val}"
                            self.log_to(self.txt_log, msg)
                            out_f.write(f"{cand} -> {val}\n")

            out_f.write(f"\n# Hits: {total_hits} | Unique: {len(unique_hits)} | "
                        f"Tokens checked: {total_tokens}\n")

        self.set_progress(self.progress_parser, file_size or 1, file_size or 1)
        self.log_to(self.txt_log,
                    f"Hits: {total_hits} | Unique: {len(unique_hits)} | "
                    f"Tokens: {total_tokens}")
        self.log_to(self.txt_log, self._("report_saved").format(path=out_path))
        messagebox.showinfo("", self._("analysis_done"))

    # =========================================================================
    # DICT GENERATOR LOGIC
    # =========================================================================
    def run_dict_generation(self):
        try:
            min_len = int(self.pin_min_len_var.get())
            max_len = int(self.pin_max_len_var.get())
            parts = int(self.pin_parts_var.get())
        except ValueError:
            messagebox.showerror(self._("msg_error"), "Invalid numeric values.")
            return

        if not (4 <= min_len <= 10 and 4 <= max_len <= 10 and min_len <= max_len):
            messagebox.showerror(self._("msg_error"), "PIN length range invalid.")
            return
        if not (1 <= parts <= 20):
            messagebox.showerror(self._("msg_error"), "Parts must be 1–20.")
            return

        gen_plain = self.pin_gen_plain_var.get()
        gen_b64 = self.pin_gen_b64_var.get()
        random_order = self.pin_random_order_var.get()

        if not gen_plain and not gen_b64:
            messagebox.showerror(self._("msg_error"), self._("msg_no_format"))
            return

        total_pins = sum(10 ** l for l in range(min_len, max_len + 1))
        avg_len = sum(l + 1 for l in range(min_len, max_len + 1)) / (max_len - min_len + 1)
        approx_mb = total_pins * avg_len / 1024 / 1024

        if not messagebox.askyesno("Confirm", self._("msg_confirm_gen").format(
                count=f"{total_pins:,}", parts=parts, mb=approx_mb)):
            return

        if random_order and total_pins > 5_000_000:
            messagebox.showerror(self._("msg_error"), self._("msg_random_too_big"))
            return

        out_dir = filedialog.askdirectory()
        if not out_dir:
            return

        self.btn_run_dict_gen.config(state="disabled")
        self.set_status("Generating PIN dictionary...")
        self.set_progress(self.progress_dictgen, 0, total_pins)

        try:
            self._do_generate_pins(min_len, max_len, parts, gen_plain, gen_b64,
                                   random_order, out_dir, total_pins)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_dict_gen.config(state="normal")
            self.set_status(self._("lbl_status_ready"))

    def _do_generate_pins(self, min_len, max_len, parts, gen_plain, gen_b64,
                          random_order, out_dir, total_pins):
        def idx_to_pin(idx):
            offset = 0
            for l in range(min_len, max_len + 1):
                count = 10 ** l
                if idx < offset + count:
                    return str(idx - offset).zfill(l)
                offset += count
            return ""

        indices = list(range(total_pins))
        if random_order:
            random.shuffle(indices)

        chunk = (total_pins + parts - 1) // parts
        label = f"{min_len}-{max_len}"
        all_files = []

        for part_i in range(parts):
            seg = indices[part_i * chunk: (part_i + 1) * chunk]
            if not seg:
                continue
            suffix = f"_p{part_i + 1}of{parts}" if parts > 1 else ""

            if gen_plain:
                fname = os.path.join(out_dir, f"pin_list_{label}{suffix}.txt")
                with open(fname, "w", encoding="utf-8") as fout:
                    for i, idx in enumerate(seg):
                        fout.write(idx_to_pin(idx) + "\n")
                        if i % 100000 == 0:
                            self.set_progress(self.progress_dictgen,
                                              part_i * chunk + i, total_pins)
                all_files.append(fname)

            if gen_b64:
                fname = os.path.join(out_dir, f"pin_b64_{label}{suffix}.txt")
                with open(fname, "w", encoding="utf-8") as fout:
                    for i, idx in enumerate(seg):
                        pin = idx_to_pin(idx)
                        b64 = base64.b64encode(pin.encode()).decode()
                        fout.write(f"{b64} -> {pin}\n")
                        if i % 100000 == 0:
                            self.set_progress(self.progress_dictgen,
                                              part_i * chunk + i, total_pins)
                all_files.append(fname)

        self.set_progress(self.progress_dictgen, total_pins, total_pins)
        self.log_to(self.txt_dictgen_log,
                    f"Done. {total_pins:,} PINs → {len(all_files)} files in {out_dir}")
        messagebox.showinfo("", f"{self._('msg_done')}\nFiles: {len(all_files)}\nDir: {out_dir}")

    # =========================================================================
    # CONVERTER LOGIC
    # =========================================================================
    def run_txt_to_b64(self):
        in_path = self.txt_to_b64_path.get().strip()
        if not in_path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        out_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=os.path.splitext(os.path.basename(in_path))[0] + "_base64.txt")
        if not out_path:
            return
        self.set_progress(self.progress_conv, 0)
        total = err = 0
        with open(in_path, encoding="utf-8", errors="replace") as fin, \
                open(out_path, "w", encoding="utf-8") as fout:
            lines = fin.readlines()
            for i, line in enumerate(lines):
                val = line.rstrip("\n\r")
                try:
                    fout.write(base64.b64encode(val.encode()).decode() + "\n")
                except Exception:
                    fout.write("#ERROR\n")
                    err += 1
                total += 1
                if i % 1000 == 0:
                    self.set_progress(self.progress_conv, i, len(lines))
        self.set_progress(self.progress_conv, len(lines), len(lines))
        self.log_to(self.txt_conv_log,
                    self._("log_t2b").format(total=total, err=err, path=out_path))
        messagebox.showinfo("", f"{self._('msg_done')} {out_path}")

    def run_b64_to_txt(self):
        in_path = self.b64_to_txt_path.get().strip()
        if not in_path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        out_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=os.path.splitext(os.path.basename(in_path))[0] + "_decoded.txt")
        if not out_path:
            return
        self.set_progress(self.progress_conv, 0)
        total = err = 0
        with open(in_path, encoding="utf-8", errors="replace") as fin, \
                open(out_path, "w", encoding="utf-8") as fout:
            lines = fin.readlines()
            for i, line in enumerate(lines):
                val = line.strip()
                try:
                    fout.write(base64.b64decode(val + "==").decode(
                        "utf-8", errors="replace") + "\n")
                except Exception:
                    fout.write("#ERROR\n")
                    err += 1
                total += 1
                if i % 1000 == 0:
                    self.set_progress(self.progress_conv, i, len(lines))
        self.set_progress(self.progress_conv, len(lines), len(lines))
        self.log_to(self.txt_conv_log,
                    self._("log_b2t").format(total=total, err=err, path=out_path))
        messagebox.showinfo("", f"{self._('msg_done')} {out_path}")

    # =========================================================================
    # LIVE ENCODER/DECODER LOGIC
    # =========================================================================
    def live_encode(self):
        content = self.txt_live_in.get("1.0", "end").rstrip("\n")
        try:
            result = base64.b64encode(content.encode("utf-8")).decode()
        except Exception as e:
            result = f"#ERROR: {e}"
        self.txt_live_out.delete("1.0", "end")
        self.txt_live_out.insert("1.0", result)

    def live_decode(self):
        content = self.txt_live_in.get("1.0", "end").strip()
        try:
            result = base64.b64decode(content + "==").decode("utf-8", errors="replace")
        except Exception as e:
            result = f"#ERROR: {e}"
        self.txt_live_out.delete("1.0", "end")
        self.txt_live_out.insert("1.0", result)

    def live_swap(self):
        content = self.txt_live_out.get("1.0", "end")
        self.txt_live_in.delete("1.0", "end")
        self.txt_live_in.insert("1.0", content.rstrip("\n"))
        self.txt_live_out.delete("1.0", "end")

    def live_clear(self):
        self.txt_live_in.delete("1.0", "end")
        self.txt_live_out.delete("1.0", "end")

    # =========================================================================
    # RESEARCH ANALYSIS LOGIC
    # =========================================================================
    def run_research_analysis(self):
        path = self.research_input_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        self.btn_run_research.config(state="disabled")
        self.set_status(self._("status_analyzing"))
        self.set_progress(self.progress_research, 0)
        try:
            self._analyze_research(path, self.txt_research_log, self.progress_research)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_research.config(state="normal")
            self.set_status(self._("lbl_status_ready"))
        messagebox.showinfo("", self._("analysis_done"))

    def _analyze_research(self, path: str, log_widget, progress_bar):
        candidate_re = re.compile(r"[A-Za-z0-9+/=]{4,}")
        jwt_re = re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
        out_path = os.path.splitext(path)[0] + "_b64_research.txt"
        file_hashes = compute_file_hashes(path)
        file_size = file_hashes["size"]
        unique: dict = {}
        class_stats: dict = {}
        total = 0
        processed = 0

        self.set_progress(progress_bar, 0, file_size or 1)

        with open(out_path, "w", encoding="utf-8") as out_f:
            out_f.write(f"# Base64 Research Report — {path}\n")
            out_f.write(f"# MD5: {file_hashes['md5']}\n"
                        f"# SHA-256: {file_hashes['sha256']}\n\n")

            with open(path, encoding="utf-8", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    processed += len(line.encode())
                    if lineno % 2000 == 0:
                        self.set_progress(progress_bar, processed, file_size or 1)

                    for cand in candidate_re.findall(line):
                        total += 1
                        if cand in unique:
                            continue
                        try:
                            dec = base64.b64decode(cand + "==")
                        except Exception:
                            continue
                        cls = classify_decoded(dec)
                        unique[cand] = cls
                        class_stats[cls] = class_stats.get(cls, 0) + 1

            out_f.write(f"Total candidates: {total}\nUnique: {len(unique)}\n")
            out_f.write("Class stats:\n")
            for k, v in sorted(class_stats.items()):
                out_f.write(f"  {k}: {v}\n")

        self.set_progress(progress_bar, file_size or 1, file_size or 1)
        self.log_to(log_widget,
                    f"[Research] Total: {total} | Unique: {len(unique)} | "
                    f"Classes: {class_stats}")
        self.log_to(log_widget, self._("report_saved").format(path=out_path))

    def run_zip_research_analysis(self):
        path = self.zip_research_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        self.btn_run_zip.config(state="disabled")
        self.set_status(self._("status_analyzing_zip"))
        self.set_progress(self.progress_research, 0)
        try:
            self._analyze_zip(path)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_zip.config(state="normal")
            self.set_status(self._("lbl_status_ready"))
        messagebox.showinfo("", self._("analysis_done"))

    def _analyze_zip(self, zip_path: str):
        candidate_re = re.compile(r"[A-Za-z0-9+/=]{4,}")
        out_path = os.path.splitext(zip_path)[0] + "_zip_b64_research.txt"
        file_hashes = compute_file_hashes(zip_path)
        unique: dict = {}
        total_cands = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            self.set_progress(self.progress_research, 0, len(infos))

            with open(out_path, "w", encoding="utf-8") as out_f:
                out_f.write(f"# ZIP Base64 Research — {zip_path}\n"
                            f"# MD5: {file_hashes['md5']}\n"
                            f"# Files: {len(infos)}\n\n")

                for idx, info in enumerate(infos):
                    self.set_progress(self.progress_research, idx, len(infos))
                    try:
                        data = zf.read(info.filename).decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    for line in data.splitlines():
                        for cand in candidate_re.findall(line):
                            total_cands += 1
                            key = (cand, info.filename)
                            if key in unique:
                                continue
                            try:
                                dec = base64.b64decode(cand + "==")
                            except Exception:
                                continue
                            cls = classify_decoded(dec)
                            unique[key] = cls
                            out_f.write(f"{info.filename}: {cand} [{cls}]\n")

                out_f.write(f"\n# Total: {total_cands} | Unique: {len(unique)}\n")

        self.set_progress(self.progress_research, len(infos), len(infos))
        self.log_to(self.txt_research_log,
                    f"[ZIP] Total: {total_cands} | Unique: {len(unique)}")
        self.log_to(self.txt_research_log,
                    self._("report_saved").format(path=out_path))

    # =========================================================================
    # KEYCHAIN DECODER LOGIC
    # =========================================================================
    def run_keychain_parse(self):
        path = self.keychain_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        self.set_status("Parsing keychain.plist...")
        self.set_progress(self.progress_kc, 0)
        self.kc_tree.delete(*self.kc_tree.get_children())
        self._keychain_rows = []

        try:
            with open(path, "rb") as f:
                data = plistlib.load(f)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), f"Cannot read plist: {e}")
            return

        rows = []
        classes = ["genp", "inet", "keys", "cert"]
        total = sum(len(data.get(c, [])) for c in classes)
        self.set_progress(self.progress_kc, 0, total or 1)
        count = 0

        for cls in classes:
            for item in data.get(cls, []):
                count += 1
                if count % 50 == 0:
                    self.set_progress(self.progress_kc, count, total)

                def decode_field(v):
                    if isinstance(v, bytes):
                        hex_str = v.hex()
                        b64_str = base64.b64encode(v).decode()
                        try:
                            txt_str = v.decode("utf-8", errors="replace")
                        except Exception:
                            txt_str = ""
                        return hex_str, b64_str, txt_str
                    return "", "", str(v) if v is not None else ""

                v_data = item.get("v_Data") or item.get("v_data") or b""
                hex_v, b64_v, txt_v = decode_field(v_data)

                def str_field(key):
                    val = item.get(key, "")
                    if isinstance(val, bytes):
                        return val.decode("utf-8", errors="replace")
                    return str(val) if val is not None else ""

                row = {
                    "class": cls,
                    "agrp": str_field("agrp"),
                    "svce": str_field("svce"),
                    "acct": str_field("acct"),
                    "v_data_hex": hex_v[:40] + ("…" if len(hex_v) > 40 else ""),
                    "v_data_b64": b64_v[:40] + ("…" if len(b64_v) > 40 else ""),
                    "v_data_text": txt_v[:60].replace("\n", "\\n"),
                    "pdmn": str_field("pdmn"),
                    "cdat": str(item.get("cdat", "")),
                    "mdat": str(item.get("mdat", "")),
                    "_raw_v_data_hex": hex_v,
                    "_raw_v_data_b64": b64_v,
                    "_raw_v_data_text": txt_v,
                }
                rows.append(row)

        self._keychain_rows = rows
        self._populate_keychain_tree(rows)
        self.set_progress(self.progress_kc, total, total)
        self.set_status(self._("lbl_status_ready"))
        self.log_to(self.txt_log if hasattr(self, "txt_log") else self.txt_jwt_log,
                    f"[Keychain] Loaded {len(rows)} entries from {path}")

    def _populate_keychain_tree(self, rows):
        self.kc_tree.delete(*self.kc_tree.get_children())
        cols = ("class", "agrp", "svce", "acct", "v_data_hex",
                "v_data_b64", "v_data_text", "pdmn", "cdat", "mdat")
        for row in rows:
            self.kc_tree.insert("", "end",
                                values=tuple(row.get(c, "") for c in cols))

    def _filter_keychain(self, *_):
        ftext = self.kc_filter_var.get().lower()
        cls_filter = self.kc_class_var.get()
        filtered = []
        for row in self._keychain_rows:
            if cls_filter != "all" and row.get("class") != cls_filter:
                continue
            if ftext and ftext not in str(row).lower():
                continue
            filtered.append(row)
        self._populate_keychain_tree(filtered)

    def export_keychain_csv(self):
        if not self._keychain_rows:
            messagebox.showwarning("", self._("msg_no_kc_data"))
            return
        out_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if not out_path:
            return
        import csv
        cols = ["class", "agrp", "svce", "acct",
                "_raw_v_data_hex", "_raw_v_data_b64", "_raw_v_data_text",
                "pdmn", "cdat", "mdat"]
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(self._keychain_rows)
        messagebox.showinfo("", self._("report_saved").format(path=out_path))

    # =========================================================================
    # JWT ANALYZER LOGIC
    # =========================================================================
    def run_jwt_analysis(self):
        path = self.jwt_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        self.btn_run_jwt.config(state="disabled")
        self.set_status("Analyzing JWT...")
        self.set_progress(self.progress_jwt, 0)
        self._clear_widget(self.txt_jwt_log)

        try:
            self._analyze_jwt(path)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_jwt.config(state="normal")
            self.set_status(self._("lbl_status_ready"))

    def _analyze_jwt(self, path: str):
        jwt_re = re.compile(
            r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+")
        # Also match partial JWTs (header only)
        eyj_re = re.compile(r"eyJ[A-Za-z0-9\-_+/=]{8,}")

        file_hashes = compute_file_hashes(path)
        file_size = file_hashes["size"]
        out_path = os.path.splitext(path)[0] + "_jwt_analysis.txt"

        found_jwts = []
        found_eyj = []
        processed = 0
        self.set_progress(self.progress_jwt, 0, file_size or 1)

        self.log_to(self.txt_jwt_log, f"[JWT] Analyzing: {path}")
        self.log_to(self.txt_jwt_log,
                    f"[JWT] MD5: {file_hashes['md5']}")

        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                processed += len(line.encode())
                if lineno % 1000 == 0:
                    self.set_progress(self.progress_jwt, processed, file_size or 1)

                # Full JWTs
                for match in jwt_re.finditer(line):
                    token = match.group()
                    if token not in [j["token"] for j in found_jwts]:
                        parts = token.split(".")
                        decoded = {}
                        for i, part_name in enumerate(["header", "payload"]):
                            if i < len(parts):
                                try:
                                    padded = parts[i] + "=="
                                    dec = base64.urlsafe_b64decode(padded)
                                    decoded[part_name] = json.loads(dec)
                                except Exception:
                                    try:
                                        dec = base64.urlsafe_b64decode(padded)
                                        decoded[part_name] = dec.decode(
                                            "utf-8", errors="replace")
                                    except Exception:
                                        decoded[part_name] = parts[i]
                        found_jwts.append({
                            "lineno": lineno,
                            "token": token,
                            "header": decoded.get("header", {}),
                            "payload": decoded.get("payload", {}),
                        })

                # eyJ fragments
                for match in eyj_re.finditer(line):
                    tok = match.group()
                    if "." not in tok and tok not in found_eyj:
                        found_eyj.append(tok)

        self.set_progress(self.progress_jwt, file_size or 1, file_size or 1)

        # Display
        self.log_to(self.txt_jwt_log,
                    f"\n[JWT] Full JWT tokens found: {len(found_jwts)}")
        with open(out_path, "w", encoding="utf-8") as out_f:
            out_f.write(f"# JWT Analysis — {path}\n"
                        f"# MD5: {file_hashes['md5']}\n"
                        f"# Date: {datetime.now().isoformat(timespec='seconds')}\n\n")
            out_f.write(f"Full JWTs: {len(found_jwts)}\n"
                        f"eyJ fragments: {len(found_eyj)}\n\n")

            for i, jwt_data in enumerate(found_jwts, 1):
                msg = (f"\n[JWT #{i}] Line {jwt_data['lineno']}\n"
                       f"  Token: {jwt_data['token'][:80]}{'...' if len(jwt_data['token']) > 80 else ''}\n"
                       f"  Header: {json.dumps(jwt_data['header'], ensure_ascii=False)}\n"
                       f"  Payload: {json.dumps(jwt_data['payload'], ensure_ascii=False)}")
                self.log_to(self.txt_jwt_log, msg)
                out_f.write(msg + "\n")

            if found_eyj:
                self.log_to(self.txt_jwt_log,
                            f"\n[JWT] eyJ fragments (no dot separator): {len(found_eyj)}")
                out_f.write(f"\n--- eyJ fragments ---\n")
                for tok in found_eyj[:50]:
                    try:
                        dec = base64.urlsafe_b64decode(tok + "==").decode(
                            "utf-8", errors="replace")
                    except Exception:
                        dec = "?"
                    line_out = f"  {tok[:60]} => {dec[:60]}"
                    self.log_to(self.txt_jwt_log, line_out)
                    out_f.write(line_out + "\n")

        self.log_to(self.txt_jwt_log,
                    self._("report_saved").format(path=out_path))
        messagebox.showinfo("JWT", self._("analysis_done"))

    # =========================================================================
    # BIRTHDAY DICTIONARY LOGIC
    # =========================================================================
    def run_birthday_gen(self):
        dob_str = self.bday_dob_var.get().strip()
        try:
            dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
        except ValueError:
            messagebox.showerror(self._("msg_error"),
                                 self._("msg_invalid_date"))
            return

        selected_formats = [f for f, var in self.bday_formats.items() if var.get()]
        if not selected_formats:
            messagebox.showwarning("", self._("msg_no_bday_format"))
            return

        gen_plain = self.bday_plain_var.get()
        gen_b64 = self.bday_b64_var.get()
        if not gen_plain and not gen_b64:
            messagebox.showwarning("", self._("msg_no_format"))
            return

        out_dir = filedialog.askdirectory()
        if not out_dir:
            return

        self.btn_run_bday.config(state="disabled")
        self.set_status("Generating birthday dictionary...")
        self.set_progress(self.progress_bday, 0, len(selected_formats))
        self._clear_widget(self.txt_bday_log)

        try:
            all_strings = generate_birthday_strings(dob)
            plain_entries = []
            b64_entries = []

            for i, fmt in enumerate(selected_formats):
                vals = all_strings.get(fmt, [])
                for val in vals:
                    if gen_plain:
                        plain_entries.append(val)
                    if gen_b64:
                        b64_val = base64.b64encode(val.encode()).decode()
                        b64_entries.append(f"{b64_val} -> {val}")
                self.set_progress(self.progress_bday, i + 1, len(selected_formats))

            dob_label = dob.strftime("%Y%m%d")
            files_created = []

            if gen_plain and plain_entries:
                fname = os.path.join(out_dir, f"birthday_{dob_label}_plain.txt")
                with open(fname, "w", encoding="utf-8") as f:
                    f.write("\n".join(plain_entries) + "\n")
                files_created.append(fname)
                self.log_to(self.txt_bday_log,
                            f"Plain: {len(plain_entries)} entries → {fname}")

            if gen_b64 and b64_entries:
                fname = os.path.join(out_dir, f"birthday_{dob_label}_base64.txt")
                with open(fname, "w", encoding="utf-8") as f:
                    f.write("\n".join(b64_entries) + "\n")
                files_created.append(fname)
                self.log_to(self.txt_bday_log,
                            f"Base64: {len(b64_entries)} entries → {fname}")

            # Also show in log
            self.log_to(self.txt_bday_log,
                        f"\nGenerated formats for {dob}:")
            for fmt in selected_formats:
                vals = all_strings.get(fmt, [])
                for val in vals:
                    b64 = base64.b64encode(val.encode()).decode() if gen_b64 else ""
                    self.log_to(self.txt_bday_log,
                                f"  [{fmt}] {val}" + (f"  →  {b64}" if b64 else ""))

            messagebox.showinfo("", f"{self._('msg_done')}\nFiles: {len(files_created)}")

        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_bday.config(state="normal")
            self.set_status(self._("lbl_status_ready"))

    # =========================================================================
    # ENTROPY ANALYSIS LOGIC
    # =========================================================================
    def run_entropy_analysis(self):
        path = self.entropy_path.get().strip()
        if not path:
            messagebox.showwarning("", self._("msg_no_file"))
            return
        try:
            threshold = float(self.entropy_threshold_var.get())
            block_size = int(self.entropy_block_var.get())
        except ValueError:
            messagebox.showerror(self._("msg_error"),
                                 self._("msg_invalid_entropy"))
            return

        self.btn_run_entropy.config(state="disabled")
        self.set_status("Entropy analysis...")
        self.set_progress(self.progress_entropy, 0)
        self._clear_widget(self.txt_entropy_log)

        try:
            self._analyze_entropy(path, threshold, block_size)
        except Exception as e:
            messagebox.showerror(self._("msg_error"), str(e))
        finally:
            self.btn_run_entropy.config(state="normal")
            self.set_status(self._("lbl_status_ready"))

    def _analyze_entropy(self, path: str, threshold: float, block_size: int):
        file_hashes = compute_file_hashes(path)
        file_size = file_hashes["size"]
        out_path = os.path.splitext(path)[0] + "_entropy_report.txt"

        self.log_to(self.txt_entropy_log,
                    f"[Entropy] File: {path}")
        self.log_to(self.txt_entropy_log,
                    f"[Entropy] Size: {file_size:,} bytes | "
                    f"Block: {block_size} B | Threshold: {threshold}")
        self.log_to(self.txt_entropy_log,
                    f"[Entropy] MD5: {file_hashes['md5']}")

        high_entropy_blocks = []
        total_blocks = 0
        self.set_progress(self.progress_entropy, 0, file_size or 1)

        with open(path, "rb") as f:
            offset = 0
            while True:
                block = f.read(block_size)
                if not block:
                    break
                total_blocks += 1
                ent = shannon_entropy(block)
                if ent >= threshold:
                    high_entropy_blocks.append({
                        "offset": offset,
                        "size": len(block),
                        "entropy": ent,
                        "magic": self._detect_block_magic(block),
                    })
                offset += len(block)
                if total_blocks % 100 == 0:
                    self.set_progress(self.progress_entropy, offset, file_size or 1)

        self.set_progress(self.progress_entropy, file_size or 1, file_size or 1)

        # Merge consecutive high-entropy blocks
        merged = self._merge_blocks(high_entropy_blocks, block_size)

        self.log_to(self.txt_entropy_log,
                    f"\n[Entropy] Total blocks: {total_blocks} | "
                    f"High entropy blocks: {len(high_entropy_blocks)} | "
                    f"Merged regions: {len(merged)}")

        with open(out_path, "w", encoding="utf-8") as out_f:
            out_f.write(f"# Entropy Analysis — {path}\n"
                        f"# MD5: {file_hashes['md5']}\n"
                        f"# SHA-256: {file_hashes['sha256']}\n"
                        f"# Block size: {block_size} B | Threshold: {threshold}\n"
                        f"# Total blocks: {total_blocks}\n"
                        f"# High-entropy blocks: {len(high_entropy_blocks)}\n"
                        f"# Merged regions: {len(merged)}\n\n")

            if not merged:
                msg = "[Entropy] No high-entropy regions found above threshold."
                self.log_to(self.txt_entropy_log, msg)
                out_f.write(msg + "\n")
            else:
                out_f.write("offset_hex,offset_dec,size_bytes,avg_entropy,magic\n")
                for region in merged:
                    msg = (f"  Offset: 0x{region['start']:08x} "
                           f"({region['start']:,}) | "
                           f"Size: {region['size']:,} B | "
                           f"Entropy: {region['avg_entropy']:.4f} | "
                           f"Magic: {region['magic']}")
                    self.log_to(self.txt_entropy_log, msg)
                    out_f.write(
                        f"0x{region['start']:08x},{region['start']},"
                        f"{region['size']},{region['avg_entropy']:.4f},"
                        f"{region['magic']}\n"
                    )

        # Overall file entropy
        with open(path, "rb") as f:
            full_data = f.read()
        overall_ent = shannon_entropy(full_data)
        self.log_to(self.txt_entropy_log,
                    f"\n[Entropy] Overall file entropy: {overall_ent:.4f}/8.000")

        interpretation = self._interpret_entropy(overall_ent, len(high_entropy_blocks),
                                                 total_blocks)
        self.log_to(self.txt_entropy_log,
                    f"[Entropy] Assessment: {interpretation}")

        self.log_to(self.txt_entropy_log,
                    self._("report_saved").format(path=out_path))
        messagebox.showinfo("Entropy", self._("analysis_done"))

    @staticmethod
    def _detect_block_magic(block: bytes) -> str:
        if block[:8] == b"bplist00":
            return "plist_binary"
        if block[:16] == b"SQLite format 3\x00":
            return "sqlite"
        if block[:4] == b"PK\x03\x04":
            return "zip"
        if block[:3] == b"\x1f\x8b\x08":
            return "gzip"
        if block[:4] == b"\x89PNG":
            return "png"
        if block[:2] == b"\xff\xd8":
            return "jpeg"
        if block[:4] in (b"\x00\x00\x00\x0c", b"\x00\x00\x00\x20"):
            return "possible_mp4"
        # AES CBC/ECB — uniform byte distribution
        cnt = Counter(block)
        if len(cnt) > 200:
            return "possible_encrypted"
        return "unknown"

    @staticmethod
    def _merge_blocks(blocks: list, block_size: int) -> list:
        if not blocks:
            return []
        merged = []
        current = None
        for b in sorted(blocks, key=lambda x: x["offset"]):
            if current is None:
                current = {
                    "start": b["offset"],
                    "end": b["offset"] + b["size"],
                    "entropies": [b["entropy"]],
                    "magic": b["magic"],
                }
            elif b["offset"] <= current["end"] + block_size:
                current["end"] = max(current["end"], b["offset"] + b["size"])
                current["entropies"].append(b["entropy"])
                if b["magic"] != "unknown":
                    current["magic"] = b["magic"]
            else:
                avg = sum(current["entropies"]) / len(current["entropies"])
                merged.append({
                    "start": current["start"],
                    "size": current["end"] - current["start"],
                    "avg_entropy": avg,
                    "magic": current["magic"],
                })
                current = {
                    "start": b["offset"],
                    "end": b["offset"] + b["size"],
                    "entropies": [b["entropy"]],
                    "magic": b["magic"],
                }
        if current:
            avg = sum(current["entropies"]) / len(current["entropies"])
            merged.append({
                "start": current["start"],
                "size": current["end"] - current["start"],
                "avg_entropy": avg,
                "magic": current["magic"],
            })
        return merged

    @staticmethod
    def _interpret_entropy(overall: float, high_blocks: int, total_blocks: int) -> str:
        ratio = high_blocks / total_blocks if total_blocks else 0
        if overall > 7.9:
            return "File appears fully encrypted or compressed (very high entropy)."
        if overall > 7.2:
            return (f"High overall entropy ({overall:.2f}). "
                    f"{ratio*100:.1f}% of blocks above threshold. "
                    "Likely contains encrypted/compressed sections.")
        if overall > 6.0:
            return (f"Moderate entropy ({overall:.2f}). "
                    "Mixed content: some encrypted/compressed regions detected.")
        return (f"Low entropy ({overall:.2f}). "
                "File appears mostly unencrypted / plaintext.")


# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    app = App()
    app.mainloop()
