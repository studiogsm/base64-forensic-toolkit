#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# b64toolkit_layout_b.py
# Layout B patch: two-level notebook (groups + sub-tabs) + Settings tab
# Import and call patch_layout_b(App, TRANSLATIONS) before mainloop

import tkinter as tk
from tkinter import ttk

# ─────────────────────────────────────────────────────────────────────────────
# Group + Settings translation keys
# ─────────────────────────────────────────────────────────────────────────────
LAYOUT_TRANSLATIONS = {
    "PL": {
        "group_analysis":    "🔍 Analiza",
        "group_dicts":       "🔑 Słowniki",
        "group_tools":       "🔄 Narzędzia",
        "group_reports":     "📋 Raporty",
        "group_settings":    "⚙️ Ustawienia",
        # Settings tab content
        "lbl_settings_lang":    "Język interfejsu:",
        "lbl_settings_theme":   "Motyw:",
        "lbl_settings_theme_light": "Jasny",
        "lbl_settings_theme_dark":  "Ciemny",
        "lbl_settings_recent":  "Historia ostatnich plików:",
        "btn_settings_clear_recent": "Wyczyść historię",
        "lbl_settings_about":   "O programie",
        "lbl_about_text":
            "Base64 Forensic Toolkit\n"
            "Wersja: {version}\n\n"
            "Laboratorium Elektroniki\n"
            "Krystian Zarzecki\n"
            "Biegły sądowy z zakresu informatyki śledczej\n"
            "Sąd Okręgowy w Tarnobrzegu\n\n"
            "k.zarzecki@wezafon.pl\n"
            "facebook.com/LaboratoriumElektroniki",
        "btn_apply_settings":   "Zastosuj ustawienia",
        "msg_restart_theme":    "Motyw zostanie w pełni zastosowany po restarcie.",
    },
    "EN": {
        "group_analysis":    "🔍 Analysis",
        "group_dicts":       "🔑 Dictionaries",
        "group_tools":       "🔄 Tools",
        "group_reports":     "📋 Reports",
        "group_settings":    "⚙️ Settings",
        "lbl_settings_lang":    "Interface language:",
        "lbl_settings_theme":   "Theme:",
        "lbl_settings_theme_light": "Light",
        "lbl_settings_theme_dark":  "Dark",
        "lbl_settings_recent":  "Recent files history:",
        "btn_settings_clear_recent": "Clear history",
        "lbl_settings_about":   "About",
        "lbl_about_text":
            "Base64 Forensic Toolkit\n"
            "Version: {version}\n\n"
            "Laboratorium Elektroniki\n"
            "Krystian Zarzecki\n"
            "Court Expert — Digital Forensics & Teleinformatics\n"
            "District Court in Tarnobrzeg\n\n"
            "k.zarzecki@wezafon.pl\n"
            "facebook.com/LaboratoriumElektroniki",
        "btn_apply_settings":   "Apply settings",
        "msg_restart_theme":    "Theme will be fully applied after restart.",
    },
    "DE": {
        "group_analysis":    "🔍 Analyse",
        "group_dicts":       "🔑 Wörterbücher",
        "group_tools":       "🔄 Werkzeuge",
        "group_reports":     "📋 Berichte",
        "group_settings":    "⚙️ Einstellungen",
        "lbl_settings_lang":    "Sprache:",
        "lbl_settings_theme":   "Design:",
        "lbl_settings_theme_light": "Hell",
        "lbl_settings_theme_dark":  "Dunkel",
        "lbl_settings_recent":  "Letzte Dateien:",
        "btn_settings_clear_recent": "Verlauf löschen",
        "lbl_settings_about":   "Über",
        "lbl_about_text":
            "Base64 Forensic Toolkit\nVersion: {version}\n\n"
            "Laboratorium Elektroniki\nKrystian Zarzecki",
        "btn_apply_settings":   "Einstellungen übernehmen",
        "msg_restart_theme":    "Design wird nach Neustart vollständig angewendet.",
    },
    "FR": {
        "group_analysis":    "🔍 Analyse",
        "group_dicts":       "🔑 Dictionnaires",
        "group_tools":       "🔄 Outils",
        "group_reports":     "📋 Rapports",
        "group_settings":    "⚙️ Paramètres",
        "lbl_settings_lang":    "Langue :",
        "lbl_settings_theme":   "Thème :",
        "lbl_settings_theme_light": "Clair",
        "lbl_settings_theme_dark":  "Sombre",
        "lbl_settings_recent":  "Fichiers récents :",
        "btn_settings_clear_recent": "Effacer l'historique",
        "lbl_settings_about":   "À propos",
        "lbl_about_text":
            "Base64 Forensic Toolkit\nVersion : {version}\n\n"
            "Laboratorium Elektroniki\nKrystian Zarzecki",
        "btn_apply_settings":   "Appliquer",
        "msg_restart_theme":    "Le thème sera appliqué après redémarrage.",
    },
    "ES": {
        "group_analysis":    "🔍 Análisis",
        "group_dicts":       "🔑 Diccionarios",
        "group_tools":       "🔄 Herramientas",
        "group_reports":     "📋 Informes",
        "group_settings":    "⚙️ Configuración",
        "lbl_settings_lang":    "Idioma:",
        "lbl_settings_theme":   "Tema:",
        "lbl_settings_theme_light": "Claro",
        "lbl_settings_theme_dark":  "Oscuro",
        "lbl_settings_recent":  "Archivos recientes:",
        "btn_settings_clear_recent": "Borrar historial",
        "lbl_settings_about":   "Acerca de",
        "lbl_about_text":
            "Base64 Forensic Toolkit\nVersión: {version}\n\n"
            "Laboratorium Elektroniki\nKrystian Zarzecki",
        "btn_apply_settings":   "Aplicar",
        "msg_restart_theme":    "El tema se aplicará completamente tras reiniciar.",
    },
    "IT": {
        "group_analysis":    "🔍 Analisi",
        "group_dicts":       "🔑 Dizionari",
        "group_tools":       "🔄 Strumenti",
        "group_reports":     "📋 Report",
        "group_settings":    "⚙️ Impostazioni",
        "lbl_settings_lang":    "Lingua:",
        "lbl_settings_theme":   "Tema:",
        "lbl_settings_theme_light": "Chiaro",
        "lbl_settings_theme_dark":  "Scuro",
        "lbl_settings_recent":  "File recenti:",
        "btn_settings_clear_recent": "Cancella cronologia",
        "lbl_settings_about":   "Info",
        "lbl_about_text":
            "Base64 Forensic Toolkit\nVersione: {version}\n\n"
            "Laboratorium Elektroniki\nKrystian Zarzecki",
        "btn_apply_settings":   "Applica",
        "msg_restart_theme":    "Il tema verrà applicato completamente al riavvio.",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Group definitions — (group_key, [sub_tab_keys...])
# ─────────────────────────────────────────────────────────────────────────────
GROUPS = [
    ("group_analysis", [
        "tab_parser",
        "tab_sqlite",
        "tab_ios",
        "tab_research",
        "tab_keychain",
        "tab_jwt",
        "tab_entropy",
    ]),
    ("group_dicts", [
        "tab_dictgen",
        "tab_birthday",
        "tab_dedup",
        "tab_pwstrength",
    ]),
    ("group_tools", [
        "tab_converter",
        "tab_live",
        "tab_hex",
    ]),
    ("group_reports", [
        "tab_pdf",
    ]),
    ("group_settings", []),   # built separately
]


# ─────────────────────────────────────────────────────────────────────────────
# Settings tab builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_settings_tab(app, parent: tk.Frame):
    """Build the Settings tab content inside parent frame."""
    from tkinter import messagebox
    pad = {"padx": 10, "pady": 6}

    # ── Language ──────────────────────────────────────────────────────
    lang_frame = ttk.LabelFrame(
        parent, text=app._("lbl_settings_lang"))
    lang_frame.pack(fill="x", **pad)

    lang_combo = ttk.Combobox(
        lang_frame, textvariable=app.lang_var,
        values=["PL", "EN", "DE", "FR", "ES", "IT"],
        width=8, state="readonly")
    lang_combo.pack(side="left", padx=8, pady=6)
    lang_combo.bind("<<ComboboxSelected>>", app._on_lang_change)

    # ── Theme ─────────────────────────────────────────────────────────
    theme_frame = ttk.LabelFrame(
        parent, text=app._("lbl_settings_theme"))
    theme_frame.pack(fill="x", **pad)

    ttk.Radiobutton(
        theme_frame,
        text=app._("lbl_settings_theme_light"),
        variable=app.dark_var, value=False,
        command=app._on_theme_toggle
    ).pack(side="left", padx=8, pady=6)

    ttk.Radiobutton(
        theme_frame,
        text=app._("lbl_settings_theme_dark"),
        variable=app.dark_var, value=True,
        command=app._on_theme_toggle
    ).pack(side="left", padx=8, pady=6)

    # ── Recent files ──────────────────────────────────────────────────
    recent_frame = ttk.LabelFrame(
        parent, text=app._("lbl_settings_recent"))
    recent_frame.pack(fill="x", **pad)

    def clear_recent():
        for key in ["parser", "research", "keychain",
                    "jwt", "birthday", "entropy",
                    "sqlite", "ios"]:
            app.config_mgr.set(f"recent_{key}", "")
        app.config_mgr.save()
        app._rebuild_recent_menu()
        recent_list.config(state="normal")
        recent_list.delete("1.0", "end")
        recent_list.config(state="disabled")

    def refresh_recent():
        recent_list.config(state="normal")
        recent_list.delete("1.0", "end")
        for key in ["parser", "research", "keychain",
                    "jwt", "birthday", "entropy",
                    "sqlite", "ios"]:
            items = app.config_mgr.get_recent(key)
            for item in items:
                recent_list.insert("end", f"[{key}]  {item}\n")
        recent_list.config(state="disabled")

    recent_list = tk.Text(recent_frame, height=8,
                          font=("Consolas", 9), state="disabled")
    recent_list.pack(fill="x", padx=6, pady=4)

    btn_row = ttk.Frame(recent_frame)
    btn_row.pack(fill="x", padx=6, pady=2)
    tk.Button(btn_row,
              text=app._("btn_settings_clear_recent"),
              command=clear_recent).pack(side="left", padx=4)
    tk.Button(btn_row, text="↻ Refresh",
              command=refresh_recent).pack(side="left", padx=4)

    refresh_recent()

    # ── Apply button ──────────────────────────────────────────────────
    tk.Button(
        parent,
        text=app._("btn_apply_settings"),
        bg=app.theme["run_bg"], fg=app.theme["run_fg"],
        font=("Arial", 10, "bold"),
        command=lambda: (app._save_config(),
                         app.set_status(app._("lbl_status_ready")))
    ).pack(anchor="w", padx=10, pady=6)

    # ── About ─────────────────────────────────────────────────────────
    about_frame = ttk.LabelFrame(
        parent, text=app._("lbl_settings_about"))
    about_frame.pack(fill="x", **pad)

    from base64_forensic_toolkit_v2_5 import VERSION
    about_text = app._("lbl_about_text").format(version=VERSION)
    tk.Label(about_frame, text=about_text,
             justify="left", font=("Arial", 10),
             anchor="w").pack(fill="x", padx=10, pady=8)


# ─────────────────────────────────────────────────────────────────────────────
# New _build_notebook — two-level layout
# ─────────────────────────────────────────────────────────────────────────────

def _new_build_notebook(self):
    """
    Replaces App._build_notebook.
    Creates outer notebook (groups) + inner notebooks (sub-tabs).
    """
    import tkinter as _tk
    self.tab_frames = {}
    self._sub_notebooks = {}

    # Unconditionally init all extension state vars
    # (hasattr unreliable on tk.Tk subclass due to Tcl __getattr__)
    self.sqlite_scan_path  = _tk.StringVar()
    self.ios_zip_path      = _tk.StringVar()
    self.pw_file_path      = _tk.StringVar()
    self.pdf_source_path   = _tk.StringVar()
    self.hex_search_var    = _tk.StringVar()
    self.hex_offset_var    = _tk.StringVar(value="0")
    self.hex_bpr_var       = _tk.StringVar(value="16")
    self.dedup_sort_var    = _tk.StringVar(value="none")
    self.pw_entry_var      = _tk.StringVar()
    self.pdf_title_var     = _tk.StringVar(
        value="Forensic Report — Base64 Analysis")
    self.pdf_expert_var    = _tk.StringVar(
        value=self.config_mgr.get("pdf_expert"))
    self.pdf_case_var      = _tk.StringVar(
        value=self.config_mgr.get("pdf_case"))
    self._sqlite_results   = []
    self._pw_results       = []
    self._dedup_files      = []
    self._hex_hits         = []
    self._hex_data         = b""
    self._hex_hit_idx      = 0

    # Outer notebook
    self.notebook = ttk.Notebook(self)
    self.notebook.pack(fill="both", expand=True, padx=4, pady=2)

    # All sub-tab builders in one dict
    # v2.5 builders
    v25_builders = {
        "tab_parser":    self._build_tab_parser,
        "tab_dictgen":   self._build_tab_dictgen,
        "tab_converter": self._build_tab_converter,
        "tab_live":      self._build_tab_live,
        "tab_research":  self._build_tab_research,
        "tab_keychain":  self._build_tab_keychain,
        "tab_jwt":       self._build_tab_jwt,
        "tab_birthday":  self._build_tab_birthday,
        "tab_entropy":   self._build_tab_entropy,
    }
    # v2.6 builders (may not exist if extension not loaded)
    v26_builders = {
        "tab_sqlite":     getattr(self, "_build_tab_sqlite",     None),
        "tab_ios":        getattr(self, "_build_tab_ios",        None),
        "tab_pwstrength": getattr(self, "_build_tab_pwstrength", None),
        "tab_dedup":      getattr(self, "_build_tab_dedup",      None),
        "tab_pdf":        getattr(self, "_build_tab_pdf",        None),
        "tab_hex":        getattr(self, "_build_tab_hex",        None),
    }
    all_builders = {**v25_builders, **v26_builders}

    for group_key, tab_keys in GROUPS:
        group_label = self.T.get(group_key, group_key)

        # Settings group — special case
        if group_key == "group_settings":
            settings_frame = ttk.Frame(self.notebook)
            self.notebook.add(settings_frame, text=group_label)
            _build_settings_tab(self, settings_frame)
            self._sub_notebooks[group_key] = None
            continue

        # Skip groups where no tab builder exists
        valid_keys = [k for k in tab_keys
                      if all_builders.get(k) is not None]
        if not valid_keys:
            continue

        # Group container frame
        group_frame = ttk.Frame(self.notebook)
        self.notebook.add(group_frame, text=group_label)

        # Inner notebook
        inner_nb = ttk.Notebook(group_frame)
        inner_nb.pack(fill="both", expand=True)
        self._sub_notebooks[group_key] = inner_nb

        for tab_key in valid_keys:
            builder = all_builders[tab_key]
            label = self.T.get(tab_key, tab_key)
            frame = ttk.Frame(inner_nb)
            inner_nb.add(frame, text=label)
            self.tab_frames[tab_key] = frame
            builder(frame)


# ─────────────────────────────────────────────────────────────────────────────
# Patch _on_lang_change to update both outer and inner tab labels
# ─────────────────────────────────────────────────────────────────────────────

def _new_on_lang_change(self, _=None):
    new_lang = self.lang_var.get()
    if new_lang not in self.T.__class__:
        # T is a plain dict, check TRANSLATIONS
        from base64_forensic_toolkit_v2_5 import TRANSLATIONS
        if new_lang not in TRANSLATIONS:
            return
    self.lang = new_lang
    # Import here to avoid circular refs
    from base64_forensic_toolkit_v2_5 import TRANSLATIONS
    self.T = TRANSLATIONS[self.lang]
    self.config_mgr.set("language", self.lang)
    self.config_mgr.save()

    # Update outer notebook (group) labels
    for i, (group_key, _) in enumerate(GROUPS):
        try:
            self.notebook.tab(i, text=self.T.get(group_key, group_key))
        except Exception:
            pass

    # Update inner notebook (sub-tab) labels
    for group_key, tab_keys in GROUPS:
        if group_key == "group_settings":
            continue
        inner_nb = self._sub_notebooks.get(group_key)
        if not inner_nb:
            continue
        valid_keys = [k for k in tab_keys
                      if k in self.tab_frames]
        for j, tab_key in enumerate(valid_keys):
            try:
                inner_nb.tab(j, text=self.T.get(tab_key, tab_key))
            except Exception:
                pass

    self.set_status(self.T.get("lbl_status_ready", "Ready"))


# ─────────────────────────────────────────────────────────────────────────────
# Remove language/theme controls from toolbar (moved to Settings tab)
# ─────────────────────────────────────────────────────────────────────────────

def _new_build_toolbar(self):
    """Minimal toolbar — only Recent files menu remains."""
    tb = tk.Frame(self, relief="flat", bd=1)
    tb.pack(fill="x", side="top")
    self._toolbar = tb

    # Recent files menu
    self._recent_btn = tk.Menubutton(
        tb, text=self._("lbl_recent"), relief="raised")
    self._recent_btn.pack(side="left", padx=4, pady=2)
    self._recent_menu = tk.Menu(self._recent_btn, tearoff=0)
    self._recent_btn["menu"] = self._recent_menu
    self._rebuild_recent_menu()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PATCH FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def patch_layout_b(app_class, translations_dict: dict):
    """
    Apply Layout B (two-level notebook + Settings tab).
    Call after patch_app() from b64toolkit_v26_extension.py.
    """
    # 1. Inject new translation keys
    for lang, keys in LAYOUT_TRANSLATIONS.items():
        if lang in translations_dict:
            translations_dict[lang].update(keys)

    # 2. Replace _build_notebook
    app_class._build_notebook = _new_build_notebook

    # 3. Replace _on_lang_change
    app_class._on_lang_change = _new_on_lang_change

    # 4. Replace _build_toolbar (moves lang/theme to Settings tab)
    app_class._build_toolbar = _new_build_toolbar
