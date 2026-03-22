#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# base64_forensic_toolkit_v2_6.py  (entry point for v2.6 / v2.7)
# Laboratorium Elektroniki / Krystian Zarzecki

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import base64_forensic_toolkit_v2_5 as _base
_base.VERSION = "2.7"

from base64_forensic_toolkit_v2_5 import App, TRANSLATIONS

# Patch 1: new tabs (SQLite, iOS, PW, Dedup, PDF, Hex)
from b64toolkit_v26_extension import patch_app
patch_app(App, TRANSLATIONS)

# Patch 2: Layout B (two-level notebook + Settings)
from b64toolkit_layout_b import patch_layout_b, GROUPS
patch_layout_b(App, TRANSLATIONS)

# Patch 3: v2.7 modules (Hash ID, BFU/AFU, Lockdown, Leet, Timestamp, URL)
from b64toolkit_v27_extension import patch_v27
patch_v27(App, TRANSLATIONS, GROUPS)

if __name__ == "__main__":
    app = App()
    app.mainloop()
