# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['base64_forensic_toolkit_v2_6.py'],
    pathex=[],
    binaries=[],
    datas=[('base64_forensic_toolkit_v2_5.py', '.'), ('b64toolkit_v26_extension.py', '.'), ('b64toolkit_layout_b.py', '.'), ('b64toolkit_v27_extension.py', '.'), ('app_icon.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='base64_forensic_toolkit_v2_7',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app_icon.ico'],
)
