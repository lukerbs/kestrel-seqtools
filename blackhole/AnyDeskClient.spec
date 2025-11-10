# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Blackhole (AnyDeskClient.exe)
# Supports CustomTkinter with --onefile mode

import os
import customtkinter

block_cipher = None

# ============================================================================
# Find CustomTkinter assets path
# ============================================================================
ctk_path = os.path.dirname(customtkinter.__file__)
ctk_assets_path = os.path.join(ctk_path, 'assets')

# ============================================================================
# Data files to include
# ============================================================================
datas = [
    # Blackhole's own data files
    ('utils/frida_hook.js', 'utils'),
    ('assets', 'assets'),
    
    # CustomTkinter assets (CRITICAL for --onefile mode)
    # Bundle as 'customtkinter/assets' to preserve directory structure
    # This ensures CustomTkinter's __file__-based path finding works correctly
    (ctk_assets_path, 'customtkinter/assets'),
]

# ============================================================================
# Hidden imports
# ============================================================================
hiddenimports = [
    # Pynput Windows modules
    'pynput.keyboard._win32',
    'pynput.mouse._win32',
    
    # CustomTkinter modules (ensure all are included)
    'customtkinter',
    'customtkinter.windows',
    'customtkinter.windows.widgets',
    'customtkinter.windows.widgets.appearance_mode',
    'customtkinter.windows.widgets.core_rendering',
    'customtkinter.windows.widgets.core_widget_classes',
    'customtkinter.windows.widgets.font',
    'customtkinter.windows.widgets.image',
    'customtkinter.windows.widgets.scaling',
    'customtkinter.windows.widgets.theme',
    'customtkinter.windows.widgets.utility',
    
    # CustomTkinter dependencies
    'darkdetect',
    'packaging',
]

# ============================================================================
# Analysis
# ============================================================================
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ============================================================================
# PYZ (Python bytecode archive)
# ============================================================================
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ============================================================================
# EXE (Single-file executable)
# ============================================================================
# Note: console mode is controlled by build script (--console or --noconsole flag)
# Default to noconsole (production), build script can override
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,  # CRITICAL: Include datas in EXE for --onefile mode
    [],
    name='AnyDeskClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Default: hidden console (production mode)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/AnyDesk.ico',
)

