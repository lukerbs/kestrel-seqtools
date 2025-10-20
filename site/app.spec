# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Flask + mitmproxy bank app

block_cipher = None

# Data files to include
datas = [
    ('templates', 'templates'),
    ('static', 'static'),
    ('data', 'data'),
]

# Hidden imports for mitmproxy
hiddenimports = [
    'mitmproxy.tools.dump',
    'mitmproxy.addons',
    'mitmproxy.certs',
    'mitmproxy.http',
    'mitmproxy.proxy',
    'mitmproxy.options',
    'mitmproxy.ctx',
    'cryptography.hazmat.backends.openssl',
    'asyncio',
    'pkg_resources.py2_warn',
    'wsproto',
    'h2',
    'hyperframe',
    'hpack',
    'kaitaistruct',
    'pyperclip',
    'sortedcontainers',
    'certifi',
    'passlib',
]

a = Analysis(
    ['app.py'],
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

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netservice',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Production default: hidden. Build script updates for dev mode.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
