# PyInstaller spec — LanScanner.app dla macOS (Apple Silicon, arm64)
# Budowanie (na Macu):  pyinstaller --noconfirm LanScanner-macos.spec

a = Analysis(["lan_scanner.py"], pathex=[], datas=[], hiddenimports=[])
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="LanScanner",
    console=False,
    target_arch="arm64",
    codesign_identity=None,   # ad-hoc podpis (wymagany na arm64)
)

coll = COLLECT(exe, a.binaries, a.datas, name="LanScanner")

app = BUNDLE(
    coll,
    name="LanScanner.app",
    bundle_identifier="pl.sevendots.lanscanner",
    info_plist={
        "CFBundleName": "LanScanner",
        "CFBundleDisplayName": "LAN Scanner",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1.0.0",
        "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
        # macOS 15+: bez tego systemowy dialog "Sieć lokalna" się nie pojawi
        "NSLocalNetworkUsageDescription":
            "LAN Scanner skanuje urządzenia w sieci lokalnej, aby wyświetlić ich nazwy.",
        "NSBonjourServices": ["_netbios-ns._udp"],
    },
)
