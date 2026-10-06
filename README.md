# Traverso Forensics v1.0 - Android Extraction Suite

**Production-grade forensic extraction tool for Android 12-13**

## Status: Stable

✓ **Android 12-13**: Fully functional, tested, reliable  
✓ **CVE-2024-0044**: PackageManager payload injection exploit  
✓ **Chain of Custody**: Compliant with ISO/IEC 27037:2012  
✓ **No root required**: Works with standard ADB  

---

## What Works

- **Android 12-13 devices**: Extract app data, media, logs
- **Non-invasive extraction**: Uses official CVE-2024-0044 payload
- **Forensic integrity**: Hash verification, chain of custody logs
- **GUI + CLI**: Both modes available
- **USB Debugging**: Standard ADB over USB cable
- **WiFi Debugging**: ADB over WiFi/LAN (IP:Port connection)

---

## Requirements

1. **Android device**: Running Android 12 or 13
2. **Traverso.apk**: Must be in working directory (included)
3. **ADB**: Android Debug Bridge (in PATH or auto-detected)
4. **Python 3.8+**: For running the extraction tool

---

## Usage

### GUI Mode
```bash
python traverso_extractor_v2.1.py
```

### Command Line
```bash
python traverso_extractor_v2.1.py --device <serial> --extract-all --output results/
```

### WiFi Connection

1. **Device Setup**:
   - Enable developer mode: Settings → About → Tap "Build Number" 7 times
   - Settings → Developer Options → Enable "Wireless Debugging"
   - Note the device IP and port

2. **In Traverso GUI**:
   - Leave USB disconnected
   - Enter device IP:Port in "WiFi IP:Port" field (e.g., `192.168.1.100:5555`)
   - Click "Connect WiFi"
   - Click "Detect Device"

---

## What's NOT Supported

- **Android 14-17**: Requires new exploits not yet available
- **Android < 12**: Deprecated versions, no support
- **Modded/Rooted devices**: Untested (extract on clean ROM)
- **iOS**: Android only

---

## File Layout

```
C:\EXTRACTOR\EXTRACTOR_APP-main\
├── traverso_extractor_v2.1.py    ← Main tool
├── Traverso.apk                  ← Extraction payload (required)
├── traverso_logo.png             ← GUI icon (optional)
└── README.md                      ← This file
```

---

## Forensic Standards

This tool follows:
- **ISO/IEC 27037:2012** - Digital evidence acquisition
- **Chain of Custody** - Logged in plaintext + JSON
- **Hash Verification** - SHA-256 of all extracted data
- **No tampering** - Read-only extraction mode

---

## Version History

| Version | Release | Status | Platforms |
|---------|---------|--------|-----------|
| **1.0** | 2026-09-09 | ✓ Stable | Android 12-13 |
| 2.1 (legacy) | 2026-03-22 | ✗ Deprecated | Android 9-13 |

---

## Support

For issues or questions:
- Check device compatibility (Android 12-13 only)
- Ensure Traverso.apk is in working directory
- Enable USB Debugging on device
- Run as Administrator (Windows)

---

**Developer**: Miguel Ángel Alfredo Traverso  
**License**: Forensic Use Only  
**Standard**: ISO/IEC 27037:2012
