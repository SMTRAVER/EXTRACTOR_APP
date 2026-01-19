
**TRAVERSO FORENSICS**
<div align="center">
<img src="./traverso_logo.png" alt="TRAVERSO FORENSIC" width="200"/>
</div>
<br>
**ANDROID DATA EXTRACTION**
DESCRIPTION:
Forensic tool for data extraction from Android apps using CVE-2024-0044 (Android 12/13)

PREREQUISITES:
Python 3.8 or higher
Android Debug Bridge (ADB) installed and on the PATH
Connected Android device with USB Debugging enabled
APK de F-Droid (o similar) para el exploit
INSTALLATION:
Install Python:

Python 3.8+
tkinter (included in most Python installations)
Install Python dependencies:

pip install -r requirements.txt

Instalar ADB (Android Debug Bridge):

Windows:

Download Android Platform Tools from: https://developer.android.com/studio/releases/platform-tools
Extract and add to the system PATH
Check: adb version
Linux (Ubuntu/Debian):

sudo apt update
sudo apt install adb
Check: adb version
macOS:

brew install android-platform-tools
Check: adb version
DEVICE SETTINGS:
Enable Developer Options on Android:

Go to Settings > About Phone
Tap 7 times on "Build Number"
Habilitar USB Debugging:

Go to Settings > Developer Options
Turn on "USB Debugging"
Connect device via USB:

Connect USB cable
Accept debug authorization on the device
Check: adb devices
RUN PROGRAM:
python extractor_app.py

FEATURES:
✓ Automatic detection of Android devices ✓ List of installed apps ✓ Data extraction using CVE-2024-0044 ✓ SHA256 hash generation of the extracted file ✓ PDF report generation with device information ✓ Detailed log of all operations ✓ Modern, easy-to-use graphical interface

OUTPUT STRUCTURE:
extraction_[package][timestamp]/ ├── wa.tar # Extracted Data ├── [package][timestamp]wa_tar_SHA256.txt # Hash del tar ├── extraction_report[timestamp].pdf # Reporte en PDF ├── extraction_report_[timestamp]SHA256.txt # Hash del PDF └── extraction_log[timestamp].txt # Operations Log

SUPPORTED DEVICES:
Android 12
Android 13
Devices with unpatched CVE-2024-0044
SAFETY REQUIREMENTS:
⚠️ This tool should be used only by:

Authorized forensic investigation personnel
With a court order or legal authorization
On your own devices or with consent
❌ NO use for:

Unauthorized access to devices
Privacy violation
Illegal activities
TROUBLESHOOTING:
Error: "adb: command not found" → ADB is not installed or is not in the PATH → Install ADB as instructed above

Error: "no devices/emulators found" → Device not connected or USB debugging disabled → Verify USB connection and authorize on the device → Execute: adb devices

Error: "APK not found" → F-Droid.apk is not in the script folder → Download from https://f-droid.org/

Error: "ImportError: No module named 'reportlab'" → pip install reportlab

Error: "Failed to create backup" → The exploit may not work on this device → Check Android version (12 or 13) → Verify that the device does not have recent security patches

REQUIRED FILES:
✓ extractor_app.py # Script principal ✓ F-Droid.apk # APK para el exploit ✓ requirements.txt # Dependencias Python

LEGAL NOTES:
Use for legal forensics only
Requires legal authorization for use
The user is responsible for compliance with applicable laws
CVE-2024-0044 is a known and documented vulnerability
CHANGELOG:
v1.0 - Current Version

PDF report generation
SHA256 hash calculation
Improved interface
Detailed logging
Simplified extraction (no decompressing tar)
2026 Traverso Forensics.
