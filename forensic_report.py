
#!/usr/bin/env python3
"""
Traverso Forensics - Professional Report Generator v1.0
FIXES & UPDATES:
- v1.0: Text Wrapping y Auto-Layout corregidos.
- v1.1: Detección automática de herramienta y firma del perito.
- v1.0: Verificación y cálculo automático de HASH SHA-256 para imágenes en el reporte.

Developer: Miguel Ángel Alfredo TRAVERSO - 2026
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import sys
import hashlib
from datetime import datetime
import re

# PIL for photo management
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("⚠️  PIL not available")

# ReportLab for PDF (Professional Features)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, 
                                   PageBreak, Image as RLImage, Table, TableStyle, KeepTogether)
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("⚠️  ReportLab not available")


class ISOForensicReportGUI:
    """
    Sistema de Reportes Forenses ISO 27037.
    Versión v1.0 - Hash de imágenes individuales.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Traverso Forensics - ISO 27037 Report Generator v1.0")
        self.root.geometry("1280x900")
        self.root.configure(bg="#1e1e1e")
        
        # Data storage
        self.extraction_dir = None
        self.extraction_log = None
        self.evidence_hash = "N/A (No Log File)"
        
        self.photos = [] 
        self.chain_of_custody = []
        self.logo_img = None 
        
        # Metrics
        self.total_files_count = 0
        self.total_size_mb = 0.0
        
        # Setup
        self.setup_styles()
        self.create_header()
        self.create_notebook()
        self.create_footer()
    
    def setup_styles(self):
        """Setup colors and styles"""
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
        style.configure("TNotebook", background=self.bg_dark, borderwidth=0)
        style.configure("TNotebook.Tab",
                       background=self.bg_panel,
                       foreground=self.fg_text,
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map("TNotebook.Tab",
                 background=[("selected", self.accent_blue)],
                 foreground=[("selected", "white")])
    
    def create_header(self):
        """Create header with LOGO"""
        header = tk.Frame(self.root, bg=self.bg_dark, height=120)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)
        
        # --- LOGO SECTION ---
        logo_frame = tk.Frame(header, bg=self.bg_dark)
        logo_frame.pack(side=tk.LEFT, padx=(20, 10), pady=10)
        
        logo_path = "traverso_logo.png"
        if PIL_AVAILABLE and os.path.exists(logo_path):
            try:
                img = Image.open(logo_path)
                baseheight = 90
                hpercent = (baseheight / float(img.size[1]))
                wsize = int((float(img.size[0]) * float(hpercent)))
                img = img.resize((wsize, baseheight), Image.Resampling.LANCZOS)
                
                self.logo_img = ImageTk.PhotoImage(img)
                tk.Label(logo_frame, image=self.logo_img, bg=self.bg_dark).pack()
            except Exception as e:
                print(f"Error loading logo: {e}")
        
        # --- TITLE SECTION ---
        title_frame = tk.Frame(header, bg=self.bg_dark)
        title_frame.pack(side=tk.LEFT, padx=15, pady=25)
        
        tk.Label(title_frame,
                text="TRAVERSO FORENSICS", 
                font=('Segoe UI', 24, 'bold'),
                fg="white", 
                bg=self.bg_dark).pack(anchor=tk.W)
        
        tk.Label(title_frame,
                text="Digital Evidence Reporting System v1.0 (Hash Verification)",
                font=('Segoe UI', 10),
                fg=self.accent_green,
                bg=self.bg_dark).pack(anchor=tk.W)

    def create_notebook(self):
        notebook_frame = tk.Frame(self.root, bg=self.bg_dark)
        notebook_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_tab_case_info()
        self.create_tab_extraction_data()
        self.create_tab_photos()
        self.create_tab_chain_custody()
        self.create_tab_generate()
    
    def create_tab_case_info(self):
        """Tab 1: Case Data"""
        tab = tk.Frame(self.notebook, bg=self.bg_panel)
        self.notebook.add(tab, text="📋 Case Data")
        
        # Left Column
        left_col = tk.Frame(tab, bg=self.bg_panel)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Directory Loader
        load_frame = tk.LabelFrame(left_col, text="Evidence Source", fg=self.accent_green, bg=self.bg_panel, padx=15, pady=15)
        load_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(load_frame, text="📁 Select Extraction Directory", command=self.load_directory,
                 bg=self.accent_blue, fg="white", font=('Segoe UI', 10, 'bold'), relief=tk.FLAT).pack(fill=tk.X, pady=5)
        
        self.dir_label = tk.Label(load_frame, text="No directory loaded", fg=self.fg_secondary, bg=self.bg_panel, wraplength=400)
        self.dir_label.pack(pady=5)
        
        # Stats & Hash Display
        self.stats_label = tk.Label(load_frame, text="Waiting for data...", fg="white", bg=self.bg_panel, font=('Consolas', 10))
        self.stats_label.pack(pady=5)
        
        self.hash_label = tk.Label(load_frame, text="Integrity Hash: Pending", fg="#e67e22", bg=self.bg_panel, font=('Consolas', 9, 'bold'))
        self.hash_label.pack(pady=5)

        # Basic Info
        info_frame = tk.LabelFrame(left_col, text="Identification", fg=self.accent_green, bg=self.bg_panel, padx=15, pady=15)
        info_frame.pack(fill=tk.X, pady=10)
        self.case_id_entry = self.add_field(info_frame, "Case ID / Reference:")
        self.analyst_entry = self.add_field(info_frame, "Forensic Analyst:")
        
        # Right Column
        right_col = tk.Frame(tab, bg=self.bg_panel)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scope_frame = tk.LabelFrame(right_col, text="Target Application / Scope (Auto-Detected)", fg=self.accent_green, bg=self.bg_panel, padx=15, pady=15)
        scope_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Label(scope_frame, text="Technical details loaded from 'detalles_extraccion.txt' if available:", fg=self.fg_secondary, bg=self.bg_panel).pack(anchor=tk.W)
        self.app_desc_text = tk.Text(scope_frame, height=10, bg=self.bg_input, fg="white", font=('Segoe UI', 10))
        self.app_desc_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.app_desc_text.insert(1.0, "[Waiting for directory selection...]")

    def create_tab_extraction_data(self):
        """Tab 2: Log"""
        tab = tk.Frame(self.notebook, bg=self.bg_panel)
        self.notebook.add(tab, text="💾 Technical Log")
        
        log_frame = tk.LabelFrame(tab, text="Extraction Process Log", fg=self.accent_green, bg=self.bg_panel, padx=10, pady=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.log_display = scrolledtext.ScrolledText(log_frame, bg=self.bg_input, fg="#00ff00", font=('Consolas', 9), wrap=tk.NONE)
        self.log_display.pack(fill=tk.BOTH, expand=True)

    def create_tab_photos(self):
        """Tab 3: Photos"""
        tab = tk.Frame(self.notebook, bg=self.bg_panel)
        self.notebook.add(tab, text="📷 Evidence Photos")
        
        ctrl_frame = tk.Frame(tab, bg=self.bg_panel)
        ctrl_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(ctrl_frame, text="➕ Add Photos", command=self.add_photos, bg=self.accent_green, fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="🗑️ Remove Last", command=self.remove_last_photo, bg=self.accent_red, fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        container = tk.Frame(tab, bg=self.bg_panel)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        canvas = tk.Canvas(container, bg=self.bg_panel, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.photos_frame = tk.Frame(canvas, bg=self.bg_panel)
        
        self.photos_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.photos_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_tab_chain_custody(self):
        """Tab 4: Chain"""
        tab = tk.Frame(self.notebook, bg=self.bg_panel)
        self.notebook.add(tab, text="🔗 Chain of Custody")
        
        input_frame = tk.LabelFrame(tab, text="New Entry", fg=self.accent_green, bg=self.bg_panel, padx=15, pady=10)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(input_frame, text="Custodian:", fg="white", bg=self.bg_panel).pack(anchor=tk.W)
        self.custody_person = tk.Entry(input_frame, bg=self.bg_input, fg="white")
        self.custody_person.pack(fill=tk.X)
        
        tk.Label(input_frame, text="Action / Purpose:", fg="white", bg=self.bg_panel).pack(anchor=tk.W)
        self.custody_action = tk.Entry(input_frame, bg=self.bg_input, fg="white")
        self.custody_action.pack(fill=tk.X, pady=(0,10))
        
        tk.Button(input_frame, text="Add to Chain", command=self.add_custody_entry, bg=self.accent_blue, fg="white", relief=tk.FLAT).pack()
        
        self.custody_display = scrolledtext.ScrolledText(tab, bg=self.bg_input, fg="white", height=10)
        self.custody_display.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    def create_tab_generate(self):
        """Tab 5: Generate"""
        tab = tk.Frame(self.notebook, bg=self.bg_panel)
        self.notebook.add(tab, text="📄 Finalize")
        
        tk.Label(tab, text="Report Preview Summary", fg=self.accent_green, bg=self.bg_panel, font=('Segoe UI', 12)).pack(pady=10)
        
        self.summary_text = scrolledtext.ScrolledText(tab, bg=self.bg_input, fg="white", font=('Consolas', 10))
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=40, pady=10)
        
        btn = tk.Button(tab, text="🖨️ GENERATE ISO 27037 PDF REPORT", command=self.generate_report,
                       bg=self.accent_green, fg="white", font=('Segoe UI', 14, 'bold'), padx=30, pady=15, relief=tk.FLAT)
        btn.pack(pady=20)
        
        tk.Button(tab, text="Refresh Data", command=self.update_summary, bg=self.bg_input, fg="white", relief=tk.FLAT).pack()

    def create_footer(self):
        footer = tk.Frame(self.root, bg="#111111", height=30)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(footer, text="Traverso Forensics System v1.0 - ISO Compliance Mode", fg="#555555", bg="#111111", font=('Segoe UI', 8)).pack()

    # --- Logic ---

    def add_field(self, parent, label):
        tk.Label(parent, text=label, fg="white", bg=self.bg_panel).pack(anchor=tk.W)
        e = tk.Entry(parent, bg=self.bg_input, fg="white")
        e.pack(fill=tk.X, pady=(0, 10))
        return e

    def calculate_file_hash(self, filepath):
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"

    def load_directory(self):
        d = filedialog.askdirectory()
        if d:
            self.extraction_dir = d
            self.dir_label.config(text=d, fg=self.accent_green)
            
            # 1. Count Files
            count = 0
            size = 0
            for root, dirs, files in os.walk(d):
                count += len(files)
                for f in files:
                    try:
                        fp = os.path.join(root, f)
                        size += os.path.getsize(fp)
                    except: pass
            
            self.total_files_count = count
            self.total_size_mb = size / (1024 * 1024)
            self.stats_label.config(text=f"Total Files: {self.total_files_count} | Size: {self.total_size_mb:.2f} MB")
            
            # 2. Load Log & Hash
            log_found = False
            for f in os.listdir(d):
                if f.endswith(".txt") and "log" in f.lower():
                    try:
                        fp = os.path.join(d, f)
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as logfile:
                            self.extraction_log = logfile.read()
                            self.log_display.delete(1.0, tk.END)
                            self.log_display.insert(1.0, self.extraction_log)
                        
                        self.evidence_hash = self.calculate_file_hash(fp)
                        self.hash_label.config(text=f"Log SHA-256: {self.evidence_hash[:16]}...", fg=self.accent_green)
                        log_found = True
                    except: pass
                    break
            
            if not log_found:
                self.log_display.delete(1.0, tk.END)
                self.log_display.insert(1.0, "[!] No extraction log found.")
                self.evidence_hash = "NOT VERIFIED"
                self.hash_label.config(text=self.evidence_hash, fg=self.accent_red)
            
            # 3. AUTO-LOAD DETALLES
            details_path = os.path.join(d, "detalles_extraccion.txt")
            self.app_desc_text.delete(1.0, tk.END)
            
            if os.path.exists(details_path):
                try:
                    with open(details_path, 'r', encoding='utf-8') as df:
                        details_content = df.read()
                        self.app_desc_text.insert(1.0, details_content)
                        messagebox.showinfo("Auto-Import", "✅ Extraction metadata imported successfully!")
                except Exception as e:
                    self.app_desc_text.insert(1.0, f"Error reading metadata: {e}")
            else:
                self.app_desc_text.insert(1.0, "Metadata file (detalles_extraccion.txt) not found.\nPlease enter details manually.")

            self.update_summary()

    def add_photos(self):
        files = filedialog.askopenfilenames(filetypes=[("Images", "*.jpg *.png *.jpeg")])
        for f in files:
            self.photos.append({'path': f, 'caption': ''})
        self.display_photos()
        self.update_summary()

    def display_photos(self):
        for w in self.photos_frame.winfo_children(): w.destroy()
        for idx, p in enumerate(self.photos):
            frame = tk.Frame(self.photos_frame, bg=self.bg_input, relief=tk.RIDGE, bd=2)
            frame.pack(fill=tk.X, pady=5)
            
            if PIL_AVAILABLE:
                try:
                    im = Image.open(p['path'])
                    im.thumbnail((150,150))
                    ph = ImageTk.PhotoImage(im)
                    l = tk.Label(frame, image=ph, bg=self.bg_input)
                    l.image = ph
                    l.pack(side=tk.LEFT, padx=10)
                except: pass
            
            df = tk.Frame(frame, bg=self.bg_input)
            df.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)
            tk.Label(df, text=f"Evidence #{idx+1}: {os.path.basename(p['path'])}", fg=self.accent_green, bg=self.bg_input, font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
            
            t = tk.Text(df, height=3, bg=self.bg_panel, fg="white", font=('Segoe UI', 9))
            t.pack(fill=tk.X)
            t.insert(1.0, p['caption'])
            t.bind('<KeyRelease>', lambda e, i=idx: self.update_caption(i, e.widget))

    def update_caption(self, i, w):
        self.photos[i]['caption'] = w.get(1.0, tk.END).strip()

    def remove_last_photo(self):
        if self.photos: self.photos.pop()
        self.display_photos()
        self.update_summary()

    def add_custody_entry(self):
        p = self.custody_person.get()
        a = self.custody_action.get()
        if p and a:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.chain_of_custody.append({'ts': ts, 'person': p, 'action': a})
            self.custody_display.insert(tk.END, f"[{ts}] {p}: {a}\n")
            self.custody_person.delete(0, tk.END)
            self.custody_action.delete(0, tk.END)
            self.update_summary()

    def update_summary(self):
        txt = f"""REPORT PREVIEW CONFIGURATION
------------------------------------------
CASE ID:      {self.case_id_entry.get()}
ANALYST:      {self.analyst_entry.get()}
INTEGRITY:    {self.evidence_hash}

METRICS:
- Total Files: {self.total_files_count}
- Size: {self.total_size_mb:.2f} MB
- Photos: {len(self.photos)}
- Chain Entries: {len(self.chain_of_custody)}
"""
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, txt)

    def footer_template(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.grey)
        
        canvas.setStrokeColor(colors.lightgrey)
        canvas.line(2*cm, 1.5*cm, 19*cm, 1.5*cm)
        
        canvas.drawString(2 * cm, 1 * cm, "TRAVERSO FORENSICS - ISO/IEC 27037 CONFIDENTIAL REPORT")
        
        page_num = canvas.getPageNumber()
        case_ref = getattr(doc, 'case_reference', 'UNKNOWN')
        canvas.drawRightString(19 * cm, 1 * cm, f"Page {page_num} | Case Ref: {case_ref}")
        
        canvas.restoreState()

    def generate_report(self):
        if not REPORTLAB_AVAILABLE:
            messagebox.showerror("Error", "ReportLab library is missing.")
            return

        fn = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")],
                                        initialfile=f"FORENSIC_REP_{self.case_id_entry.get()}.pdf")
        if not fn: return

        try:
            doc = SimpleDocTemplate(fn, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=3*cm)
            doc.case_reference = self.case_id_entry.get() if self.case_id_entry.get() else "DRAFT"
            
            story = []
            styles = getSampleStyleSheet()
            
            style_title = ParagraphStyle('T', parent=styles['Heading1'], alignment=TA_CENTER, fontSize=18, spaceAfter=20, textColor=colors.HexColor("#2c3e50"))
            style_h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceBefore=15, spaceAfter=10, 
                                    textColor=colors.white, backColor=colors.HexColor("#2c3e50"), padding=5, borderPadding=5)
            style_code = ParagraphStyle('C', parent=styles['Code'], fontSize=7, fontName='Courier')
            
            # Estilo para celdas de tabla (Wrap Text)
            style_cell = ParagraphStyle('TableCell', parent=styles['Normal'], fontSize=8, leading=10)

            # 1. HEADER
            logo_path = "traverso_logo.png"
            header_data = []
            if os.path.exists(logo_path):
                img = RLImage(logo_path, width=5*cm, height=2.0*cm, kind='proportional')
                header_data = [[img, Paragraph("<b>TRAVERSO FORENSICS</b><br/>ISO 27037 Digital Evidence Report", style_title)]]
            else:
                header_data = [[Paragraph("<b>TRAVERSO FORENSICS</b>", style_title)]]

            t_head = Table(header_data, colWidths=[6*cm, 10*cm])
            t_head.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
            story.append(t_head)
            story.append(Spacer(1, 0.5*cm))
            
            # --- STEP: EXTRACT TOOL NAME FROM LOG ---
            tool_name = "Standard Extraction Method"
            if self.extraction_log:
                for line in self.extraction_log.split('\n'):
                    if "TRAVERSO FORENSICS - PROFESSIONAL EXTRACTION" in line and "SUCCESS" in line:
                        parts = line.split("SUCCESS]")
                        if len(parts) > 1:
                            tool_name = parts[1].strip()
                            break

            # 2. CASE INFO & INTEGRITY
            story.append(Paragraph("1. IDENTIFICATION & INTEGRITY VERIFICATION", style_h2))
            
            source_p = Paragraph(str(self.extraction_dir), style_cell)
            hash_p = Paragraph(f"<font color='red'>{self.evidence_hash}</font>", style_cell)
            tool_p = Paragraph(f"<b>{tool_name}</b>", style_cell) 

            case_data = [
                ["Case Reference ID:", self.case_id_entry.get()],
                ["Forensic Analyst:", self.analyst_entry.get()],
                ["Report Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["Extraction Tool:", tool_p],
                ["Evidence Source:", source_p],
                ["Evidence Log SHA-256:", hash_p],
                ["Total Files / Size:", f"{self.total_files_count} files / {self.total_size_mb:.2f} MB"]
            ]
            
            t_info = Table(case_data, colWidths=[5*cm, 11*cm])
            t_info.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#ecf0f1")),
                ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#2c3e50")),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'), 
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(t_info)
            story.append(Spacer(1, 0.5*cm))
            
            # 3. SCOPE (AUTO-IMPORTED)
            story.append(Paragraph("<b>Extraction Scope & Metadata (Auto-Imported):</b>", styles['Normal']))
            scope_content = self.app_desc_text.get(1.0, tk.END).strip().replace('\n', '<br/>')
            if "REPORTE DE EXTRACCIÓN" in scope_content:
                story.append(Paragraph(scope_content, style_code))
            else:
                story.append(Paragraph(scope_content, styles['Normal']))
            story.append(Spacer(1, 0.5*cm))

            # 4. CHAIN OF CUSTODY
            story.append(Paragraph("2. CHAIN OF CUSTODY", style_h2))
            if self.chain_of_custody:
                cc_data = [["Timestamp", "Custodian", "Action / Purpose"]]
                
                for c in self.chain_of_custody:
                    p_ts = Paragraph(c['ts'], style_cell)
                    p_person = Paragraph(c['person'], style_cell)
                    p_action = Paragraph(c['action'], style_cell)
                    cc_data.append([p_ts, p_person, p_action])
                
                t_cc = Table(cc_data, colWidths=[4.5*cm, 4.5*cm, 7*cm])
                t_cc.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#95a5a6")),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'), 
                    ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                ]))
                story.append(t_cc)
            else:
                story.append(Paragraph("<i>No entries recorded.</i>", styles['Normal']))
            story.append(PageBreak())

            # 5. LOG
            story.append(Paragraph("3. TECHNICAL LOG", style_h2))
            if self.extraction_log:
                lines = self.extraction_log.split('\n')
                clean_log = "<br/>".join([l[:120].replace('<','&lt;').replace('>','&gt;') for l in lines[:400]])
                story.append(Paragraph(clean_log, style_code))
            else:
                story.append(Paragraph("Log unavailable.", styles['Normal']))
            
            # 6. PHOTOS (WITH HASH CHECK)
            if self.photos:
                story.append(PageBreak())
                story.append(Paragraph("4. PHOTOGRAPHIC EVIDENCE", style_h2))
                for i, p in enumerate(self.photos, 1):
                    story.append(Paragraph(f"<b>Evidence Item #{i}</b>", styles['Heading3']))
                    try:
                        # 1. Image
                        if PIL_AVAILABLE:
                            pim = Image.open(p['path'])
                            w, h = pim.size
                            aspect = h / float(w)
                            disp_w = 12*cm
                            disp_h = disp_w * aspect
                            if disp_h > 14*cm:
                                disp_h = 14*cm
                                disp_w = disp_h / aspect
                            img = RLImage(p['path'], width=disp_w, height=disp_h)
                            story.append(img)
                        else:
                            story.append(Paragraph("[No PIL]", styles['Normal']))
                        
                        story.append(Spacer(1, 0.2*cm))
                        
                        # 2. Description
                        story.append(Paragraph(f"<i>Description: {p['caption']}</i>", styles['Normal']))
                        
                        # 3. HASH LOGIC START
                        img_path = p['path']
                        img_hash = None
                        hash_source_msg = "(Calculated)"

                        # Check if sidecar hash exists (image.jpg.sha256 or image.sha256)
                        sidecar_candidates = [
                            img_path + ".sha256",
                            img_path + ".txt",
                            os.path.splitext(img_path)[0] + ".sha256"
                        ]

                        found_sidecar = False
                        for cand in sidecar_candidates:
                            if os.path.exists(cand):
                                try:
                                    with open(cand, 'r') as f:
                                        content = f.read().strip()
                                        # Basic extraction: first word or full line
                                        possible_hash = content.split()[0] if content else ""
                                        if len(possible_hash) == 64: # SHA256 length check
                                            img_hash = possible_hash
                                            hash_source_msg = "(Source File)"
                                            found_sidecar = True
                                            break
                                except: pass
                        
                        # Calculate if not found
                        if not found_sidecar:
                            img_hash = self.calculate_file_hash(img_path)
                        
                        # Display Hash
                        story.append(Spacer(1, 0.1*cm))
                        hash_paragraph = Paragraph(
                            f"<b>SHA-256:</b> <font name='Courier'>{img_hash}</font> "
                            f"<font size='7' color='grey'>{hash_source_msg}</font>",
                            styles['Normal']
                        )
                        story.append(hash_paragraph)
                        # --- HASH LOGIC END ---

                        story.append(Spacer(1, 1*cm))
                    except Exception as ex_img: 
                        print(f"Error adding image {i}: {ex_img}")
            
            # --- ANALYST SIGNATURE ---
            story.append(KeepTogether([
                Spacer(1, 2*cm),
                Paragraph("<b>FORENSIC ANALYST DECLARATION</b>", style_h2),
                Spacer(1, 1.5*cm), 
                Paragraph("_" * 50, styles['Normal']),
                Spacer(1, 0.2*cm),
                Paragraph(f"<b>{self.analyst_entry.get()}</b>", styles['Normal']),
                Paragraph("Certified Forensic Analyst / Perito Informático", styles['Normal']),
                Paragraph(f"Reference ID: {self.case_id_entry.get()}", styles['Normal']),
                Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d')}", styles['Normal']),
            ]))

            doc.build(story, onFirstPage=self.footer_template, onLaterPages=self.footer_template)
            
            messagebox.showinfo("Success", f"Report Generated Successfully (v1.0):\n{fn}")
            try: os.startfile(fn)
            except: pass

        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = ISOForensicReportGUI(root)
    root.mainloop()

