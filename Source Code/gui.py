import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import os
import logic
import threading
import queue
import logging
import tempfile
import shutil

try:
    import config
except ImportError:
    config = None

logger = logging.getLogger(__name__)

class MetadataInspectorGUI:
    
    def __init__(self, master):
        self.master = master
        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(1, weight=1)

        self.filename = None
        self.temp_filepath = None
        self.original_filename_for_display = "N/A"
        self.analysis_result = {}
        
        if config and hasattr(config, 'VIRUSTOTAL_API_KEY'):
            self.virustotal_api_key = config.VIRUSTOTAL_API_KEY
            max_size_mb = getattr(config, 'MAX_FILE_SIZE', 100 * 1024 * 1024) / (1024 * 1024)
            logger.info(f"Configuration loaded successfully. Max file size: {max_size_mb:.0f} MB")
        else:
            self.virustotal_api_key = "YOUR_NEW_API_KEY_GOES_HERE"
            logger.warning("No config.py found - using default settings")
        
        self.scan_queue = queue.Queue()
        
        self._setup_styles()
        self.setup_widgets()
        
        logger.info("Application initialized successfully")
        
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)


    def _setup_styles(self):
        self.style = ttk.Style(self.master)
        
        import platform
        if platform.system() == 'Windows':
            theme_name = 'vista'
            logger.info("Using 'vista' theme for Windows")
        elif platform.system() == 'Darwin':
            theme_name = 'aqua'
            logger.info("Using 'aqua' theme for macOS")
        else:
            theme_name = 'clam'
            logger.info(f"Using 'clam' theme for {platform.system()}")
        
        try:
            self.style.theme_use(theme_name)
        except tk.TclError:
            logger.warning(f"Theme '{theme_name}' not available, using default")
            self.style.theme_use('default')
        
        self.style.configure("Status.High.TFrame", background="#C00000")
        self.style.configure("Status.High.TLabel", background="#C00000", foreground="white", font=("Arial", 16, "bold"))
        self.style.configure("Status.Low.TFrame", background="#008000")
        self.style.configure("Status.Low.TLabel", background="#008000", foreground="white", font=("Arial", 16, "bold"))
        self.style.configure("Status.Default.TFrame", background="#F0F0F0")
        self.style.configure("Status.Default.TLabel", background="#F0F0F0", foreground="black", font=("Arial", 16, "bold"))

        self.style.configure("Check.Fail.TLabel", foreground="#C00000", font=("Arial", 10, "bold"))
        self.style.configure("Check.OK.TLabel", foreground="#008000", font=("Arial", 10, "bold"))
        self.style.configure("Check.Warn.TLabel", foreground="#E89B00", font=("Arial", 10, "bold"))

        self.style.configure("Header.TLabel", font=("Arial", 10, "bold"))
        self.style.configure("Data.TLabel", font=("Arial", 10))
        
        self.style.configure("ScanSafe.TLabel", foreground="#008000", font=("Arial", 10, "bold"))
        self.style.configure("ScanSuspicious.TLabel", foreground="#E89B00", font=("Arial", 10, "bold"))
        self.style.configure("ScanHighRisk.TLabel", foreground="#C00000", font=("Arial", 10, "bold"))
        self.style.configure("ScanError.TLabel", foreground="#C00000", font=("Arial", 10, "bold"))
        self.style.configure("ScanDefault.TLabel", font=("Arial", 10, "bold"))
        self.style.configure("ScanDetails.TLabel", font=("Consolas", 9), foreground="#333333")

    def setup_widgets(self):
        self._setup_button_bar()
        
        content_frame = ttk.Frame(self.master, padding=(10, 0))
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.columnconfigure(1, weight=3)
        content_frame.columnconfigure(0, weight=2)
        content_frame.rowconfigure(0, weight=1)

        self._setup_left_panel(content_frame)
        self._setup_right_panel(content_frame)

    def _setup_button_bar(self):
        button_frame = ttk.Frame(self.master, padding=(10, 10))
        button_frame.grid(row=0, column=0, sticky="ew")
        
        button_frame.columnconfigure(0, weight=1)
        button_frame_inner = ttk.Frame(button_frame)
        button_frame_inner.grid(row=0, column=0)
        
        self.import_btn = ttk.Button(button_frame_inner, text="Import File", command=self.import_file)
        self.import_btn.grid(row=0, column=0, padx=5, pady=5)
        
        self.remove_btn = ttk.Button(button_frame_inner, text="Remove Metadata", command=self.confirm_remove_metadata, state=tk.DISABLED)
        self.remove_btn.grid(row=0, column=1, padx=5, pady=5)
        
        self.fix_btn = ttk.Button(button_frame_inner, text="Fix Extension", command=self.confirm_fix_extension, state=tk.DISABLED)
        self.fix_btn.grid(row=0, column=2, padx=5, pady=5)
        
        self.export_btn = ttk.Button(button_frame_inner, text="Export Safe File...", command=self.export_file, state=tk.DISABLED)
        self.export_btn.grid(row=0, column=3, padx=5, pady=5)
        
        self.scan_btn = ttk.Button(button_frame_inner, text="Scan with VirusTotal", command=self.scan_file_threaded, state=tk.DISABLED)
        self.scan_btn.grid(row=0, column=4, padx=5, pady=5)

    def _setup_left_panel(self, parent_frame):
        left_panel = ttk.Frame(parent_frame, padding=(0, 0, 10, 0))
        left_panel.grid(row=0, column=0, sticky="nsew")
        left_panel.rowconfigure(1, weight=1)
        left_panel.columnconfigure(0, weight=1)
        
        file_info_frame = ttk.LabelFrame(left_panel, text="File Information", padding=(10, 10))
        file_info_frame.grid(row=0, column=0, sticky="ew")
        file_info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_info_frame, text="File:", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.lbl_file = ttk.Label(file_info_frame, text="N/A", style="Data.TLabel", anchor="w")
        self.lbl_file.grid(row=0, column=1, sticky="ew", padx=5)
        
        ttk.Label(file_info_frame, text="Size:", style="Header.TLabel").grid(row=1, column=0, sticky="w")
        self.lbl_size = ttk.Label(file_info_frame, text="N/A", style="Data.TLabel", anchor="w")
        self.lbl_size.grid(row=1, column=1, sticky="ew", padx=5)
        
        ttk.Label(file_info_frame, text="MIME Type:", style="Header.TLabel").grid(row=2, column=0, sticky="w")
        self.lbl_mime = ttk.Label(file_info_frame, text="N/A", style="Data.TLabel", anchor="w")
        self.lbl_mime.grid(row=2, column=1, sticky="ew", padx=5)
        
        ttk.Label(file_info_frame, text="Real Extension:", style="Header.TLabel").grid(row=3, column=0, sticky="w")
        self.lbl_ext = ttk.Label(file_info_frame, text="N/A", style="Data.TLabel", anchor="w")
        self.lbl_ext.grid(row=3, column=1, sticky="ew", padx=5)

        metadata_frame = ttk.LabelFrame(left_panel, text="Metadata", padding=(10, 10))
        metadata_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        metadata_frame.rowconfigure(0, weight=1)
        metadata_frame.columnconfigure(0, weight=1)
        
        self.info_box = scrolledtext.ScrolledText(metadata_frame, width=50, height=10, state=tk.DISABLED, font=("Consolas", 9))
        self.info_box.grid(row=0, column=0, sticky="nsew")
        
    def _setup_right_panel(self, parent_frame):
        right_panel = ttk.LabelFrame(parent_frame, text="Analysis Dashboard", padding=(10, 10))
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.columnconfigure(0, weight=1)
        
        self.status_frame = ttk.Frame(right_panel, style="Status.Default.TFrame", padding=(10, 10))
        self.status_frame.grid(row=0, column=0, sticky="ew")
        self.status_frame.columnconfigure(0, weight=1)
        self.lbl_threat = ttk.Label(self.status_frame, text="STATUS: N/A", style="Status.Default.TLabel", anchor="center")
        self.lbl_threat.grid(row=0, column=0, sticky="ew")
        
        reasons_frame = ttk.Frame(right_panel, padding=(0, 10))
        reasons_frame.grid(row=1, column=0, sticky="ew")
        reasons_frame.columnconfigure(0, weight=1)
        
        ttk.Label(reasons_frame, text="Internal Checks:", style="Header.TLabel").grid(row=0, column=0, sticky="w", pady=(0,5))
        self.lbl_mismatch_check = ttk.Label(reasons_frame, text="[?] File Type", style="Data.TLabel")
        self.lbl_mismatch_check.grid(row=1, column=0, sticky="w", padx=10)
        self.lbl_macro_check = ttk.Label(reasons_frame, text="[?] Macros", style="Data.TLabel")
        self.lbl_macro_check.grid(row=2, column=0, sticky="w", padx=10)
        self.lbl_metadata_check = ttk.Label(reasons_frame, text="[?] Metadata", style="Data.TLabel")
        self.lbl_metadata_check.grid(row=3, column=0, sticky="w", padx=10)
        
        ttk.Separator(right_panel, orient="horizontal").grid(row=2, column=0, sticky="ew", pady=10)

        vt_frame = ttk.Frame(right_panel)
        vt_frame.grid(row=3, column=0, sticky="ew")
        vt_frame.columnconfigure(0, weight=1)
        
        ttk.Label(vt_frame, text="External Scan (VirusTotal):", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.lbl_scan = ttk.Label(vt_frame, text="Not scanned", style="ScanDefault.TLabel")
        self.lbl_scan.grid(row=1, column=0, sticky="w", padx=10)
        
        self.scan_progressbar = ttk.Progressbar(vt_frame, mode='indeterminate')
        self.scan_progressbar.grid(row=2, column=0, sticky="ew", pady=5, padx=10)
        self.scan_progressbar.grid_remove()
        
        self.lbl_scan_details_header = ttk.Label(vt_frame, text="", style="ScanDefault.TLabel")
        self.lbl_scan_details_header.grid(row=3, column=0, sticky="w", pady=(0, 0), padx=10)
        
        self.lbl_scan_details = ttk.Label(vt_frame, text="", style="ScanDetails.TLabel", justify=tk.LEFT)
        self.lbl_scan_details.grid(row=4, column=0, sticky="w", pady=(0, 5), padx=10)

    def on_close(self):
        self.cleanup_temp_file()
        self.master.destroy()

    def cleanup_temp_file(self):
        try:
            if self.temp_filepath and os.path.exists(self.temp_filepath):
                os.remove(self.temp_filepath)
                logger.info(f"Cleaned up temporary file: {self.temp_filepath}")
                self.temp_filepath = None
        except Exception as e:
            logger.warning(f"Could not delete temp file: {e}")

    def import_file(self):
        original_path = filedialog.askopenfilename(title="Select file")
        if not original_path:
            return
        
        logger.info(f"Importing file: {original_path}")

        try:
            file_size = os.path.getsize(original_path)
            max_size = getattr(config, 'MAX_FILE_SIZE', 100 * 1024 * 1024) if config else 100 * 1024 * 1024
            
            if file_size > max_size:
                size_mb = file_size / (1024 * 1024)
                limit_mb = max_size / (1024 * 1024)
                
                logger.warning(f"File rejected: size {size_mb:.1f} MB exceeds limit of {limit_mb:.0f} MB")
                
                messagebox.showerror(
                    "File Too Large",
                    f"File size: {size_mb:.1f} MB\n"
                    f"Maximum allowed: {limit_mb:.0f} MB\n\n"
                    f"This file is too large to analyze safely.\n"
                    f"Please select a smaller file.\n\n"
                    f"Tip: You can adjust MAX_FILE_SIZE in config.py"
                )
                return
        except OSError as e:
            logger.error(f"Could not check file size: {e}")
            messagebox.showerror("Error", f"Could not check file size:\n{e}")
            return

        try:
            self.cleanup_temp_file()

            original_suffix = os.path.splitext(original_path)[1]
            temp_fd, self.temp_filepath = tempfile.mkstemp(suffix=original_suffix)
            os.close(temp_fd)

            shutil.copy2(original_path, self.temp_filepath)

            self.filename = self.temp_filepath
            self.original_filename_for_display = os.path.basename(original_path)
            
            logger.info(f"Analyzing file: {self.temp_filepath}")

            self.export_btn.config(state=tk.DISABLED)
            self.scan_btn.config(state=tk.DISABLED)
            self.remove_btn.config(state=tk.DISABLED)
            self.fix_btn.config(state=tk.DISABLED)
            
            self.lbl_mismatch_check.config(text="[?] File Type", style="Data.TLabel")
            self.lbl_macro_check.config(text="[?] Macros", style="Data.TLabel")
            self.lbl_metadata_check.config(text="[?] Metadata", style="Data.TLabel")
            self.status_frame.config(style="Status.Default.TFrame")
            self.lbl_threat.config(text="STATUS: N/A", style="Status.Default.TLabel")

            self.analyze_file()
            
            self.lbl_scan.config(text="Not scanned", style="ScanDefault.TLabel")
            self.lbl_scan_details_header.config(text="")
            self.lbl_scan_details.config(text="")
            
        except Exception as e:
            logger.error(f"Failed to import file: {e}", exc_info=True)
            messagebox.showerror("Import Failed", f"Could not create a temporary copy of the file:\n{e}")
            self.filename = None
            self.temp_filepath = None

    def analyze_file(self):
        if not self.filename:
            return
        
        self.analysis_result = logic.analyze_file(self.filename)
        
        logger.info("File analysis completed successfully")
        
        self.display_info()
        
        self.export_btn.config(state=tk.NORMAL)
        self.scan_btn.config(state=tk.NORMAL)
        self.remove_btn.config(state=tk.NORMAL)

    def has_sensitive_metadata(self, metadata_str):
        if not metadata_str or metadata_str == "No metadata found.":
            return False
        
        safe_fields = ['created', 'modified', 'content_status', 'version', 'revision', 'language']
        
        lines = metadata_str.strip().split('\n')
        
        for line in lines:
            if ':' not in line:
                continue
            
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            if key.lower() in safe_fields:
                continue
            
            if not value or value == 'None' or value == '':
                continue
            
            return True
        
        return False
    
    def display_info(self):
        if not self.analysis_result:
            return

        self.lbl_file.config(text=self.original_filename_for_display)
        self.lbl_size.config(text=f"{self.analysis_result['file_size']} bytes")
        self.lbl_mime.config(text=self.analysis_result['real_mime_type'])
        self.lbl_ext.config(text=self.analysis_result['real_extension'])
        
        self.info_box.config(state=tk.NORMAL)
        self.info_box.delete(1.0, tk.END)
        self.info_box.insert(tk.END, self.analysis_result['metadata'])
        self.info_box.config(state=tk.DISABLED)
        
        level = self.analysis_result['threat_level']
        macro_found = self.analysis_result['macro_found']
        mismatch = self.analysis_result['extension_mismatch']
        metadata_str = self.analysis_result['metadata']
        metadata_found = self.has_sensitive_metadata(metadata_str)

        if level == "High":
            self.status_frame.config(style="Status.High.TFrame")
            self.lbl_threat.config(text="STATUS: HIGH RISK", style="Status.High.TLabel")
        else:
            self.status_frame.config(style="Status.Low.TFrame")
            self.lbl_threat.config(text="STATUS: LOW RISK", style="Status.Low.TLabel")
            
        if mismatch:
            self.lbl_mismatch_check.config(text="✗ File Type Mismatch (High Risk)", style="Check.Fail.TLabel")
            self.fix_btn.config(state=tk.NORMAL)
        else:
            self.lbl_mismatch_check.config(text="✓ File Type Match (Safe)", style="Check.OK.TLabel")
            self.fix_btn.config(state=tk.DISABLED)
            
        if macro_found:
            self.lbl_macro_check.config(text="✗ Macros Detected! (High Risk)", style="Check.Fail.TLabel")
        else:
            self.lbl_macro_check.config(text="✓ No Macros Found (Safe)", style="Check.OK.TLabel")
            
        if metadata_found:
            self.lbl_metadata_check.config(text="! Metadata Found (Privacy Risk)", style="Check.Warn.TLabel")
        else:
            self.lbl_metadata_check.config(text="✓ No Metadata Found (Safe)", style="Check.OK.TLabel")

    def confirm_remove_metadata(self):
        if not self.filename: return
        
        if not (self.analysis_result['metadata'] and self.analysis_result['metadata'] != "No metadata found."):
             messagebox.showinfo("Remove Metadata", "No metadata was found to remove.")
             return
             
        warning_title = "Confirm Metadata Removal"
        warning_msg = (
            "This will remove metadata from the imported file.\n"
            "Your *original* file will not be changed.\n\n"
            "Are you sure you want to continue?"
        )
        if messagebox.askyesno(warning_title, warning_msg):
            self.remove_metadata_in_place()

    def remove_metadata_in_place(self):
        try:
            success, msg = logic.remove_metadata_in_place(self.filename)
            
            if success:
                messagebox.showinfo("Remove Metadata", f"Successfully removed metadata from temp file!\n({msg})")
                self.analyze_file()
            else:
                messagebox.showerror("Remove Metadata Failed", msg)
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    
    def confirm_fix_extension(self):
        if not self.filename: return
        
        current_ext = self.analysis_result['current_extension']
        real_ext = self.analysis_result['real_extension']
        
        warning_title = "Confirm File Rename"
        warning_msg = (
            f"This will correct the temp file's extension from '{current_ext}' to '{real_ext}'.\n"
            "Your *original* file will not be changed.\n\n"
            "Are you sure you want to continue?"
        )
        if messagebox.askyesno(warning_title, warning_msg):
            self.fix_extension_in_place()

    def fix_extension_in_place(self):
        try:
            success, msg, new_filepath = logic.fix_extension_in_place(self.filename)
            
            if success:
                messagebox.showinfo("File Renamed", msg)
                self.filename = new_filepath
                self.temp_filepath = new_filepath
                self.analyze_file()
            else:
                messagebox.showerror("Failed to Rename", msg)
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def export_file(self):
        if not self.filename: return
        
        threat_level = self.analysis_result.get("threat_level", "Low")
        real_ext = self.analysis_result.get("real_extension")
        
        base_name_no_ext = os.path.splitext(self.original_filename_for_display)[0]
        final_ext = real_ext or os.path.splitext(self.filename)[1]
        
        prefix = "SAFE_" if threat_level == "Low" else "HIGH_RISK_"
        sanitized_base_name = logic.sanitize_filename(base_name_no_ext)
        default_name = prefix + sanitized_base_name + final_ext
        
        save_path = filedialog.asksaveasfilename(
            defaultextension=final_ext,
            initialfile=default_name,
            filetypes=[(f"Detected Type (*{final_ext})", f"*{final_ext}"), ("All Files", "*.*")]
        )
        
        if save_path:
            success, msg = logic.export_safe_file(self.filename, save_path, threat_level, None)
            if success:
                messagebox.showinfo("Export", msg)
            else:
                messagebox.showerror("Export Failed", msg)

    def scan_file_threaded(self):
        key = (self.virustotal_api_key or "").strip()
        if (not key or "YOUR_NEW_API_KEY_GOES_HERE" in key or
            "YOUR_API_KEY_HERE" in key):
            messagebox.showerror(
                "VirusTotal API Key Required", 
                "Please add your VirusTotal API key to config.py\n\n"
                "Steps:\n"
                "1. Get a free API key from virustotal.com\n"
                "2. Open config.py\n"
                "3. Add your API key\n"
                "4. Save and restart the application"
            )
            return
            
        if not messagebox.askyesno("Privacy Warning",
            "This will upload your file to VirusTotal for analysis.\n"
            "Uploaded files can be seen by VirusTotal and its partners.\n"
            "Everything else in this app runs only on your computer.\n\n"
            "Do you want to continue?"):
            return

        # Importing another file during a scan would delete the temp file
        # that is being uploaded, so the buttons stay off until it finishes.
        self.set_action_buttons(tk.DISABLED)
        self.scan_progressbar.grid()
        self.scan_progressbar.start()
        self.lbl_scan.config(text="Submitting file...", style="ScanDefault.TLabel")
        self.lbl_scan_details_header.config(text="")
        self.lbl_scan_details.config(text="")
        
        self.scan_thread = threading.Thread(target=self._thread_scan_wrapper)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        self.check_scan_queue()

    def set_action_buttons(self, state):
        for btn in (self.import_btn, self.remove_btn, self.export_btn, self.scan_btn):
            btn.config(state=state)
        if state == tk.NORMAL and self.analysis_result.get('extension_mismatch'):
            self.fix_btn.config(state=tk.NORMAL)
        else:
            self.fix_btn.config(state=tk.DISABLED)

    def _thread_scan_wrapper(self):
        try:
            result = logic.scan_with_virustotal(self.filename, self.virustotal_api_key)
            self.scan_queue.put(result)
        except Exception as e:
            self.scan_queue.put({"status": "Error", "message": f"Scan Error: {e}", "details": ""})

    def check_scan_queue(self):
        try:
            result_dict = self.scan_queue.get(block=False)
            
            self.scan_progressbar.stop()
            self.scan_progressbar.grid_remove()
            self.set_action_buttons(tk.NORMAL)

            status = result_dict.get("status", "Error")
            message = result_dict.get("message", "An unknown error occurred.")
            details = result_dict.get("details", "")
            
            self.lbl_scan.config(text=f"{message}")
            self.lbl_scan.config(style=f"Scan{status}.TLabel")
            
            if details:
                self.lbl_scan_details_header.config(text="Detections:", style="Header.TLabel")
                self.lbl_scan_details.config(text=details)
            else:
                self.lbl_scan_details_header.config(text="")
                self.lbl_scan_details.config(text="")

            if status == "HighRisk" or status == "Suspicious":
                self.status_frame.config(style="Status.High.TFrame")
                self.lbl_threat.config(text="STATUS: HIGH RISK", style="Status.High.TLabel")
            
        except queue.Empty:
            if self.scan_thread.is_alive():
                 self.lbl_scan.config(text="Scanning in progress...", style="ScanDefault.TLabel")
            self.master.after(200, self.check_scan_queue)
