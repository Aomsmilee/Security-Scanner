import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import threading
import datetime
import pyperclip
import scanner_api

# ===== ตั้งค่า =====
VT_API_KEY = 'VIRUSTOTAL_API_KEY'

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ===== สีและ Font =====
COLOR_BG        = "#F5F7FA"
COLOR_CARD      = "#FFFFFF"
COLOR_PRIMARY   = "#2563EB"
COLOR_ACCENT    = "#DBEAFE"
COLOR_BORDER    = "#E2E8F0"
COLOR_TEXT      = "#1E293B"
COLOR_SUBTEXT   = "#64748B"
COLOR_SUCCESS   = "#16A34A"
COLOR_DANGER    = "#DC2626"
COLOR_WARNING   = "#D97706"

class SentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Security Scanner")
        self.geometry("860x720")
        self.resizable(False, False)
        self.configure(fg_color=COLOR_BG)

        self.history = []
        self._build_ui()

    def _build_ui(self):
        # ===== Header =====
        header = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=64,
                              border_width=1, border_color=COLOR_BORDER)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="🛡 Security Scanner", font=ctk.CTkFont(family="Georgia", size=22, weight="bold"),
                     text_color=COLOR_PRIMARY).place(x=28, y=14)

        # ===== Tab =====
        self.tab_var = tk.StringVar(value="file")
        tab_frame = ctk.CTkFrame(self, fg_color=COLOR_BG)
        tab_frame.pack(pady=(20, 0), padx=28, fill="x")

        tabs = [
            ("📁  Scan Files", "file"),
            ("🔗  Scan Link", "url"),
            ("#  Scan Hash", "hash"),
            ("🔐  Check for Hash matching", "verify"),
            ("🕒  history", "history")
        ]
        for label, val in tabs:
            btn = ctk.CTkButton(tab_frame, text=label, width=140, height=36,
                                corner_radius=8, font=ctk.CTkFont(size=12),
                                fg_color=COLOR_PRIMARY if self.tab_var.get() == val else COLOR_CARD,
                                text_color="white" if self.tab_var.get() == val else COLOR_TEXT,
                                hover_color="#1D4ED8",
                                border_width=1, border_color=COLOR_BORDER,
                                command=lambda v=val: self._switch_tab(v))
            btn.pack(side="left", padx=(0, 6))
            setattr(self, f"tab_btn_{val}", btn)

        # ===== Content Area =====
        self.content = ctk.CTkFrame(self, fg_color=COLOR_BG)
        self.content.pack(fill="both", expand=True, padx=28, pady=16)

        self._show_file_tab()

    def _switch_tab(self, tab):
        self.tab_var.set(tab)
        for v in ["file", "url", "hash", "verify", "history"]:
            btn = getattr(self, f"tab_btn_{v}", None)
            if btn:
                btn.configure(fg_color=COLOR_PRIMARY if v == tab else COLOR_CARD,
                              text_color="white" if v == tab else COLOR_TEXT)

        for w in self.content.winfo_children():
            w.destroy()

        {
            "file": self._show_file_tab,
            "url": self._show_url_tab,
            "hash": self._show_hash_tab,
            "verify": self._show_verify_tab,
            "history": self._show_history_tab
        }[tab]()

    # ========== TAB: FILE ==========
    def _show_file_tab(self):
        card = self._card(self.content)

        ctk.CTkLabel(card, text="Upload files for scanning",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(card, text="The system calculates the SHA-256 hash and verifies it against the VirusTotal database",
                     font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", pady=(0, 20))

        self.file_label = ctk.CTkLabel(card, text="No file selected",
                                       font=ctk.CTkFont(size=13), text_color=COLOR_SUBTEXT)
        self.file_label.pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(anchor="w")
        ctk.CTkButton(btn_row, text="📂  Select file", width=140, height=38,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_ACCENT, text_color=COLOR_PRIMARY,
                      hover_color="#BFDBFE",
                      command=self._browse_file).pack(side="left", padx=(0, 12))
        ctk.CTkButton(btn_row, text="🔍  Scan", width=120, height=38,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_PRIMARY, text_color="white",
                      hover_color="#1D4ED8",
                      command=self._scan_file).pack(side="left")

        self.file_result = self._result_box(card)
        self.selected_file = None

    def _browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            self.file_label.configure(text=f"✅  {path.split('/')[-1]}", text_color=COLOR_PRIMARY)

    def _scan_file(self):
        if not self.selected_file:
            self._show_result(self.file_result, "⚠️ Please select a file", "warning")
            return
        self._show_result(self.file_result, "⏳ Scanning...", "info")
        threading.Thread(target=self._do_scan_file, daemon=True).start()

    def _do_scan_file(self):
        try:
            with open(self.selected_file, "rb") as f:
                file_bytes = f.read()
            file_hash = scanner_api.calculate_hash(file_bytes)
            result = scanner_api.check_virustotal_file(file_hash, VT_API_KEY)
            name = self.selected_file.split("/")[-1]
            self._add_history("file", name, result)
            self.after(0, lambda: self._show_result(self.file_result, result))
        except Exception as e:
            self.after(0, lambda: self._show_result(self.file_result, f"❌ Something went wrong: {e}", "danger"))

    # ========== TAB: URL ==========
    def _show_url_tab(self):
        card = self._card(self.content)

        ctk.CTkLabel(card, text="Scan the link (URL)",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(card, text="Paste the link you want to scan below",
                     font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", pady=(0, 16))

        self.url_var = tk.StringVar()
        entry_row = ctk.CTkFrame(card, fg_color="transparent")
        entry_row.pack(fill="x", pady=(0, 12))

        self.url_entry = ctk.CTkEntry(entry_row, textvariable=self.url_var,
                                      placeholder_text="https://example.com",
                                      height=42, corner_radius=8, font=ctk.CTkFont(size=13),
                                      border_color=COLOR_BORDER, fg_color=COLOR_BG)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(entry_row, text="📋 Paste", width=70, height=42,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_ACCENT, text_color=COLOR_PRIMARY,
                      hover_color="#BFDBFE",
                      command=lambda: self.url_var.set(pyperclip.paste())).pack(side="left")

        ctk.CTkButton(card, text="🔍  Scan Link", height=40,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_PRIMARY, text_color="white",
                      hover_color="#1D4ED8",
                      command=self._scan_url).pack(anchor="w")

        self.url_result = self._result_box(card)

    def _scan_url(self):
        url = self.url_var.get().strip()
        if not url:
            self._show_result(self.url_result, "⚠️ Please insert the link", "warning")
            return
        self._show_result(self.url_result, "⏳ Scanning...", "info")
        threading.Thread(target=self._do_scan_url, args=(url,), daemon=True).start()

    def _do_scan_url(self, url):
        try:
            result = scanner_api.check_virustotal_url(url, VT_API_KEY)
            self._add_history("URL", url, result)
            self.after(0, lambda: self._show_result(self.url_result, result))
        except Exception as e:
            self.after(0, lambda: self._show_result(self.url_result, f"❌ Something went wrong: {e}", "danger"))

    # ========== TAB: HASH ==========
    def _show_hash_tab(self):
        card = self._card(self.content)

        ctk.CTkLabel(card, text="Scan Hash (SHA-256)",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(card, text="Enter the SHA-256 hash of the file you want to scan",
                     font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", pady=(0, 16))

        self.hash_var = tk.StringVar()
        entry_row = ctk.CTkFrame(card, fg_color="transparent")
        entry_row.pack(fill="x", pady=(0, 12))

        self.hash_entry = ctk.CTkEntry(entry_row, textvariable=self.hash_var,
                                       placeholder_text="e3b0c44298fc1c149afbf4c8996fb924...",
                                       height=42, corner_radius=8, font=ctk.CTkFont(size=13),
                                       border_color=COLOR_BORDER, fg_color=COLOR_BG)
        self.hash_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(entry_row, text="📋 Paste", width=70, height=42,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_ACCENT, text_color=COLOR_PRIMARY,
                      hover_color="#BFDBFE",
                      command=lambda: self.hash_var.set(pyperclip.paste())).pack(side="left")

        ctk.CTkButton(card, text="🔍  Scan Hash", height=40,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_PRIMARY, text_color="white",
                      hover_color="#1D4ED8",
                      command=self._scan_hash).pack(anchor="w")

        self.hash_result = self._result_box(card)

    def _scan_hash(self):
        h = self.hash_var.get().strip()
        if not h:
            self._show_result(self.hash_result, "⚠️ Please enter the hash", "warning")
            return
        self._show_result(self.hash_result, "⏳ Scanning...", "info")
        threading.Thread(target=self._do_scan_hash, args=(h,), daemon=True).start()

    def _do_scan_hash(self, h):
        try:
            result = scanner_api.check_virustotal_file(h, VT_API_KEY)
            self._add_history("Hash", h[:20] + "...", result)
            self.after(0, lambda: self._show_result(self.hash_result, result))
        except Exception as e:
            self.after(0, lambda: self._show_result(self.hash_result, f"❌ Something went wrong: {e}", "danger"))

    # ========== TAB: VERIFY HASH ==========
    def _show_verify_tab(self):
        card = self._card(self.content)

        ctk.CTkLabel(card, text="Check for hash matching",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(card, text="Compare the original hash from the developer's website with the downloaded file to confirm that the file has not been modified",
                     font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", pady=(0, 16))

        # ช่องใส่ Hash ต้นฉบับ
        ctk.CTkLabel(card, text="Original Hash",
                     font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 6))

        self.verify_hash_var = tk.StringVar()
        entry_row = ctk.CTkFrame(card, fg_color="transparent")
        entry_row.pack(fill="x", pady=(0, 16))

        self.verify_hash_entry = ctk.CTkEntry(entry_row, textvariable=self.verify_hash_var,
                                              placeholder_text="Insert the original SHA-256 hash here",
                                              height=42, corner_radius=8, font=ctk.CTkFont(size=13),
                                              border_color=COLOR_BORDER, fg_color=COLOR_BG)
        self.verify_hash_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(entry_row, text="📋 Paste", width=70, height=42,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_ACCENT, text_color=COLOR_PRIMARY,
                      hover_color="#BFDBFE",
                      command=lambda: self.verify_hash_var.set(pyperclip.paste())).pack(side="left")

        # ปุ่มเลือกไฟล์
        ctk.CTkLabel(card, text="Downloaded file",
                     font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 6))

        self.verify_file_label = ctk.CTkLabel(card, text="No file selected",
                                              font=ctk.CTkFont(size=13), text_color=COLOR_SUBTEXT)
        self.verify_file_label.pack(anchor="w", pady=(0, 8))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(anchor="w")

        ctk.CTkButton(btn_row, text="📂  Select file", width=140, height=38,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_ACCENT, text_color=COLOR_PRIMARY,
                      hover_color="#BFDBFE",
                      command=self._browse_verify_file).pack(side="left", padx=(0, 12))

        ctk.CTkButton(btn_row, text="🔐  Check", width=130, height=38,
                      corner_radius=8, font=ctk.CTkFont(size=13),
                      fg_color=COLOR_PRIMARY, text_color="white",
                      hover_color="#1D4ED8",
                      command=self._do_verify).pack(side="left")

        # กล่องแสดงผล Hash ของไฟล์
        self.verify_hash_display = ctk.CTkLabel(card, text="",
                                                font=ctk.CTkFont(size=11), text_color=COLOR_SUBTEXT,
                                                wraplength=750)
        self.verify_hash_display.pack(anchor="w", pady=(12, 0))

        self.verify_result = self._result_box(card)
        self.verify_selected_file = None

    def _browse_verify_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.verify_selected_file = path
            self.verify_file_label.configure(text=f"✅  {path.split('/')[-1]}", text_color=COLOR_PRIMARY)

    def _do_verify(self):
        original_hash = self.verify_hash_var.get().strip()
        if not original_hash:
            self._show_result(self.verify_result, "⚠️ Please include the original hash", "warning")
            return
        if not self.verify_selected_file:
            self._show_result(self.verify_result, "⚠️ Please select a file", "warning")
            return
        self._show_result(self.verify_result, "⏳ Scanning...", "info")
        threading.Thread(target=self._run_verify, args=(original_hash,), daemon=True).start()

    def _run_verify(self, original_hash):
        try:
            with open(self.verify_selected_file, "rb") as f:
                file_bytes = f.read()
            match, file_hash = scanner_api.verify_hash(file_bytes, original_hash)
            name = self.verify_selected_file.split("/")[-1]

            if match:
                result = "✅ The Hash matches! The File has not been modified"
                self._add_history("ตรวจ Hash", name, result)
            else:
                result = "❌ Hash mismatch! The File may have been modified or corrupted"
                self._add_history("ตรวจ Hash", name, result)

            hash_text = f"File Hash: {file_hash}"
            self.after(0, lambda: self.verify_hash_display.configure(text=hash_text))
            self.after(0, lambda: self._show_result(self.verify_result, result))
        except Exception as e:
            self.after(0, lambda: self._show_result(self.verify_result, f"❌ Something went wrong: {e}", "danger"))

    # ========== TAB: HISTORY ==========
    def _show_history_tab(self):
        card = self._card(self.content)

        ctk.CTkLabel(card, text="Scan History",
                     font=ctk.CTkFont(size=15, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(card, text="Record all scans in this session",
                     font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", pady=(0, 16))

        scroll = ctk.CTkScrollableFrame(card, fg_color=COLOR_BG, corner_radius=8, height=360)
        scroll.pack(fill="both", expand=True)

        if not self.history:
            ctk.CTkLabel(scroll, text="No scan history yet",
                         font=ctk.CTkFont(size=13), text_color=COLOR_SUBTEXT).pack(pady=40)
        else:
            for item in reversed(self.history):
                row = ctk.CTkFrame(scroll, fg_color=COLOR_CARD, corner_radius=8,
                                   border_width=1, border_color=COLOR_BORDER)
                row.pack(fill="x", pady=(0, 8))
                ctk.CTkLabel(row, text=f"[{item['type']}]  {item['name']}",
                             font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_TEXT).pack(anchor="w", padx=14, pady=(10, 2))
                ctk.CTkLabel(row, text=item['result'],
                             font=ctk.CTkFont(size=12), text_color=COLOR_SUBTEXT).pack(anchor="w", padx=14)
                ctk.CTkLabel(row, text=item['time'],
                             font=ctk.CTkFont(size=11), text_color=COLOR_SUBTEXT).pack(anchor="w", padx=14, pady=(2, 10))

    # ========== Helper ==========
    def _card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12,
                            border_width=1, border_color=COLOR_BORDER)
        card.pack(fill="both", expand=True)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=28, pady=24)
        return inner

    def _result_box(self, parent):
        box = ctk.CTkFrame(parent, fg_color=COLOR_BG, corner_radius=8,
                           border_width=1, border_color=COLOR_BORDER, height=72)
        box.pack(fill="x", pady=(20, 0))
        box.pack_propagate(False)
        label = ctk.CTkLabel(box, text="The scan results will be displayed here",
                             font=ctk.CTkFont(size=13), text_color=COLOR_SUBTEXT)
        label.place(relx=0.5, rely=0.5, anchor="center")
        box._result_label = label
        return box

    def _show_result(self, box, text, kind=None):
        if kind is None:
            if "✅" in text:   kind = "success"
            elif "❌" in text: kind = "danger"
            elif "⚪" in text or "⚠️" in text: kind = "warning"
            else: kind = "info"

        colors = {
            "success": (COLOR_SUCCESS, "#DCFCE7", "#BBF7D0"),
            "danger":  (COLOR_DANGER,  "#FEE2E2", "#FECACA"),
            "warning": (COLOR_WARNING, "#FEF3C7", "#FDE68A"),
            "info":    (COLOR_SUBTEXT, COLOR_BG,  COLOR_BORDER),
        }
        text_color, bg, border = colors.get(kind, colors["info"])
        box.configure(fg_color=bg, border_color=border)
        box._result_label.configure(text=text, text_color=text_color,
                                    font=ctk.CTkFont(size=13, weight="bold"))

    def _add_history(self, scan_type, name, result):
        self.history.append({
            "type": scan_type,
            "name": name,
            "result": result,
            "time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        })


if __name__ == "__main__":
    app = SentinelApp()
    app.mainloop()