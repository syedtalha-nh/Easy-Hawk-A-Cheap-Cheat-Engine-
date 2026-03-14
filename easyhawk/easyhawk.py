"""
EasyHawk v2 - Easy Memory Scanner for Windows
Run as Administrator for full memory access.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import ctypes
import ctypes.wintypes
import struct
import sys
import subprocess

# ── Windows API ───────────────────────────────────────────────────────────────
if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PROCESS_ALL_ACCESS     = 0x1F0FFF
    MEM_COMMIT             = 0x1000
    PAGE_READWRITE         = 0x04
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_WRITECOPY         = 0x08
    PAGE_EXECUTE_WRITECOPY = 0x80
    WRITABLE_PAGES         = {PAGE_READWRITE, PAGE_EXECUTE_READWRITE,
                              PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress",       ctypes.c_ulonglong),
            ("AllocationBase",    ctypes.c_ulonglong),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("__align1",          ctypes.wintypes.DWORD),
            ("RegionSize",        ctypes.c_ulonglong),
            ("State",             ctypes.wintypes.DWORD),
            ("Protect",           ctypes.wintypes.DWORD),
            ("Type",              ctypes.wintypes.DWORD),
            ("__align2",          ctypes.wintypes.DWORD),
        ]

    def open_process(pid):
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
        return h if h else None

    def close_handle(h):
        if h: kernel32.CloseHandle(h)

    def read_bytes(h, addr, size):
        buf  = (ctypes.c_char * size)()
        done = ctypes.c_size_t(0)
        ok   = kernel32.ReadProcessMemory(
            h, ctypes.c_ulonglong(addr), buf, size, ctypes.byref(done))
        return bytes(buf[:done.value]) if ok else None

    def write_bytes(h, addr, data):
        done = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(
            h, ctypes.c_ulonglong(addr), data, len(data), ctypes.byref(done)))

    def vquery(h, addr):
        mbi  = MEMORY_BASIC_INFORMATION()
        ret  = kernel32.VirtualQueryEx(
            h, ctypes.c_ulonglong(addr),
            ctypes.byref(mbi), ctypes.sizeof(mbi))
        return mbi if ret else None

    def get_process_list():
        try:
            raw = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                creationflags=0x08000000
            ).decode("utf-8", errors="ignore")
            procs = []
            for line in raw.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    try:
                        procs.append((parts[0], int(parts[1])))
                    except ValueError:
                        pass
            return sorted(procs, key=lambda x: x[0].lower())
        except Exception:
            return []

else:
    WRITABLE_PAGES = set()
    MEM_COMMIT = 0x1000
    def open_process(pid):      return None
    def close_handle(h):        pass
    def read_bytes(h, a, s):    return None
    def write_bytes(h, a, d):   return False
    def vquery(h, a):           return None
    def get_process_list():     return []


# ── Value helpers ─────────────────────────────────────────────────────────────
TYPES = {
    "Integer (4 byte)": ("<i", 4),
    "Integer (8 byte)": ("<q", 8),
    "Float":            ("<f", 4),
    "Double":           ("<d", 8),
}

def to_bytes(vtype, val_str):
    fmt, sz = TYPES[vtype]
    try:
        v = float(val_str) if fmt in ("<f", "<d") else int(float(val_str))
        return struct.pack(fmt, v)
    except Exception:
        return None

def from_bytes(vtype, raw):
    fmt, sz = TYPES[vtype]
    if not raw or len(raw) < sz:
        return None
    try:
        v = struct.unpack(fmt, raw[:sz])[0]
        return round(v, 4) if fmt in ("<f", "<d") else int(v)
    except Exception:
        return None

def fmt_val(v):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)

def parse_num(s):
    try:
        return float(s) if '.' in s else int(s)
    except Exception:
        return None


# ── Color palette  ────────────────────────────────────────────────────────────
BG0    = "#0e1117"
BG1    = "#131a24"
BG2    = "#192030"
BG3    = "#1e2840"
BG4    = "#253050"

ACCENT = "#00c8ff"
GREEN  = "#00e676"
RED    = "#ff4444"
YELLOW = "#ffb300"

TEXT0  = "#ffffff"
TEXT1  = "#d0daea"
TEXT2  = "#6a7a9a"

BORDER = "#243050"

F_MAIN  = ("Segoe UI", 10)
F_BOLD  = ("Segoe UI", 10, "bold")
F_MONO  = ("Consolas", 11)
F_SMALL = ("Segoe UI",  9)
F_TITLE = ("Segoe UI", 15, "bold")
F_HEAD  = ("Segoe UI", 11, "bold")


# ── Main window ───────────────────────────────────────────────────────────────
class EasyHawk(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EasyHawk")
        self.geometry("1150x740")
        self.minsize(950, 620)
        self.configure(bg=BG0)

        self.pid     = None
        self.pname   = ""
        self.handle  = None
        self.results = []        # list of int addresses from latest scan
        self.prev_val= None      # numeric value used in the last scan
        self.saved   = []        # list of dicts
        self.freeze_jobs = {}
        self._all_procs  = []
        self._sav_uid    = 0

        self._apply_styles()
        self._build()
        self._load_processes()

    # ── ttk styles ────────────────────────────────────────────────────────────
    def _apply_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview",
            background=BG2, foreground=TEXT1, fieldbackground=BG2,
            borderwidth=0, font=F_MONO, rowheight=25,
            highlightthickness=0)
        s.configure("Treeview.Heading",
            background=BG1, foreground=TEXT2,
            borderwidth=0, relief="flat",
            font=("Segoe UI", 9, "bold"))
        s.map("Treeview",
            background=[("selected", ACCENT)],
            foreground=[("selected", "#000")])
        s.configure("TCombobox",
            fieldbackground=BG3, background=BG3,
            foreground=TEXT1, selectbackground=ACCENT,
            selectforeground="#000", arrowcolor=TEXT2)
        s.map("TCombobox",
            fieldbackground=[("readonly", BG3)],
            foreground=[("readonly", TEXT1)])

    # ── Build ─────────────────────────────────────────────────────────────────
    def _build(self):
        self._build_titlebar()
        body = tk.Frame(self, bg=BG0)
        body.pack(fill=tk.BOTH, expand=True)
        self._build_sidebar(body)
        self._build_right(body)
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self, bg=BG1, height=50)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)
        tk.Label(bar, text="🦅 EasyHawk", font=F_TITLE,
                 bg=BG1, fg=TEXT0).pack(side=tk.LEFT, padx=16)
        tk.Label(bar, text="Easy Memory Scanner", font=F_SMALL,
                 bg=BG1, fg=TEXT2).pack(side=tk.LEFT)
        self.badge = tk.Label(bar, text="  Not attached  ",
            font=("Segoe UI", 9, "bold"),
            bg=BG3, fg=TEXT2, padx=12, pady=4)
        self.badge.pack(side=tk.RIGHT, padx=16, pady=10)

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, bg=BG1, width=265)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        hdr = tk.Frame(side, bg=BG1)
        hdr.pack(fill=tk.X, padx=12, pady=(12, 6))
        tk.Label(hdr, text="Processes", font=F_HEAD,
                 bg=BG1, fg=TEXT0).pack(side=tk.LEFT)
        tk.Button(hdr, text="⟳ Refresh", font=F_SMALL,
                  bg=BG3, fg=ACCENT, relief="flat", bd=0,
                  cursor="hand2", padx=8, pady=3,
                  activebackground=BG4, activeforeground=ACCENT,
                  command=self._load_processes).pack(side=tk.RIGHT)

        # Search
        sf = tk.Frame(side, bg=BG3,
                      highlightbackground=BORDER, highlightthickness=1)
        sf.pack(fill=tk.X, padx=12, pady=(0, 6))
        tk.Label(sf, text="🔍", bg=BG3, fg=TEXT2,
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(8,2), pady=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *_: self._filter_procs())
        tk.Entry(sf, textvariable=self.search_var,
                 bg=BG3, fg=TEXT1, insertbackground=ACCENT,
                 relief="flat", font=F_SMALL, bd=0,
                 highlightthickness=0).pack(
                     side=tk.LEFT, fill=tk.X, expand=True, pady=5, padx=4)

        # Listbox
        lf = tk.Frame(side, bg=BG1)
        lf.pack(fill=tk.BOTH, expand=True, padx=12)
        sb = tk.Scrollbar(lf, orient=tk.VERTICAL, bg=BG3,
                          troughcolor=BG1, relief="flat", bd=0, width=5)
        self.proc_lb = tk.Listbox(
            lf, bg=BG2, fg=TEXT1,
            selectbackground=ACCENT, selectforeground="#000",
            font=("Consolas", 10), relief="flat", bd=0,
            activestyle="none", highlightthickness=0,
            yscrollcommand=sb.set)
        sb.config(command=self.proc_lb.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.proc_lb.pack(fill=tk.BOTH, expand=True)
        self.proc_lb.bind("<Double-1>", self._attach)

        # Attach btn
        tk.Button(side, text="⚡  Attach to Process",
                  font=F_BOLD, bg=ACCENT, fg="#000",
                  relief="flat", bd=0, cursor="hand2",
                  padx=10, pady=9,
                  activebackground="#33d4ff", activeforeground="#000",
                  command=self._attach).pack(
                      fill=tk.X, padx=12, pady=10)

    def _build_right(self, parent):
        right = tk.Frame(parent, bg=BG0)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=8)
        self._build_scanner(right)
        self._build_results(right)
        self._build_saved(right)

    def _build_scanner(self, parent):
        box = tk.LabelFrame(parent, text="  Memory Scanner  ",
            font=F_BOLD, bg=BG0, fg=ACCENT,
            bd=1, relief="solid", highlightbackground=BORDER)
        box.pack(fill=tk.X, pady=(0, 6))

        row = tk.Frame(box, bg=BG0)
        row.pack(fill=tk.X, padx=12, pady=10)

        def label(p, t):
            tk.Label(p, text=t, font=("Segoe UI", 9), bg=BG0, fg=TEXT2).pack(anchor="w")

        # Value input
        vf = tk.Frame(row, bg=BG0)
        vf.pack(side=tk.LEFT, padx=(0, 14))
        label(vf, "Value to find")
        self.val_var = tk.StringVar()
        ve = tk.Entry(vf, textvariable=self.val_var,
                      width=16, font=("Consolas", 13),
                      bg=BG3, fg=ACCENT, insertbackground=ACCENT,
                      relief="flat", bd=6,
                      highlightbackground=ACCENT, highlightthickness=1)
        ve.pack()
        ve.bind("<Return>", lambda e: self._first_scan())

        # Type selector
        tf = tk.Frame(row, bg=BG0)
        tf.pack(side=tk.LEFT, padx=(0, 14))
        label(tf, "Value type")
        self.type_var = tk.StringVar(value="Integer (4 byte)")
        ttk.Combobox(tf, textvariable=self.type_var,
                     values=list(TYPES.keys()),
                     width=18, state="readonly",
                     font=F_MAIN).pack()

        # Buttons
        bf = tk.Frame(row, bg=BG0)
        bf.pack(side=tk.LEFT)
        label(bf, " ")
        br = tk.Frame(bf, bg=BG0)
        br.pack()

        def mkbtn(text, bg, fg, cmd, state=tk.NORMAL):
            b = tk.Button(br, text=text, font=F_BOLD,
                          bg=bg, fg=fg, relief="flat", bd=0,
                          cursor="hand2", padx=14, pady=7,
                          activebackground=bg, activeforeground=fg,
                          state=state, command=cmd)
            b.pack(side=tk.LEFT, padx=(0, 6))
            return b

        self.btn_first = mkbtn("🔍  First Scan", ACCENT, "#000",
                               self._first_scan, tk.DISABLED)
        self.btn_next  = mkbtn("⟳  Next Scan",  GREEN,  "#000",
                               self._next_scan,  tk.DISABLED)
        self.btn_reset = mkbtn("✕  Reset",       BG3,    TEXT2,
                               self._reset_scan, tk.DISABLED)

        self.tip = tk.Label(box,
            text="💡  Attach a process from the left panel to begin.",
            font=F_SMALL, bg=BG0, fg=TEXT2, anchor="w")
        self.tip.pack(fill=tk.X, padx=12, pady=(0, 8))

    def _build_results(self, parent):
        lf = tk.LabelFrame(parent, text="  Scan Results  ",
            font=F_BOLD, bg=BG0, fg=ACCENT,
            bd=1, relief="solid", highlightbackground=BORDER)
        lf.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        info = tk.Frame(lf, bg=BG0)
        info.pack(fill=tk.X, padx=8, pady=(6, 2))
        self.res_count = tk.Label(info, text="Results: 0",
            font=F_SMALL, bg=BG0, fg=TEXT2)
        self.res_count.pack(side=tk.LEFT)
        tk.Label(info, text="Double-click a result to save it →",
            font=F_SMALL, bg=BG0, fg=TEXT2).pack(side=tk.RIGHT)

        cols = ("Address", "Current Value", "Previous Value")
        self.res_tree = ttk.Treeview(lf, columns=cols,
                                     show="headings", height=7)
        for col, w in zip(cols, [220, 170, 170]):
            self.res_tree.heading(col, text=col)
            self.res_tree.column(col, width=w,
                anchor="w" if col=="Address" else "center")

        sb = ttk.Scrollbar(lf, orient=tk.VERTICAL,
                           command=self.res_tree.yview)
        self.res_tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 6), pady=4)
        self.res_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.res_tree.bind("<Double-1>", self._add_to_saved)

    def _build_saved(self, parent):
        lf = tk.LabelFrame(parent, text="  Saved Addresses  ",
            font=F_BOLD, bg=BG0, fg=YELLOW,
            bd=1, relief="solid", highlightbackground=BORDER)
        lf.pack(fill=tk.BOTH, expand=True)

        info = tk.Frame(lf, bg=BG0)
        info.pack(fill=tk.X, padx=8, pady=(6, 2))
        tk.Label(info, text="Double-click the Value cell to write to memory",
            font=F_SMALL, bg=BG0, fg=TEXT2).pack(side=tk.LEFT)
        tk.Button(info, text="🗑  Remove", font=F_SMALL,
                  bg=BG3, fg=RED, relief="flat", bd=0,
                  cursor="hand2", padx=8, pady=3,
                  activebackground=BG4, activeforeground=RED,
                  command=self._remove_saved).pack(side=tk.RIGHT)

        cols = ("Description", "Address", "Type", "Value", "Frozen")
        self.sav_tree = ttk.Treeview(lf, columns=cols,
                                     show="headings", height=5)
        widths = [170, 200, 130, 130, 90]
        anchors= ["w","w","center","center","center"]
        for col, w, a in zip(cols, widths, anchors):
            self.sav_tree.heading(col, text=col)
            self.sav_tree.column(col, width=w, anchor=a)

        sb2 = ttk.Scrollbar(lf, orient=tk.VERTICAL,
                            command=self.sav_tree.yview)
        self.sav_tree.configure(yscrollcommand=sb2.set)
        sb2.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 6), pady=4)
        self.sav_tree.pack(fill=tk.BOTH, expand=True,
                           padx=8, pady=(0, 4))
        self.sav_tree.bind("<Double-1>", self._on_saved_dblclick)

        ab = tk.Frame(lf, bg=BG0)
        ab.pack(fill=tk.X, padx=8, pady=(0, 8))
        for text, bg, fg, cmd in [
            ("🔒  Toggle Freeze",    YELLOW, "#000", self._toggle_freeze),
            ("✏️  Edit Description", BG3,    TEXT1,  self._edit_desc),
        ]:
            tk.Button(ab, text=text, font=F_BOLD,
                      bg=bg, fg=fg, relief="flat", bd=0,
                      cursor="hand2", padx=14, pady=6,
                      activebackground=bg, activeforeground=fg,
                      command=cmd).pack(side=tk.LEFT, padx=(0, 6))

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=BG1, height=26)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self.status = tk.Label(bar,
            text="Ready — select and attach a process to begin",
            font=F_SMALL, bg=BG1, fg=TEXT2, anchor="w")
        self.status.pack(side=tk.LEFT, padx=12)
        tk.Label(bar, text="EasyHawk v2.0  •  Run as Administrator",
                 font=F_SMALL, bg=BG1, fg=TEXT2).pack(side=tk.RIGHT, padx=12)

    # ── Process management ────────────────────────────────────────────────────
    def _load_processes(self):
        self._all_procs = get_process_list()
        self._render_procs(self._all_procs)
        self._set_status(f"Found {len(self._all_procs)} running processes")

    def _filter_procs(self):
        q = self.search_var.get().lower()
        self._render_procs([(n, p) for n, p in self._all_procs
                            if q in n.lower() or q in str(p)])

    def _render_procs(self, procs):
        self.proc_lb.delete(0, tk.END)
        for name, pid in procs:
            self.proc_lb.insert(tk.END, f"  {name}  [{pid}]")

    def _attach(self, event=None):
        sel = self.proc_lb.curselection()
        if not sel:
            messagebox.showinfo("Select Process",
                                "Click a process in the list first.")
            return
        text = self.proc_lb.get(sel[0]).strip()
        try:
            name = text[:text.rfind("[")].strip()
            pid  = int(text[text.rfind("[")+1 : text.rfind("]")])
        except Exception:
            messagebox.showerror("Error", "Could not parse process info.")
            return

        if self.handle:
            close_handle(self.handle)
        h = open_process(pid)
        if not h:
            messagebox.showerror("Access Denied",
                f"Cannot open {name} (PID {pid}).\n\n"
                "Right-click EasyHawk → Run as Administrator.")
            return

        self.pid    = pid
        self.pname  = name
        self.handle = h
        self._reset_scan(confirm=False)
        self.btn_first.config(state=tk.NORMAL)
        self.badge.config(
            text=f"  ● {name}  (PID {pid})  ",
            bg="#0a2018", fg=GREEN)
        self._set_tip(
            f"Attached to {name}! Enter the current in-game value then click First Scan.",
            GREEN)
        self._set_status(f"Attached: {name}  (PID {pid})")

    # ── Scanning ──────────────────────────────────────────────────────────────
    def _first_scan(self):
        if not self.pid:
            messagebox.showinfo("No Process", "Attach to a process first.")
            return
        val_str = self.val_var.get().strip()
        if not val_str:
            messagebox.showinfo("Enter Value",
                                "Type the current in-game value first.")
            return
        target = to_bytes(self.type_var.get(), val_str)
        if target is None:
            messagebox.showerror("Invalid Value",
                f"'{val_str}' is not valid for {self.type_var.get()}.")
            return

        self.btn_first.config(state=tk.DISABLED, text="Scanning…")
        self.btn_next.config(state=tk.DISABLED)
        self.res_tree.delete(*self.res_tree.get_children())
        self._set_status("Scanning memory — please wait…")
        self.update()

        cur_val = parse_num(val_str)
        vtype   = self.type_var.get()
        h       = self.handle
        sz      = len(target)

        def run():
            found = _scan_all(h, target, sz)
            self.after(0, lambda: self._on_first_done(found, cur_val))

        threading.Thread(target=run, daemon=True).start()

    def _on_first_done(self, found, cur_val):
        self.results  = found
        self.prev_val = cur_val
        self._redraw_results(found, cur_val, None)
        self.btn_first.config(state=tk.NORMAL, text="🔍  First Scan")
        self.btn_next.config(state=tk.NORMAL if found else tk.DISABLED)
        self.btn_reset.config(state=tk.NORMAL)
        n = len(found)
        self._set_status(f"First scan — {n} result{'s' if n!=1 else ''} found")

        if n == 0:
            self._set_tip("No results. Make sure you typed the exact value shown in-game.", RED)
        elif n > 1000:
            self._set_tip(
                f"{n} results — change the value in-game, type the new value, then click Next Scan.",
                YELLOW)
        else:
            self._set_tip(
                f"{n} result{'s' if n!=1 else ''} found! Change the value in-game, enter the new value, click Next Scan.",
                ACCENT)

    def _next_scan(self):
        if not self.results:
            messagebox.showinfo("No Results", "Run First Scan first.")
            return
        val_str = self.val_var.get().strip()
        if not val_str:
            messagebox.showinfo("Enter Value",
                                "Type the NEW value (what it changed to in-game).")
            return
        target = to_bytes(self.type_var.get(), val_str)
        if target is None:
            messagebox.showerror("Invalid Value",
                f"'{val_str}' is not valid for {self.type_var.get()}.")
            return

        self.btn_next.config(state=tk.DISABLED, text="Filtering…")
        self.btn_first.config(state=tk.DISABLED)
        n = len(self.results)
        self._set_status(f"Checking {n} address{'es' if n!=1 else ''}…")
        self.update()

        old_addrs = list(self.results)   # snapshot — thread-safe copy
        old_val   = self.prev_val
        new_val   = parse_num(val_str)
        sz        = len(target)
        h         = self.handle

        def run():
            # Re-read each saved address and keep only those that
            # NOW contain exactly the target bytes.
            kept = []
            for addr in old_addrs:
                raw = read_bytes(h, addr, sz)
                if raw is not None and raw == target:
                    kept.append(addr)
            self.after(0, lambda: self._on_next_done(kept, new_val, old_val))

        threading.Thread(target=run, daemon=True).start()

    def _on_next_done(self, kept, new_val, old_val):
        self.results  = kept
        self.prev_val = new_val
        self._redraw_results(kept, new_val, old_val)
        self.btn_next.config(state=tk.NORMAL if kept else tk.DISABLED,
                             text="⟳  Next Scan")
        self.btn_first.config(state=tk.NORMAL)
        n = len(kept)
        self._set_status(f"Next scan — {n} address{'es' if n!=1 else ''} remain")

        if n == 0:
            self._set_tip(
                "0 results. The value may have changed again — try First Scan with the current value.",
                RED)
        elif n <= 5:
            self._set_tip(
                f"Only {n} address{'es' if n!=1 else ''} left! Double-click one to add it to Saved Addresses.",
                GREEN)
        else:
            self._set_tip(
                f"{n} addresses remain. Change the value again in-game and click Next Scan.",
                YELLOW)

    def _reset_scan(self, confirm=True):
        if confirm and self.results:
            if not messagebox.askyesno("Reset Scan",
                                       "Clear all scan results and start over?"):
                return
        self.results  = []
        self.prev_val = None
        self.res_tree.delete(*self.res_tree.get_children())
        self.res_count.config(text="Results: 0")
        self.btn_next.config(state=tk.DISABLED)
        self.btn_reset.config(state=tk.DISABLED)
        self._set_tip("Scan reset. Enter a value and click First Scan.", TEXT2)
        self._set_status("Reset — ready for a new scan")

    def _redraw_results(self, addrs, cur_val, prev_val):
        self.res_tree.delete(*self.res_tree.get_children())
        MAX = 500
        for addr in addrs[:MAX]:
            self.res_tree.insert("", tk.END, values=(
                f"0x{addr:016X}",
                fmt_val(cur_val),
                fmt_val(prev_val),
            ))
        n = len(addrs)
        extra = f"  (showing first {MAX})" if n > MAX else ""
        self.res_count.config(text=f"Results: {n}{extra}")

    # ── Saved addresses ───────────────────────────────────────────────────────
    def _add_to_saved(self, event=None):
        sel = self.res_tree.selection()
        if not sel:
            return
        vals     = self.res_tree.item(sel[0])["values"]
        addr_str = str(vals[0])
        cur_val  = str(vals[1])
        self._sav_uid += 1
        row = {
            "uid":    self._sav_uid,
            "desc":   f"Address {self._sav_uid}",
            "addr":   addr_str,
            "type":   self.type_var.get(),
            "value":  cur_val,
            "frozen": False,
        }
        self.saved.append(row)
        self._redraw_saved()
        self._set_status(f"Saved {addr_str}")

    def _redraw_saved(self):
        self.sav_tree.delete(*self.sav_tree.get_children())
        for r in self.saved:
            self.sav_tree.insert("", tk.END, iid=str(r["uid"]),
                values=(r["desc"], r["addr"], r["type"],
                        r["value"],
                        "🔒 Frozen" if r["frozen"] else "No"))

    def _row_by_iid(self, iid):
        return next((r for r in self.saved if str(r["uid"]) == iid), None)

    def _on_saved_dblclick(self, event):
        sel = self.sav_tree.selection()
        if not sel:
            return
        col = self.sav_tree.identify_column(event.x)
        if col != "#4":   # only the Value column (#4)
            return
        row = self._row_by_iid(sel[0])
        if not row:
            return
        new_str = simpledialog.askstring(
            "Edit Value",
            f"New value for {row['addr']}\nCurrent: {row['value']}",
            initialvalue=row["value"], parent=self)
        if new_str is None:
            return
        data = to_bytes(row["type"], new_str)
        if data is None:
            messagebox.showerror("Invalid",
                f"'{new_str}' is not a valid {row['type']}.")
            return
        try:
            addr_int = int(row["addr"], 16)
        except ValueError:
            messagebox.showerror("Error", "Malformed address.")
            return
        ok = write_bytes(self.handle, addr_int, data)
        if ok:
            row["value"] = new_str
            self._redraw_saved()
            self._set_status(f"Wrote {new_str} → {row['addr']}")
        else:
            messagebox.showerror("Write Failed",
                "Could not write to memory.\n"
                "Make sure EasyHawk is running as Administrator.")

    def _toggle_freeze(self):
        sel = self.sav_tree.selection()
        if not sel:
            messagebox.showinfo("Select Row",
                                "Click a row in Saved Addresses first.")
            return
        row = self._row_by_iid(sel[0])
        if not row:
            return
        row["frozen"] = not row["frozen"]
        uid = row["uid"]
        if row["frozen"]:
            def tick():
                if not row["frozen"] or not self.handle:
                    return
                try:
                    data = to_bytes(row["type"], row["value"])
                    if data:
                        write_bytes(self.handle,
                                    int(row["addr"], 16), data)
                except Exception:
                    pass
                self.freeze_jobs[uid] = self.after(100, tick)
            job = self.freeze_jobs.pop(uid, None)
            if job:
                self.after_cancel(job)
            self.freeze_jobs[uid] = self.after(100, tick)
            self._set_status(f"🔒 Frozen {row['addr']} at {row['value']}")
        else:
            job = self.freeze_jobs.pop(uid, None)
            if job:
                self.after_cancel(job)
            self._set_status(f"Unfroze {row['addr']}")
        self._redraw_saved()

    def _remove_saved(self):
        sel = self.sav_tree.selection()
        if not sel:
            messagebox.showinfo("Select Row", "Click a row to remove first.")
            return
        for iid in sel:
            row = self._row_by_iid(iid)
            if row:
                job = self.freeze_jobs.pop(row["uid"], None)
                if job:
                    self.after_cancel(job)
                self.saved.remove(row)
        self._redraw_saved()

    def _edit_desc(self):
        sel = self.sav_tree.selection()
        if not sel:
            messagebox.showinfo("Select Row", "Click a row first.")
            return
        row = self._row_by_iid(sel[0])
        if not row:
            return
        nd = simpledialog.askstring(
            "Edit Description", "Enter description:",
            initialvalue=row["desc"], parent=self)
        if nd:
            row["desc"] = nd
            self._redraw_saved()

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _set_status(self, msg):
        self.status.config(text=msg)

    def _set_tip(self, msg, color=TEXT2):
        self.tip.config(text=f"💡  {msg}", fg=color)

    def on_close(self):
        for job in list(self.freeze_jobs.values()):
            try: self.after_cancel(job)
            except Exception: pass
        close_handle(self.handle)
        self.destroy()


# ── Module-level scan (runs in thread, no self needed) ────────────────────────
def _scan_all(h, target_bytes, sz):
    """Walk every writable committed region and collect matching addresses."""
    results = []
    addr    = 0
    MAX_ADDR= 0x7FFFFFFFFFFFFFFF

    while addr < MAX_ADDR:
        mbi = vquery(h, addr)
        if not mbi:
            break
        rsize = int(mbi.RegionSize)
        if rsize == 0:
            break

        if (mbi.State == MEM_COMMIT and
                mbi.Protect in WRITABLE_PAGES):
            chunk = read_bytes(h, mbi.BaseAddress, rsize)
            if chunk:
                i   = 0
                end = len(chunk) - sz
                while i <= end:
                    if chunk[i:i+sz] == target_bytes:
                        results.append(mbi.BaseAddress + i)
                        if len(results) >= 5000:
                            return results
                    i += 1          # step 1 byte — catches unaligned values

        addr = mbi.BaseAddress + rsize

    return results


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = EasyHawk()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
