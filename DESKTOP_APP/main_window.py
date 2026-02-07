"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Desktop GUI Application

PyQt6-based graphical interface for E-MAT
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QMessageBox, QProgressBar,
    QGroupBox, QLineEdit, QListWidget, QSplitter, QFrame, QSizePolicy,
    QSpacerItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QDesktopServices


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================
# BACKGROUND WORKERS
# ============================================================

class AnalysisWorker(QThread):
    """Background worker for file analysis"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            self.progress.emit("Starting analysis...")
            from CLI_TOOL.commands.analyze import perform_static_analysis
            self.progress.emit("Analyzing file...")
            result = perform_static_analysis(self.filepath)
            self.progress.emit("Analysis complete!")
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(f"Analysis failed: {str(e)}")


class YARASearchWorker(QThread):
    """Background worker for YARA search"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, filepath, rules_path=None):
        super().__init__()
        self.filepath = filepath
        self.rules_path = rules_path

    def run(self):
        try:
            from CORE_ENGINE.utils.yara_manager import YARAManager
            manager = YARAManager(self.rules_path)
            result = manager.scan(self.filepath)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class StringSearchWorker(QThread):
    """Background worker for string search"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, filepath, pattern):
        super().__init__()
        self.filepath = filepath
        self.pattern = pattern

    def run(self):
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            matches = []
            pattern_bytes = self.pattern.encode('utf-8', errors='ignore')
            offset = 0
            while True:
                idx = data.find(pattern_bytes, offset)
                if idx == -1:
                    break
                ctx_s = max(0, idx - 16)
                ctx_e = min(len(data), idx + len(pattern_bytes) + 16)
                matches.append({'offset': hex(idx), 'type': 'ASCII', 'context': data[ctx_s:ctx_e].hex()})
                offset = idx + 1
                if len(matches) >= 200:
                    break
            hex_matches = []
            try:
                hex_pat = bytes.fromhex(self.pattern.replace(' ', ''))
                offset = 0
                while True:
                    idx = data.find(hex_pat, offset)
                    if idx == -1:
                        break
                    ctx_s = max(0, idx - 16)
                    ctx_e = min(len(data), idx + len(hex_pat) + 16)
                    hex_matches.append({'offset': hex(idx), 'type': 'HEX', 'context': data[ctx_s:ctx_e].hex()})
                    offset = idx + 1
                    if len(hex_matches) >= 200:
                        break
            except ValueError:
                pass
            self.finished.emit({'ascii': matches, 'hex': hex_matches, 'filename': Path(self.filepath).name})
        except Exception as e:
            self.error.emit(str(e))


# ============================================================
# HELPER: Horizontal separator line
# ============================================================

def h_line():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Sunken)
    line.setStyleSheet("color: #2d3748; background-color: #2d3748; max-height: 1px; margin: 4px 0;")
    return line


def section_label(text):
    lbl = QLabel(text)
    lbl.setStyleSheet("color: #4a9eff; font-size: 11px; font-weight: 600; letter-spacing: 1px; padding: 0; margin: 0; background: transparent;")
    return lbl


def muted_label(text, center=True):
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet("color: #9ca3af; font-size: 12px; padding: 2px 0; background: transparent;")
    if center:
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return lbl


def primary_btn(text):
    btn = QPushButton(text)
    btn.setStyleSheet(
        "QPushButton { background-color: #4a9eff; color: white; font-weight: 600; "
        "padding: 8px 24px; border-radius: 6px; border: none; }"
        "QPushButton:hover { background-color: #6bb0ff; }"
        "QPushButton:pressed { background-color: #3a8eef; }"
    )
    return btn


def secondary_btn(text):
    btn = QPushButton(text)
    btn.setStyleSheet(
        "QPushButton { background-color: #1a2332; color: #e5e7eb; font-weight: 500; "
        "padding: 8px 20px; border-radius: 6px; border: 1px solid #2d3748; }"
        "QPushButton:hover { background-color: #2d3748; border-color: #4a9eff; }"
    )
    return btn


def success_btn(text):
    btn = QPushButton(text)
    btn.setStyleSheet(
        "QPushButton { background-color: #10b981; color: white; font-weight: 600; "
        "padding: 8px 24px; border-radius: 6px; border: none; }"
        "QPushButton:hover { background-color: #34d399; }"
    )
    return btn


def mono_text_edit(placeholder=""):
    te = QTextEdit()
    te.setReadOnly(True)
    te.setFont(QFont("Consolas", 10))
    te.setPlaceholderText(placeholder)
    te.setStyleSheet(
        "QTextEdit { background-color: #0f1520; color: #e5e7eb; border: 1px solid #2d3748; "
        "border-radius: 6px; padding: 10px; }"
    )
    return te


def styled_input(placeholder=""):
    inp = QLineEdit()
    inp.setPlaceholderText(placeholder)
    inp.setStyleSheet(
        "QLineEdit { background-color: #141b2d; color: #e5e7eb; border: 1px solid #2d3748; "
        "border-radius: 6px; padding: 9px 14px; font-size: 13px; }"
        "QLineEdit:focus { border-color: #4a9eff; }"
    )
    return inp


def card_frame():
    """A subtle card container"""
    frame = QFrame()
    frame.setStyleSheet(
        "QFrame { background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; }"
    )
    return frame


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.current_result = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("E-MAT - ETHICAL Malware Analysis Toolkit")
        self.setGeometry(120, 80, 1000, 650)
        self.setMinimumSize(800, 500)

        # Load dark theme
        theme_path = Path(__file__).parent / 'styles' / 'dark_theme.qss'
        if theme_path.exists():
            with open(theme_path, 'r') as f:
                self.setStyleSheet(f.read())

        icon_path = Path(__file__).parent.parent / 'ASSETS' / 'logo.svg'
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- Header ----
        header = QWidget()
        header.setFixedHeight(52)
        header.setStyleSheet("background-color: #0d1117; border-bottom: 1px solid #1e293b;")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)

        title = QLabel("E-MAT")
        title.setStyleSheet("color: #4a9eff; font-size: 18px; font-weight: 700; letter-spacing: 2px; background: transparent;")
        hl.addWidget(title)

        subtitle = QLabel("ETHICAL Malware Analysis Toolkit")
        subtitle.setStyleSheet("color: #64748b; font-size: 11px; letter-spacing: 1px; background: transparent;")
        hl.addWidget(subtitle)

        hl.addStretch()

        warn = QLabel("[!] EDUCATIONAL USE ONLY")
        warn.setStyleSheet("color: #ef4444; font-size: 11px; font-weight: 600; background: transparent;")
        hl.addWidget(warn)

        root.addWidget(header)

        # ---- Progress bar ----
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setStyleSheet(
            "QProgressBar { background-color: #0d1117; border: none; border-radius: 0; "
            "text-align: center; color: #64748b; font-size: 11px; }"
            "QProgressBar::chunk { background-color: #4a9eff; }"
        )
        root.addWidget(self.progress_bar)

        # ---- Body ----
        body = QWidget()
        body.setStyleSheet("background-color: #0a0e1a;")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(16, 12, 16, 8)
        body_layout.setSpacing(0)

        # Top-level tabs
        self.main_tabs = QTabWidget()
        self.main_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e293b;
                border-radius: 0 0 8px 8px;
                background-color: #0f1520;
                padding: 16px;
            }
            QTabBar::tab {
                background-color: #111827;
                color: #94a3b8;
                padding: 9px 22px;
                border: 1px solid #1e293b;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 3px;
                font-size: 12px;
                font-weight: 500;
            }
            QTabBar::tab:selected {
                background-color: #0f1520;
                color: #4a9eff;
                border-bottom: 2px solid #4a9eff;
            }
            QTabBar::tab:hover:!selected {
                background-color: #1e293b;
                color: #e5e7eb;
            }
        """)

        self.main_tabs.addTab(self._build_file_url_tab(), "  File / URL  ")
        self.main_tabs.addTab(self._build_collection_tab(), "  File Collection  ")
        self.main_tabs.addTab(self._build_report_search_tab(), "  Report Search  ")
        self.main_tabs.addTab(self._build_yara_tab(), "  YARA Search  ")
        self.main_tabs.addTab(self._build_string_tab(), "  String Search  ")

        body_layout.addWidget(self.main_tabs)
        root.addWidget(body, 1)

        # ---- Footer ----
        footer = QWidget()
        footer.setFixedHeight(28)
        footer.setStyleSheet("background-color: #0d1117; border-top: 1px solid #1e293b;")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(16, 0, 16, 0)
        fl.addWidget(QLabel("2026 E-MAT"))
        fl.addStretch()
        center_lbl = QLabel("ETHICAL Malware Analysis Toolkit")
        center_lbl.setStyleSheet("color: #475569; font-size: 10px; background: transparent;")
        gh = QLabel('<a href="https://github.com/naveed-gung" style="color:#4a9eff;text-decoration:none;font-size:10px;">GitHub</a>')
        gh.setOpenExternalLinks(True)
        gh.setStyleSheet("background: transparent;")
        fl.addWidget(gh)

        dot = QLabel(" | ")
        dot.setStyleSheet("color: #475569; font-size: 10px; background: transparent;")
        fl.addWidget(dot)

        pf = QLabel('<a href="https://naveed-gung.dev" style="color:#4a9eff;text-decoration:none;font-size:10px;">Portfolio</a>')
        pf.setOpenExternalLinks(True)
        pf.setStyleSheet("background: transparent;")
        fl.addWidget(pf)

        fl.addStretch()
        fl.addWidget(center_lbl)

        root.addWidget(footer)

        self.statusBar().showMessage("Ready")
        self.statusBar().setStyleSheet("QStatusBar { background-color: #0d1117; color: #64748b; border-top: 1px solid #1e293b; font-size: 11px; }")

    # ============================================================
    # TAB 1: FILE / URL
    # ============================================================

    def _build_file_url_tab(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        lay.addWidget(muted_label(
            "Analyze files using static analysis, YARA rules, and string extraction."
        ))

        # File selection row
        row = QHBoxLayout()
        row.setSpacing(8)
        self.file_path_edit = styled_input("Select a file to analyze...")
        self.file_path_edit.setReadOnly(True)
        row.addWidget(self.file_path_edit, 1)

        browse = secondary_btn("Browse...")
        browse.clicked.connect(self.browse_file)
        row.addWidget(browse)

        analyze = primary_btn("Analyze")
        analyze.clicked.connect(self.analyze_file)
        row.addWidget(analyze)
        lay.addLayout(row)

        lay.addWidget(h_line())

        # Result sub-tabs
        self.result_tabs = QTabWidget()
        self.result_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e293b; border-radius: 6px;
                background-color: #0a0f18; padding: 8px;
            }
            QTabBar::tab {
                background-color: #111827; color: #94a3b8;
                padding: 6px 14px; border: 1px solid #1e293b;
                border-bottom: none; border-top-left-radius: 4px;
                border-top-right-radius: 4px; margin-right: 2px; font-size: 11px;
            }
            QTabBar::tab:selected { background-color: #0a0f18; color: #4a9eff; border-bottom: 2px solid #4a9eff; }
            QTabBar::tab:hover:!selected { background-color: #1e293b; color: #e5e7eb; }
        """)

        self.overview_tab = mono_text_edit("Overview will appear here after analysis...")
        self.result_tabs.addTab(self.overview_tab, "Overview")

        self.hashes_tab = QTableWidget()
        self.hashes_tab.setColumnCount(2)
        self.hashes_tab.setHorizontalHeaderLabels(["Hash Type", "Value"])
        self.hashes_tab.horizontalHeader().setStretchLastSection(True)
        self.hashes_tab.setAlternatingRowColors(True)
        self.result_tabs.addTab(self.hashes_tab, "Hashes")

        self.binary_tab = mono_text_edit("Binary analysis will appear here...")
        self.result_tabs.addTab(self.binary_tab, "Binary")

        self.strings_tab = mono_text_edit("String analysis will appear here...")
        self.result_tabs.addTab(self.strings_tab, "Strings")

        self.yara_tab = mono_text_edit("YARA matches will appear here...")
        self.result_tabs.addTab(self.yara_tab, "YARA")

        self.summary_tab = QTextEdit()
        self.summary_tab.setReadOnly(True)
        self.summary_tab.setFont(QFont("Segoe UI", 11))
        self.summary_tab.setPlaceholderText("Educational summary will appear here...")
        self.summary_tab.setStyleSheet(
            "QTextEdit { background-color: #0a0f18; color: #e5e7eb; border: 1px solid #1e293b; "
            "border-radius: 6px; padding: 12px; line-height: 1.6; }"
        )
        self.result_tabs.addTab(self.summary_tab, "Summary")

        lay.addWidget(self.result_tabs, 1)
        return w

    # ============================================================
    # TAB 2: FILE COLLECTION
    # ============================================================

    def _build_collection_tab(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        lay.addWidget(muted_label(
            "Upload and analyze multiple files at once.\n"
            "Receive instant threat analysis using static analysis, YARA rules, and string extraction."
        ))

        # Buttons
        row = QHBoxLayout()
        row.setSpacing(8)
        add_btn = primary_btn("Add Files...")
        add_btn.clicked.connect(self._collection_add_files)
        row.addWidget(add_btn)

        clear_btn = secondary_btn("Clear")
        clear_btn.clicked.connect(self._collection_clear)
        row.addWidget(clear_btn)

        row.addStretch()

        analyze_btn = success_btn("Analyze All")
        analyze_btn.clicked.connect(self._collection_analyze)
        row.addWidget(analyze_btn)
        lay.addLayout(row)

        # File list
        self.collection_list = QListWidget()
        self.collection_list.setMaximumHeight(150)
        self.collection_list.setStyleSheet(
            "QListWidget { background-color: #0a0f18; border: 1px solid #1e293b; border-radius: 6px; "
            "color: #e5e7eb; font-size: 12px; }"
            "QListWidget::item { padding: 6px 10px; }"
            "QListWidget::item:selected { background-color: #1e293b; }"
        )
        lay.addWidget(self.collection_list)

        lay.addWidget(h_line())

        self.collection_results = mono_text_edit("Results will appear here after analysis...")
        lay.addWidget(self.collection_results, 1)
        return w

    # ============================================================
    # TAB 3: REPORT SEARCH
    # ============================================================

    def _build_report_search_tab(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        lay.addWidget(muted_label(
            "Search through past analysis reports by IP, Domain, Hash, or filename."
        ))

        row = QHBoxLayout()
        row.setSpacing(8)
        self.report_search_input = styled_input("IP, Domain, Hash...")
        self.report_search_input.returnPressed.connect(self._report_search)
        row.addWidget(self.report_search_input, 1)

        search_btn = primary_btn("Search")
        search_btn.clicked.connect(self._report_search)
        row.addWidget(search_btn)
        lay.addLayout(row)

        lay.addWidget(h_line())

        self.report_search_results = mono_text_edit("Search results will appear here...")
        lay.addWidget(self.report_search_results, 1)
        return w

    # ============================================================
    # TAB 4: YARA SEARCH
    # ============================================================

    def _build_yara_tab(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        lay.addWidget(muted_label(
            "Hunt samples matching YARA rules at the byte level."
        ))

        # Target file
        lay.addWidget(section_label("TARGET FILE"))
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        self.yara_target_edit = styled_input("Select target file to scan...")
        self.yara_target_edit.setReadOnly(True)
        r1.addWidget(self.yara_target_edit, 1)
        b1 = secondary_btn("Browse...")
        b1.clicked.connect(self._yara_browse_target)
        r1.addWidget(b1)
        lay.addLayout(r1)

        # Rules file
        lay.addWidget(section_label("YARA RULES (optional)"))
        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.yara_rules_edit = styled_input("Uses default rules if empty...")
        self.yara_rules_edit.setReadOnly(True)
        r2.addWidget(self.yara_rules_edit, 1)
        b2 = secondary_btn("Browse...")
        b2.clicked.connect(self._yara_browse_rules)
        r2.addWidget(b2)

        scan_btn = primary_btn("Scan")
        scan_btn.clicked.connect(self._yara_scan)
        r2.addWidget(scan_btn)
        lay.addLayout(r2)

        lay.addWidget(h_line())

        self.yara_search_results = mono_text_edit("YARA scan results will appear here...")
        lay.addWidget(self.yara_search_results, 1)
        return w

    # ============================================================
    # TAB 5: STRING SEARCH
    # ============================================================

    def _build_string_tab(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        lay.addWidget(muted_label(
            "Hunt samples matching strings and hex patterns at the byte level."
        ))

        # File
        lay.addWidget(section_label("FILE TO SEARCH"))
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        self.string_target_edit = styled_input("Select file to search in...")
        self.string_target_edit.setReadOnly(True)
        r1.addWidget(self.string_target_edit, 1)
        b1 = secondary_btn("Browse...")
        b1.clicked.connect(self._string_browse_target)
        r1.addWidget(b1)
        lay.addLayout(r1)

        # Pattern
        lay.addWidget(section_label("SEARCH PATTERN"))
        r2 = QHBoxLayout()
        r2.setSpacing(8)
        self.string_pattern_edit = styled_input("HEX, ASCII string")
        self.string_pattern_edit.returnPressed.connect(self._string_search)
        r2.addWidget(self.string_pattern_edit, 1)

        search_btn = primary_btn("Search")
        search_btn.clicked.connect(self._string_search)
        r2.addWidget(search_btn)
        lay.addLayout(r2)

        lay.addWidget(h_line())

        self.string_search_results = mono_text_edit("String search results will appear here...")
        lay.addWidget(self.string_search_results, 1)
        return w

    # ============================================================
    # ACTION HANDLERS
    # ============================================================

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Analyze", "", "All Files (*.*)")
        if path:
            self.file_path_edit.setText(path)
            self.statusBar().showMessage(f"Selected: {path}")

    def analyze_file(self):
        filepath = self.file_path_edit.text()
        if not filepath:
            QMessageBox.warning(self, "No File", "Please select a file to analyze.")
            return

        reply = QMessageBox.question(
            self, "Ethical Confirmation",
            "I confirm that I have legal authorization to analyze this file\n"
            "and will use the results for educational purposes only.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.No:
            return

        self.clear_results()
        self.progress_bar.setFormat("Analyzing...")
        self.progress_bar.setRange(0, 0)

        self.worker = AnalysisWorker(filepath)
        self.worker.finished.connect(self.on_analysis_complete)
        self.worker.error.connect(self.on_analysis_error)
        self.worker.progress.connect(lambda m: self.progress_bar.setFormat(m))
        self.worker.start()
        self.statusBar().showMessage("Analysis in progress...")

    def on_analysis_complete(self, result):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.current_result = result
        self.display_results(result)
        self.statusBar().showMessage("Analysis complete!")

    def on_analysis_error(self, msg):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Error")
        self.statusBar().showMessage("Analysis failed")
        QMessageBox.critical(self, "Analysis Error", msg)

    def clear_results(self):
        self.overview_tab.clear()
        self.hashes_tab.setRowCount(0)
        self.binary_tab.clear()
        self.strings_tab.clear()
        self.yara_tab.clear()
        self.summary_tab.clear()
        self.result_tabs.setCurrentIndex(0)

    def display_results(self, result):
        fi = result['file_info']
        sa = result['static_analysis']
        edu = result['educational_summary']

        # Overview
        txt = f"FILE INFORMATION\n{'='*50}\n"
        txt += f"  Filename:   {fi['filename']}\n"
        txt += f"  Size:       {fi['size']:,} bytes\n"
        txt += f"  Type:       {fi['description']}\n"
        txt += f"  MIME:       {fi['mime_type']}\n"
        txt += f"  Entropy:    {fi['entropy']} - {fi['entropy_analysis']}\n\n"
        txt += f"ANALYSIS METADATA\n{'='*50}\n"
        txt += f"  ID:         {result['metadata']['analysis_id']}\n"
        txt += f"  Timestamp:  {result['metadata']['timestamp']}\n"
        self.overview_tab.setText(txt)

        # Hashes
        hashes = fi['hashes']
        self.hashes_tab.setRowCount(len(hashes))
        for i, (k, v) in enumerate(hashes.items()):
            self.hashes_tab.setItem(i, 0, QTableWidgetItem(k.upper()))
            self.hashes_tab.setItem(i, 1, QTableWidgetItem(v))
        self.hashes_tab.resizeColumnsToContents()

        # Binary
        btxt = ""
        if sa.get('pe_analysis', {}).get('is_pe'):
            pe = sa['pe_analysis']
            btxt += f"PE ANALYSIS (Windows Executable)\n{'='*50}\n\n"
            btxt += f"  Architecture:  {pe.get('architecture', 'Unknown')}\n"
            btxt += f"  Subsystem:     {pe.get('subsystem', 'Unknown')}\n"
            btxt += f"  Compile Time:  {pe.get('compile_timestamp', 'Unknown')}\n"
            btxt += f"  Entry Point:   {pe.get('entry_point', 'Unknown')}\n\n"
            if pe.get('sections'):
                btxt += f"  Sections ({len(pe['sections'])}):\n"
                for s in pe['sections'][:10]:
                    btxt += f"    {s['name']:10s}  Size: {s['virtual_size']:8d}  Entropy: {s['entropy']:.2f}\n"
        elif sa.get('elf_analysis', {}).get('is_elf'):
            elf = sa['elf_analysis']
            btxt += f"ELF ANALYSIS (Linux Executable)\n{'='*50}\n\n"
            btxt += f"  Architecture:  {elf.get('architecture', 'Unknown')}\n"
            btxt += f"  Class:         {elf.get('class', 'Unknown')}\n"
            btxt += f"  Type:          {elf.get('type', 'Unknown')}\n"
            btxt += f"  Entry Point:   {elf.get('entry_point', 'Unknown')}\n"
        else:
            btxt = "No PE or ELF binary analysis available for this file type."
        self.binary_tab.setText(btxt)

        # Strings
        if sa.get('strings'):
            s = sa['strings']
            stxt = f"Total Strings: {s.get('total_count', 0)}\n\n"
            stats = s.get('statistics', {})
            stxt += f"STATISTICS\n{'='*50}\n"
            stxt += f"  URLs:                {stats.get('urls_found', 0)}\n"
            stxt += f"  IP Addresses:        {stats.get('ips_found', 0)}\n"
            stxt += f"  File Paths:          {stats.get('file_paths_found', 0)}\n"
            stxt += f"  Suspicious Keywords: {stats.get('suspicious_keywords_found', 0)}\n"
            cats = s.get('categories', {})
            if cats.get('urls'):
                stxt += f"\nSAMPLE URLs:\n"
                for u in cats['urls'][:5]:
                    stxt += f"  {u}\n"
            if cats.get('suspicious_keywords'):
                stxt += f"\nSUSPICIOUS KEYWORDS:\n"
                for kw in cats['suspicious_keywords'][:10]:
                    stxt += f"  {kw}\n"
            self.strings_tab.setText(stxt)

        # YARA
        yara = sa.get('yara_matches', [])
        if yara:
            ytxt = f"Matched {len(yara)} YARA rule(s)\n\n"
            for m in yara:
                ytxt += f"{'='*50}\n"
                ytxt += f"  Rule:        {m['rule']}\n"
                ytxt += f"  Severity:    {m.get('meta', {}).get('severity', 'unknown').upper()}\n"
                ytxt += f"  Description: {m.get('meta', {}).get('description', 'N/A')}\n"
                ytxt += f"  Note:        {m.get('educational_note', '')}\n\n"
            self.yara_tab.setText(ytxt)
        else:
            self.yara_tab.setText("No YARA rules matched.")

        # Summary
        stxt = f"EDUCATIONAL ASSESSMENT\n{'='*50}\n\n"
        stxt += edu['overall_assessment'] + "\n\n"
        stxt += f"SUGGESTED LEARNING TOPICS\n{'='*50}\n"
        for t in edu['suggested_learning_topics']:
            stxt += f"  \u2022 {t}\n"
        self.summary_tab.setText(stxt)

    # ---- Collection handlers ----

    def _collection_add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files", "", "All Files (*.*)")
        for f in files:
            self.collection_list.addItem(f)
        self.statusBar().showMessage(f"Added {len(files)} file(s)")

    def _collection_clear(self):
        self.collection_list.clear()
        self.collection_results.clear()

    def _collection_analyze(self):
        count = self.collection_list.count()
        if count == 0:
            QMessageBox.warning(self, "No Files", "Add files to the collection first.")
            return

        reply = QMessageBox.question(self, "Ethical Confirmation",
            f"Analyze {count} file(s)?\nI confirm ethical and legal authorization.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.No:
            return

        self.progress_bar.setRange(0, count)
        self.collection_results.clear()
        output = ""

        from CLI_TOOL.commands.analyze import perform_static_analysis
        from CORE_ENGINE.utils.safety_checker import get_safety_checker
        safety = get_safety_checker()

        for i in range(count):
            filepath = self.collection_list.item(i).text()
            self.progress_bar.setValue(i + 1)
            self.progress_bar.setFormat(f"Analyzing {i+1}/{count}...")
            QApplication.processEvents()
            try:
                is_safe, err = safety.check_file_safety(filepath)
                if not is_safe:
                    output += f"\n{'='*50}\nFILE: {filepath}\nERROR: {err}\n"
                    continue
                result = perform_static_analysis(filepath)
                fi = result['file_info']
                output += f"\n{'='*50}\n"
                output += f"  FILE:     {fi['filename']}\n"
                output += f"  Size:     {fi['size']:,} bytes\n"
                output += f"  Type:     {fi['description']}\n"
                output += f"  SHA256:   {fi['hashes'].get('sha256', 'N/A')}\n"
                output += f"  Entropy:  {fi['entropy']} - {fi['entropy_analysis']}\n"
                yc = len(result['static_analysis'].get('yara_matches', []))
                output += f"  YARA:     {yc} match(es)\n"
            except Exception as e:
                output += f"\n{'='*50}\nFILE: {filepath}\nERROR: {str(e)}\n"

        self.collection_results.setText(output)
        self.progress_bar.setFormat("Collection analysis complete")
        self.statusBar().showMessage(f"Analyzed {count} file(s)")

    # ---- Report search handlers ----

    def _report_search(self):
        query = self.report_search_input.text().strip().lower()
        if not query:
            QMessageBox.warning(self, "Empty Query", "Enter a search term.")
            return

        history_file = Path(__file__).parent.parent / 'DATA' / 'report_history.json'
        history = []
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    history = json.load(f)
            except:
                pass

        matches = []
        for entry in history:
            hashes = entry.get('hashes', {})
            if any(query in str(v).lower() for v in hashes.values() if v):
                matches.append(entry)
            elif query in entry.get('filename', '').lower():
                matches.append(entry)
            elif query in entry.get('summary', '').lower():
                matches.append(entry)
            elif query in entry.get('mime_type', '').lower():
                matches.append(entry)

        if matches:
            output = f"Found {len(matches)} result(s) for '{query}':\n\n"
            for m in matches[:50]:
                output += f"{'='*50}\n"
                output += f"  File:    {m.get('filename', 'unknown')}\n"
                output += f"  Time:    {m.get('timestamp', 'unknown')}\n"
                output += f"  Type:    {m.get('mime_type', 'unknown')}\n"
                output += f"  Size:    {m.get('size', 0):,} bytes\n"
                output += f"  SHA256:  {m.get('hashes', {}).get('sha256', 'N/A')}\n"
                output += f"  YARA:    {m.get('yara_matches', 0)} match(es)\n\n"
        else:
            output = f"No results found for '{query}'.\n\nTip: Analyze some files first to build the report history."

        self.report_search_results.setText(output)
        self.statusBar().showMessage(f"Search: {len(matches)} result(s)")

    # ---- YARA handlers ----

    def _yara_browse_target(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Target File", "", "All Files (*.*)")
        if path:
            self.yara_target_edit.setText(path)

    def _yara_browse_rules(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select YARA Rules", "", "YARA Rules (*.yar *.yara);;All Files (*.*)")
        if path:
            self.yara_rules_edit.setText(path)

    def _yara_scan(self):
        target = self.yara_target_edit.text()
        if not target:
            QMessageBox.warning(self, "No Target", "Select a target file to scan.")
            return
        rules = self.yara_rules_edit.text() or None
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("YARA scanning...")
        self.yara_search_results.setText("Scanning...")
        self._yara_worker = YARASearchWorker(target, rules)
        self._yara_worker.finished.connect(self._on_yara_done)
        self._yara_worker.error.connect(self._on_yara_error)
        self._yara_worker.start()

    def _on_yara_done(self, result):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("YARA scan complete")
        if not result.get('scanned'):
            self.yara_search_results.setText(f"Scan failed: {result.get('error', 'Unknown error')}")
            return
        output = f"Rules: {result.get('rules_file', 'default')}\n"
        output += f"Matches: {result.get('matches_count', 0)}\n\n"
        for m in result.get('matches', []):
            output += f"{'='*50}\n"
            output += f"  Rule:        {m['rule']}\n"
            output += f"  Severity:    {m.get('meta', {}).get('severity', 'unknown').upper()}\n"
            output += f"  Description: {m.get('meta', {}).get('description', 'N/A')}\n"
            output += f"  Note:        {m.get('educational_note', '')}\n\n"
        output += f"\n{result.get('educational_summary', '')}"
        self.yara_search_results.setText(output)

    def _on_yara_error(self, msg):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Error")
        self.yara_search_results.setText(f"YARA scan error: {msg}")

    # ---- String search handlers ----

    def _string_browse_target(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*.*)")
        if path:
            self.string_target_edit.setText(path)

    def _string_search(self):
        target = self.string_target_edit.text()
        pattern = self.string_pattern_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "No File", "Select a file to search in.")
            return
        if not pattern:
            QMessageBox.warning(self, "No Pattern", "Enter a search pattern.")
            return
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFormat("Searching strings...")
        self.string_search_results.setText("Searching...")
        self._string_worker = StringSearchWorker(target, pattern)
        self._string_worker.finished.connect(self._on_string_done)
        self._string_worker.error.connect(self._on_string_error)
        self._string_worker.start()

    def _on_string_done(self, result):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("String search complete")
        ascii_m = result.get('ascii', [])
        hex_m = result.get('hex', [])
        output = f"File: {result.get('filename', '')}\n"
        output += f"ASCII matches: {len(ascii_m)}  |  HEX matches: {len(hex_m)}\n\n"
        for m in (ascii_m + hex_m)[:100]:
            output += f"  [{m['type']}]  Offset: {m['offset']}  Context: {m['context']}\n"
        if not ascii_m and not hex_m:
            output += "No matches found."
        self.string_search_results.setText(output)

    def _on_string_error(self, msg):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Error")
        self.string_search_results.setText(f"String search error: {msg}")


# ============================================================
# LAUNCH FUNCTIONS
# ============================================================

def launch_desktop_app():
    """Launch the desktop GUI application"""
    app = QApplication(sys.argv)
    app.setApplicationName("E-MAT")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


# Alias expected by __main__.py
def launch_desktop():
    """Alias for launch_desktop_app"""
    return launch_desktop_app()


if __name__ == "__main__":
    launch_desktop_app()
