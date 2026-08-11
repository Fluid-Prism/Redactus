"""gui.py — desktop app (PySide6).

Third app in a family, and deliberately the one that doesn't look like the
other two. Kevscope is cool blue-black and teal with a sans headline;
VigilvCheck is indigo and gold with a serif one. This is a dossier: moss
charcoal, a single signal-orange accent, monospace headings, square corners,
and evidence rendered as an actual redaction bar — the one visual idea the
subject hands you for free, since covering the secret is literally what this
tool does before it shows you anything.

The shared parts are shared on purpose: the worker pattern, tabs instead of a
side panel, the token-driven light/dark themes. Those are house style across
the three, not an accident of copying.

Launch:  python3 -m exposure        (or python3 -m exposure.gui)
"""
import html
import sys
import time
import traceback

from PySide6.QtCore import (Qt, QEasingCurve, QObject, QPropertyAnimation, QRunnable,
                            QSettings, QThreadPool, QTimer, QVariantAnimation, Signal, Slot)
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (QApplication, QComboBox, QFrame, QGraphicsDropShadowEffect,
                               QGraphicsOpacityEffect, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMainWindow, QMessageBox, QPushButton, QScrollArea,
                               QTableWidget, QTableWidgetItem, QTabBar, QTabWidget,
                               QVBoxLayout, QWidget)

from . import store, warn_if_root
from .redact import REDACT_CHAR
from .rules import RULES_BY_ID
from .scanner import DEFAULT_TIME_BUDGET_SECONDS, scan
from .scoring import by_severity, ranked, weighted_total

PALETTES = {
    "dark": {
        "bg": "#0E1210", "surface": "#161B18", "surface_alt": "#121714",
        "border": "#28302B", "text": "#E3E7E2", "text_muted": "#87938B",
        "accent": "#D9533B", "accent_ink": "#FFF3EF",
        "critical": "#E2565B", "high": "#D9722E", "medium": "#C9A227", "low": "#7C8B80",
        "certain": "#E2565B", "likely": "#C9A227", "possible": "#87938B",
        "row_bad_bg": "#1E1512", "redaction": "#2E3630",
        "shadow": (0, 0, 0, 140),
    },
    "light": {
        "bg": "#F2F4EF", "surface": "#FCFCFA", "surface_alt": "#E9EDE4",
        "border": "#D3DACD", "text": "#1A201B", "text_muted": "#5F6B61",
        "accent": "#A8401F", "accent_ink": "#FFFFFF",
        "critical": "#B32F35", "high": "#9C5511", "medium": "#7D6410", "low": "#6B7770",
        "certain": "#B32F35", "likely": "#7D6410", "possible": "#6B7770",
        "row_bad_bg": "#F7EBE6", "redaction": "#C9D1C4",
        "shadow": (40, 50, 40, 40),
    },
}

SEVERITIES = ["critical", "high", "medium", "low"]
COLS = ["Severity", "Finding", "Where", "Confidence"]


def _esc(value):
    return html.escape(str(value)) if value is not None else ""


def _rgba(hex_color, alpha):
    h = hex_color.lstrip("#")
    return f"rgba({int(h[0:2],16)},{int(h[2:4],16)},{int(h[4:6],16)},{alpha})"


def _build_qss(c):
    return f"""
QMainWindow, QWidget {{ background: {c['bg']}; color: {c['text']};
    font-family: -apple-system, 'Segoe UI', sans-serif; font-size: 13px; }}
#Title {{ font-family: Menlo, 'SF Mono', Consolas, monospace; font-size: 21px;
    font-weight: 600; color: {c['text']}; letter-spacing: -0.2px; }}
#Eyebrow {{ font-family: Menlo, 'SF Mono', Consolas, monospace; color: {c['accent']};
    font-size: 10px; font-weight: 700; letter-spacing: 3px; }}
#Sub {{ color: {c['text_muted']}; font-size: 12px; }}
#Notice {{ background: {c['surface_alt']}; border: 1px solid {c['border']};
    border-left: 3px solid {c['accent']}; border-radius: 2px; padding: 10px 12px;
    color: {c['text_muted']}; font-size: 12px; }}
QPushButton {{ background: {c['surface']}; color: {c['text']}; border: 1px solid {c['border']};
    border-radius: 2px; padding: 8px 15px; font-size: 12px; font-weight: 500; }}
QPushButton:hover {{ border-color: {c['accent']}; color: {c['accent']}; }}
QPushButton:pressed {{ background: {c['surface_alt']}; }}
QPushButton:disabled {{ color: {c['text_muted']}; border-color: {c['border']}; }}
QPushButton#Primary {{ background: {c['accent']}; color: {c['accent_ink']}; border: none;
    font-weight: 700; font-family: Menlo, monospace; letter-spacing: 1px; }}
QPushButton#Ghost {{ background: transparent; border: 1px solid transparent; padding: 8px 10px; }}
QPushButton#Ghost:hover {{ background: {c['surface']}; border-color: {c['border']}; color: {c['text']}; }}
QFrame#Kpi {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 2px; }}
QLabel#KpiVal {{ background: transparent; }}
QLabel#KpiLbl {{ color: {c['text_muted']}; font-family: Menlo, monospace; font-size: 9px;
    font-weight: 700; letter-spacing: 1.6px; background: transparent; }}
QLabel#DetailBody {{ font-size: 12px; background: transparent; padding: 16px; }}
QScrollArea {{ border: none; background: transparent; }}
QLineEdit, QComboBox {{ background: {c['surface']}; color: {c['text']};
    border: 1px solid {c['border']}; border-radius: 2px; padding: 7px 10px; font-size: 12px; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {c['accent']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {c['surface']}; color: {c['text']};
    border: 1px solid {c['border']}; selection-background-color: {_rgba(c['accent'], 40)}; }}
QTableWidget {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 2px;
    gridline-color: {c['border']}; alternate-background-color: {c['surface_alt']}; }}
QHeaderView::section {{ background: {c['surface']}; color: {c['text_muted']}; border: none;
    border-bottom: 1px solid {c['border']}; padding: 9px 10px;
    font-family: Menlo, monospace; font-size: 9px; font-weight: 700; letter-spacing: 1.4px; }}
QTableWidget::item {{ padding: 7px 10px; border-bottom: 1px solid {c['border']}; }}
QTableWidget::item:selected {{ background: {_rgba(c['accent'], 45)}; }}
QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 2px; top: -1px;
    background: {c['surface']}; }}
QTabBar::tab {{ background: transparent; color: {c['text_muted']}; padding: 8px 14px;
    margin-right: 2px; border: none; border-bottom: 2px solid transparent;
    font-family: Menlo, monospace; font-size: 11px; }}
QTabBar::tab:selected {{ color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
QTabBar::tab:hover {{ color: {c['text']}; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {c['text_muted']}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {c['border']}; border-radius: 5px; min-width: 24px; }}
QScrollBar::handle:horizontal:hover {{ background: {c['text_muted']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QStatusBar {{ color: {c['text_muted']}; font-size: 11px; }}
"""


class _Signals(QObject):
    done = Signal(object)
    error = Signal(str)
    progress = Signal(int, int)


class _Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.signals = _Signals()

    @Slot()
    def run(self):
        try:
            self.signals.done.emit(self.fn(*self.args, **self.kwargs))
        except Exception:
            self.signals.error.emit(traceback.format_exc().strip().splitlines()[-1])


class KpiCard(QFrame):
    """Square-cornered, no accent bar — the count carries the colour itself."""
    def __init__(self, label_text):
        super().__init__()
        self.setObjectName("Kpi")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 13)
        layout.setSpacing(5)

        self.value_label = QLabel("—")
        self.value_label.setObjectName("KpiVal")
        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(20)
        mono.setWeight(QFont.DemiBold)
        self.value_label.setFont(mono)

        self.label_widget = QLabel(label_text)
        self.label_widget.setObjectName("KpiLbl")
        layout.addWidget(self.value_label)
        layout.addWidget(self.label_widget)

        self._shadow = QGraphicsDropShadowEffect(self)
        self._shadow.setOffset(0, 4)
        self._shadow.setBlurRadius(12)
        self.setGraphicsEffect(self._shadow)
        self._anim = QPropertyAnimation(self._shadow, b"blurRadius", self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def set_theme(self, colour, shadow_rgba):
        self.value_label.setStyleSheet(f"color:{colour}")
        self._shadow.setColor(QColor(*shadow_rgba))

    def _animate(self, to):
        self._anim.stop()
        self._anim.setStartValue(self._shadow.blurRadius())
        self._anim.setEndValue(to)
        self._anim.start()

    def enterEvent(self, event):
        self._animate(24)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate(12)
        super().leaveEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, auto_scan=False):
        super().__init__()
        self.setWindowTitle("Exposure Auditor")
        self.resize(1060, 700)
        self.pool = QThreadPool.globalInstance()
        self._report = None
        self._rows = []
        self.detail_tabs = {}
        self._permanent_tabs = set()
        self._kpi_prev = {s: 0 for s in SEVERITIES}
        self._workers = []
        self._anim_refs = []

        self._settings = QSettings("Fluid-Prism", "ExposureAuditor")
        saved = self._settings.value("theme")
        self.theme = saved if saved in PALETTES else self._detect_system_theme()
        self.c = PALETTES[self.theme]

        self._build_ui()
        self._apply_theme(self.theme, first_load=True)
        self._kpi_anims = {s: self._make_kpi_anim(s) for s in SEVERITIES}
        if auto_scan:
            self.on_scan()

    @staticmethod
    def _detect_system_theme():
        try:
            if QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Light:
                return "light"
        except Exception:
            pass
        return "dark"

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._rows:
            self.table.resizeRowsToContents()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 18, 20, 12)
        layout.setSpacing(14)

        head = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        eyebrow = QLabel("DATA AT REST")
        eyebrow.setObjectName("Eyebrow")
        title = QLabel("What's exposed on this disk")
        title.setObjectName("Title")
        sub = QLabel("Credentials, keys and tokens sitting where something else could read them.")
        sub.setObjectName("Sub")
        for widget in (eyebrow, title, sub):
            titles.addWidget(widget)
        head.addLayout(titles)
        head.addStretch()

        self.btn_theme = QPushButton()
        self.btn_theme.setObjectName("Ghost")
        self.btn_theme.clicked.connect(self.on_theme_toggle)
        self.btn_scan = QPushButton("SCAN")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.clicked.connect(self.on_scan)
        for button in (self.btn_theme, self.btn_scan):
            button.setCursor(Qt.PointingHandCursor)
            head.addWidget(button)
        layout.addLayout(head)

        self.kpis = {}
        krow = QHBoxLayout()
        krow.setSpacing(12)
        for severity in SEVERITIES:
            card = KpiCard(severity.upper())
            self.kpis[severity] = card
            krow.addWidget(card)
        layout.addLayout(krow)

        self.notice = QLabel()
        self.notice.setObjectName("Notice")
        self.notice.setWordWrap(True)
        self.notice.hide()
        layout.addWidget(self.notice)

        frow = QHBoxLayout()
        frow.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by file or finding…")
        self.search.textChanged.connect(self._render)
        self.f_severity = QComboBox()
        self.f_severity.addItems(["All severities", "Critical", "High", "Medium", "Low"])
        self.f_severity.currentIndexChanged.connect(self._render)
        self.f_confidence = QComboBox()
        self.f_confidence.addItems(["All confidence", "Certain", "Likely", "Possible"])
        self.f_confidence.currentIndexChanged.connect(self._render)
        frow.addWidget(self.search, 1)
        frow.addWidget(self.f_severity)
        frow.addWidget(self.f_confidence)
        self.count = QLabel("")
        self.count.setObjectName("Sub")
        frow.addWidget(self.count)
        layout.addLayout(frow)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.cellClicked.connect(self._on_cell_clicked)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        self.tabs.addTab(self.table, "Findings")
        self.tabs.tabBar().setTabButton(0, QTabBar.RightSide, None)
        self._permanent_tabs.add(self.table)
        layout.addWidget(self.tabs, 1)

        self.statusBar().showMessage("Press Scan to look at this machine.")
        self.btn_forget = QPushButton("Forget history")
        self.btn_forget.setObjectName("Ghost")
        self.btn_forget.setCursor(Qt.PointingHandCursor)
        self.btn_forget.clicked.connect(self.on_forget)
        self.statusBar().addPermanentWidget(self.btn_forget)

    def _make_kpi_anim(self, severity):
        anim = QVariantAnimation(self)
        anim.setDuration(500)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.valueChanged.connect(
            lambda value, s=severity: self.kpis[s].value_label.setText(str(int(value))))
        return anim

    # ── theme ────────────────────────────────────────────────────────────────
    def on_theme_toggle(self):
        new_theme = "light" if self.theme == "dark" else "dark"
        central = self.centralWidget()
        self._fade(central, 1.0, 0.0, 110)
        QTimer.singleShot(66, lambda: self._apply_theme(new_theme))
        QTimer.singleShot(110, lambda: self._fade(central, 0.0, 1.0, 150))

    def _apply_theme(self, name, first_load=False):
        self.theme = name
        self.c = PALETTES[name]
        self._settings.setValue("theme", name)
        self.setStyleSheet(_build_qss(self.c))
        self.btn_theme.setText("☾  Dark" if name == "light" else "☀  Light")
        for severity in SEVERITIES:
            self.kpis[severity].set_theme(self.c[severity], self.c["shadow"])
        if not first_load:
            if self._rows:
                self._render()
            for tab in self.detail_tabs.values():
                self._render_detail(tab)

    def _fade(self, widget, start, end, duration):
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(duration)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim_refs.append(anim)

        def cleanup():
            if anim in self._anim_refs:
                self._anim_refs.remove(anim)
            widget.setGraphicsEffect(None)

        anim.finished.connect(cleanup)
        anim.start()

    # ── scanning ─────────────────────────────────────────────────────────────
    def on_scan(self):
        self.btn_scan.setEnabled(False)
        self.statusBar().showMessage("Reading files… this takes a few seconds.")
        worker = _Worker(self._scan_and_record)
        self._workers.append(worker)

        def cleanup(*_):
            if worker in self._workers:
                self._workers.remove(worker)

        worker.signals.done.connect(self._on_data)
        worker.signals.done.connect(cleanup)
        worker.signals.error.connect(self._on_error)
        worker.signals.error.connect(cleanup)
        self.pool.start(worker)

    @staticmethod
    def _scan_and_record():
        report = scan(time_budget=DEFAULT_TIME_BUDGET_SECONDS)
        store.record_scan(report, weighted_total(report.findings))
        return report

    @Slot(object)
    def _on_data(self, report):
        self._report = report
        counts = by_severity(report.findings)
        for index, severity in enumerate(SEVERITIES):
            QTimer.singleShot(index * 60,
                              lambda s=severity, v=counts[severity]: self._animate_kpi(s, v))

        self._render()
        self._render_notice(report)
        self.btn_scan.setEnabled(True)
        self.statusBar().showMessage(
            f"{len(report.findings)} finding(s) across {report.files_seen:,} files "
            f"· {report.duration_seconds:.1f}s · {time.strftime('%H:%M:%S')}")

    def _animate_kpi(self, severity, value):
        anim = self._kpi_anims[severity]
        anim.stop()
        anim.setStartValue(self._kpi_prev.get(severity, 0))
        anim.setEndValue(value)
        anim.start()
        self._kpi_prev[severity] = value

    @Slot(str)
    def _on_error(self, message):
        self.btn_scan.setEnabled(True)
        self.statusBar().showMessage(f"Error: {message}")

    def _render_notice(self, report):
        """Coverage gaps are stated plainly, next to the findings rather than
        buried. 'Nothing found in what I could read' is a different claim from
        'nothing found', and only the first one is ever true here."""
        if not report.coverage_is_partial:
            self.notice.hide()
            return
        parts = []
        if report.stopped_early:
            parts.append(_esc(report.stop_reason))
        if report.skipped_too_large:
            parts.append(f"{report.skipped_too_large:,} file(s) skipped for size.")
        if report.skipped_unreadable:
            parts.append(f"{report.skipped_unreadable:,} file(s) couldn't be read.")
        if report.detector_errors:
            parts.append(f"{report.detector_errors:,} file(s) hit an internal error.")
        self.notice.setText(
            "<b>Coverage was not complete.</b> " + " ".join(parts)
            + " Findings below are real — but an empty result here is not proof that "
              "nothing else is exposed.")
        self.notice.show()

    # ── table ────────────────────────────────────────────────────────────────
    def _render(self):
        if not self._report:
            return
        c = self.c
        query = self.search.text().lower().strip()
        severity_filter = self.f_severity.currentText().lower().replace(" severities", "")
        confidence_filter = self.f_confidence.currentText().lower().replace(" confidence", "")

        rows = []
        for finding in ranked(self._report.findings):
            rule = RULES_BY_ID.get(finding.rule_id)
            title = rule.title if rule else finding.rule_id
            if query and query not in finding.display_path.lower() and query not in title.lower():
                continue
            if severity_filter != "all" and finding.severity != severity_filter:
                continue
            if confidence_filter != "all" and finding.confidence != confidence_filter:
                continue
            rows.append((finding, title))

        self._rows = rows
        self.count.setText(f"{len(rows)} of {len(self._report.findings)}")
        self.table.setRowCount(len(rows))
        mono = QFont("Menlo")
        mono.setStyleHint(QFont.Monospace)
        mono.setPointSize(11)

        for index, (finding, title) in enumerate(rows):
            where = finding.display_path + (f":{finding.line_no}" if finding.line_no else "")
            cells = [finding.severity.upper(), title, where, finding.confidence]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column in (0, 3):
                    item.setFont(mono)
                if column == 0:
                    item.setForeground(QColor(c[finding.severity]))
                if column == 3:
                    item.setForeground(QColor(c.get(finding.confidence, c["text_muted"])))
                if finding.severity in ("critical", "high"):
                    item.setBackground(QColor(c["row_bad_bg"]))
                self.table.setItem(index, column, item)
        self.table.resizeRowsToContents()

    # ── detail tabs ──────────────────────────────────────────────────────────
    def _on_cell_clicked(self, row, _column):
        if 0 <= row < len(self._rows):
            self._open_detail(*self._rows[row])

    def _open_detail(self, finding, title):
        key = (finding.rule_id, finding.display_path, finding.line_no)
        existing = self.detail_tabs.get(key)
        if existing:
            index = self.tabs.indexOf(existing["container"])
            if index != -1:
                self.tabs.setCurrentIndex(index)
                return
            del self.detail_tabs[key]

        body = QLabel()
        body.setObjectName("DetailBody")
        body.setWordWrap(True)
        body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        body.setTextFormat(Qt.RichText)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)

        tab = {"finding": finding, "title": title, "body": body, "container": scroll}
        self.detail_tabs[key] = tab
        self._render_detail(tab)
        label = title if len(title) <= 26 else title[:25] + "…"
        self.tabs.setCurrentIndex(self.tabs.addTab(scroll, label))

    def _render_detail(self, tab):
        tab["body"].setText(self._detail_html(tab["finding"], tab["title"]))

    def _close_tab(self, index):
        widget = self.tabs.widget(index)
        if widget in self._permanent_tabs:
            return
        for key, tab in list(self.detail_tabs.items()):
            if tab["container"] is widget:
                del self.detail_tabs[key]
                break
        self.tabs.removeTab(index)
        widget.deleteLater()

    def _detail_html(self, finding, title):
        c = self.c
        rule = RULES_BY_ID.get(finding.rule_id)
        severity_colour = c.get(finding.severity, c["text"])
        where = _esc(finding.display_path) + (f":{finding.line_no}" if finding.line_no else "")

        parts = [
            f"<div style='font-size:16px;font-weight:600;color:{c['text']}'>{_esc(title)}</div>",
            f"<div style='color:{c['text_muted']};font-size:11px;margin:6px 0 12px 0'>"
            f"<span style='color:{severity_colour};font-weight:700'>"
            f"{_esc(finding.severity.upper())}</span>"
            f" &middot; {_esc(finding.confidence)} &middot; "
            f"<span style='font-family:Menlo,monospace'>{where}</span></div>",
            f"<div style='color:{c['text']}'>{_esc(finding.detail)}</div>",
        ]

        if finding.evidence:
            # The signature element: what was found, with the value covered.
            # The bars are real characters from redact.py, not styling over a
            # value that's still present underneath.
            parts.append(
                f"<div style='margin-top:12px;padding:10px 12px;background:{c['surface_alt']};"
                f"border-left:3px solid {c['accent']};font-family:Menlo,monospace;"
                f"font-size:12px;color:{c['text']}'>{_esc(finding.evidence)}</div>"
                f"<div style='color:{c['text_muted']};font-size:10px;margin-top:5px'>"
                f"{_esc(REDACT_CHAR * 3)} covered here and never written to disk by this app.</div>")

        if rule:
            parts += [
                f"<hr style='border:none;border-top:1px solid {c['border']};margin:14px 0'>",
                f"<div style='color:{c['accent']};font-family:Menlo,monospace;font-size:10px;"
                f"font-weight:700;letter-spacing:1.4px;margin-bottom:6px'>WHY IT MATTERS</div>",
                f"<div style='color:{c['text_muted']}'>{_esc(rule.rationale)}</div>",
                f"<div style='color:{c['accent']};font-family:Menlo,monospace;font-size:10px;"
                f"font-weight:700;letter-spacing:1.4px;margin:16px 0 6px 0'>HOW TO FIX IT</div>",
                f"<div style='color:{c['text']};font-family:Menlo,monospace;font-size:11px;"
                f"white-space:pre-wrap'>{_esc(rule.remediation(finding))}</div>",
            ]
        return "".join(parts)

    # ── history ──────────────────────────────────────────────────────────────
    def on_forget(self):
        answer = QMessageBox.question(
            self, "Forget scan history",
            "Delete the local history database?\n\n"
            f"{store.DB_PATH}\n\n"
            "It records which files held findings, so it's worth not keeping around "
            "once you've acted on them. Findings currently on screen stay until you rescan.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer == QMessageBox.Yes:
            store.forget_everything()
            store.init()
            self.statusBar().showMessage("History deleted.")


def main():
    warn_if_root()
    app = QApplication(sys.argv)
    app.setApplicationName("Exposure Auditor")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
