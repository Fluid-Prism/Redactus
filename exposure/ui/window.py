"""window.py — the application shell.

Layout is a nav rail on the left, a top bar with the primary action, and a
stack of pages. Findings is a master–detail split rather than a table, because
the thing you do with a finding is read its explanation and copy its fix, and
that wants a pane rather than a tooltip. Filters live in a drawer since
they're consulted and dismissed.
"""
import html
import time
import traceback

from PySide6.QtCore import (QEasingCurve, QObject, QPropertyAnimation, QRunnable,
                            QSettings, QThreadPool, QTimer, QVariantAnimation,
                            Qt, Signal, Slot)
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFrame,
                               QGraphicsOpacityEffect, QHBoxLayout, QLabel,
                               QLineEdit, QMainWindow, QMessageBox, QPushButton,
                               QScrollArea, QSplitter, QStackedWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import store
from ..redact import REDACT_CHAR
from ..rules import ALL_RULES, RULES_BY_ID
from ..scanner import DEFAULT_TIME_BUDGET_SECONDS, scan
from ..scoring import by_severity, group_by_file, ranked, weighted_total
from . import icons
from .theme import MONO, PALETTES, build_qss
from .widgets import (ROLE_BADGE, ROLE_FINDING, ROLE_KIND, ROLE_SEVERITY,
                      ROLE_SUBTITLE, ROLE_TITLE, Drawer, FindingDelegate,
                      NavRail, SeverityBar, StatCard)

SEVERITIES = ["critical", "high", "medium", "low"]


def esc(value):
    return html.escape(str(value)) if value is not None else ""


def esc_block(value):
    """Escaped, with newlines turned into <br>. Qt's rich text is an HTML4
    subset that ignores `white-space: pre-wrap`, so preformatted remediation
    text collapses into one paragraph without this."""
    return esc(value).replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")


class _Signals(QObject):
    done = Signal(object)
    error = Signal(str)


class _Worker(QRunnable):
    def __init__(self, fn, *args):
        super().__init__()
        self.fn, self.args = fn, args
        self.signals = _Signals()

    @Slot()
    def run(self):
        try:
            self.signals.done.emit(self.fn(*self.args))
        except Exception:
            self.signals.error.emit(traceback.format_exc().strip().splitlines()[-1])


class MainWindow(QMainWindow):
    def __init__(self, auto_scan=False):
        super().__init__()
        self.setWindowTitle("Exposure Auditor")
        self.resize(1180, 760)
        self.setMinimumSize(940, 600)

        self.pool = QThreadPool.globalInstance()
        self._report = None
        self._workers = []
        self._anims = []
        self._kpi_prev = {s: 0 for s in SEVERITIES}
        self._current_finding = None

        self._settings = QSettings("Fluid-Prism", "ExposureAuditor")
        saved = self._settings.value("theme")
        self.theme = saved if saved in PALETTES else self._detect_theme()
        self.c = PALETTES[self.theme]

        self._build()
        self._apply_theme(self.theme, first=True)
        self._kpi_anims = {s: self._make_counter(s) for s in SEVERITIES}
        self._show_empty_state()
        if auto_scan:
            self.on_scan()

    @staticmethod
    def _detect_theme():
        try:
            if QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Light:
                return "light"
        except Exception:
            pass
        return "dark"

    # ── construction ─────────────────────────────────────────────────────────
    def _build(self):
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_topbar())

        middle = QWidget()
        middle_layout = QHBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(0)

        self.nav = NavRail(self.c)
        self.nav.add_item("overview", "Overview")
        self.nav.add_item("findings", "Findings")
        self.nav.add_item("history", "History")
        self.nav.add_item("about", "About")
        self.nav.finish()
        self.nav.changed.connect(self._on_nav)
        middle_layout.addWidget(self.nav)

        self.stage = QWidget()
        stage_layout = QVBoxLayout(self.stage)
        stage_layout.setContentsMargins(0, 0, 0, 0)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_overview())
        self.pages.addWidget(self._build_findings())
        self.pages.addWidget(self._build_history())
        self.pages.addWidget(self._build_about())
        stage_layout.addWidget(self.pages)
        middle_layout.addWidget(self.stage, 1)

        outer.addWidget(middle, 1)
        outer.addWidget(self._build_statusbar())

        self.drawer = Drawer(self.stage, width=310)
        self._build_drawer()

        for sequence, slot in ((QKeySequence("Ctrl+R"), self.on_scan),
                               (QKeySequence("Ctrl+F"), self._focus_search),
                               (QKeySequence("Ctrl+K"), self._focus_search)):
            action = QAction(self)
            action.setShortcut(sequence)
            action.triggered.connect(slot)
            self.addAction(action)

    def _build_topbar(self):
        bar = QWidget()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(54)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 12, 0)
        layout.setSpacing(10)

        brand = QVBoxLayout()
        brand.setSpacing(0)
        mark = QLabel("DATA AT REST")
        mark.setObjectName("BrandMark")
        name = QLabel("Exposure Auditor")
        name.setObjectName("BrandName")
        brand.addWidget(mark)
        brand.addWidget(name)
        layout.addLayout(brand)
        layout.addSpacing(8)

        self.progress = QLabel("")
        self.progress.setObjectName("Meta")
        layout.addWidget(self.progress)
        layout.addStretch()

        self.btn_filter = QPushButton("  Filters")
        self.btn_filter.setObjectName("Quiet")
        self.btn_filter.setCheckable(True)
        self.btn_filter.setCursor(Qt.PointingHandCursor)
        self.btn_filter.clicked.connect(self._toggle_filters)

        self.btn_theme = QPushButton()
        self.btn_theme.setObjectName("Quiet")
        self.btn_theme.setCursor(Qt.PointingHandCursor)
        self.btn_theme.setToolTip("Switch theme")
        self.btn_theme.clicked.connect(self.on_theme_toggle)

        self.btn_scan = QPushButton("SCAN")
        self.btn_scan.setObjectName("Primary")
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        self.btn_scan.setToolTip("Scan this machine  (Ctrl+R)")
        self.btn_scan.clicked.connect(self.on_scan)

        for widget in (self.btn_filter, self.btn_theme, self.btn_scan):
            layout.addWidget(widget)
        return bar

    def _build_statusbar(self):
        bar = QWidget()
        bar.setObjectName("StatusBar")
        bar.setFixedHeight(30)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 12, 0)
        self.status = QLabel("Ready")
        self.status.setObjectName("Meta")
        layout.addWidget(self.status)
        layout.addStretch()
        self.status_right = QLabel("")
        self.status_right.setObjectName("Meta")
        layout.addWidget(self.status_right)
        return bar

    def _page_header(self, title, subtitle):
        header = QVBoxLayout()
        header.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        sub_label = QLabel(subtitle)
        sub_label.setObjectName("PageSub")
        sub_label.setWordWrap(True)
        header.addWidget(title_label)
        header.addWidget(sub_label)
        return header

    def _build_overview(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(18)
        layout.addLayout(self._page_header(
            "Overview", "What a scan of this machine turned up, worst first."))

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.cards = {}
        for severity in SEVERITIES:
            card = StatCard(severity.upper(), self.c)
            self.cards[severity] = card
            cards.addWidget(card)
        layout.addLayout(cards)

        self.sev_bar = SeverityBar(self.c)
        layout.addWidget(self.sev_bar)

        self.notice = QLabel()
        self.notice.setObjectName("Notice")
        self.notice.setWordWrap(True)
        self.notice.hide()
        layout.addWidget(self.notice)

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)
        head = QWidget()
        head.setObjectName("PanelHeader")
        head.setFixedHeight(36)
        head_layout = QHBoxLayout(head)
        head_layout.setContentsMargins(14, 0, 14, 0)
        head_label = QLabel("MOST EXPOSED FILES")
        head_label.setObjectName("SectionLabel")
        head_layout.addWidget(head_label)
        panel_layout.addWidget(head)

        self.top_files = QLabel()
        self.top_files.setObjectName("Detail")
        self.top_files.setTextFormat(Qt.RichText)
        self.top_files.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.top_files.setWordWrap(True)
        self.top_files.setContentsMargins(14, 12, 14, 14)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.top_files)
        panel_layout.addWidget(scroll, 1)
        layout.addWidget(panel, 1)
        return page

    def _build_findings(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)

        top = QHBoxLayout()
        top.addLayout(self._page_header(
            "Findings", "Grouped by file. Select one to see why it matters and how to fix it."))
        top.addStretch()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter…  (Ctrl+F)")
        self.search.setFixedWidth(220)
        self.search.textChanged.connect(self._render_tree)
        top.addWidget(self.search, 0, Qt.AlignBottom)
        layout.addLayout(top)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(1)

        left = QFrame()
        left.setObjectName("Panel")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        self.tree.setMouseTracking(True)
        self.tree.setUniformRowHeights(False)
        self.tree.setSelectionMode(QTreeWidget.SingleSelection)
        self.tree.setVerticalScrollMode(QTreeWidget.ScrollPerPixel)
        self.delegate = FindingDelegate(self.c, self.tree)
        self.tree.setItemDelegate(self.delegate)
        self.tree.currentItemChanged.connect(self._on_select)
        left_layout.addWidget(self.tree)
        splitter.addWidget(left)

        right = QFrame()
        right.setObjectName("Panel")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        detail_head = QWidget()
        detail_head.setObjectName("PanelHeader")
        detail_head.setFixedHeight(36)
        detail_head_layout = QHBoxLayout(detail_head)
        detail_head_layout.setContentsMargins(14, 0, 8, 0)
        self.detail_label = QLabel("DETAIL")
        self.detail_label.setObjectName("SectionLabel")
        detail_head_layout.addWidget(self.detail_label)
        detail_head_layout.addStretch()
        self.btn_copy = QPushButton("Copy fix")
        self.btn_copy.setObjectName("Quiet")
        self.btn_copy.setCursor(Qt.PointingHandCursor)
        self.btn_copy.clicked.connect(self._copy_fix)
        self.btn_copy.setEnabled(False)
        detail_head_layout.addWidget(self.btn_copy)
        right_layout.addWidget(detail_head)

        self.detail = QLabel()
        self.detail.setObjectName("Detail")
        self.detail.setTextFormat(Qt.RichText)
        self.detail.setWordWrap(True)
        self.detail.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.detail.setContentsMargins(16, 14, 16, 16)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self.detail)
        right_layout.addWidget(detail_scroll, 1)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([480, 560])
        layout.addWidget(splitter, 1)
        return page

    def _build_history(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(16)
        layout.addLayout(self._page_header(
            "History", "Past scans on this machine. Stored locally, and never with the "
                       "evidence itself."))

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)
        head = QWidget()
        head.setObjectName("PanelHeader")
        head.setFixedHeight(36)
        head_layout = QHBoxLayout(head)
        head_layout.setContentsMargins(14, 0, 8, 0)
        head_label = QLabel("SCANS")
        head_label.setObjectName("SectionLabel")
        head_layout.addWidget(head_label)
        head_layout.addStretch()
        self.btn_forget = QPushButton("Forget history")
        self.btn_forget.setObjectName("Quiet")
        self.btn_forget.setCursor(Qt.PointingHandCursor)
        self.btn_forget.clicked.connect(self.on_forget)
        head_layout.addWidget(self.btn_forget)
        panel_layout.addWidget(head)

        self.history_body = QLabel()
        self.history_body.setObjectName("Detail")
        self.history_body.setTextFormat(Qt.RichText)
        self.history_body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.history_body.setWordWrap(True)
        self.history_body.setContentsMargins(14, 12, 14, 14)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.history_body)
        panel_layout.addWidget(scroll, 1)
        layout.addWidget(panel, 1)
        return page

    def _build_about(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(16)
        layout.addLayout(self._page_header(
            "About", "What this tool does, and what it deliberately doesn't."))

        panel = QFrame()
        panel.setObjectName("Panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        self.about_body = QLabel()
        self.about_body.setObjectName("Detail")
        self.about_body.setTextFormat(Qt.RichText)
        self.about_body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.about_body.setWordWrap(True)
        self.about_body.setOpenExternalLinks(False)
        self.about_body.setContentsMargins(18, 16, 18, 18)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.about_body)
        panel_layout.addWidget(scroll)
        layout.addWidget(panel, 1)
        return page

    def _build_drawer(self):
        close = QPushButton()
        close.setObjectName("Quiet")
        close.setCursor(Qt.PointingHandCursor)
        close.setFixedWidth(30)
        close.clicked.connect(self.drawer.close_drawer)
        self._drawer_close = close
        self.drawer.add_header_button(close)
        self.drawer.closed.connect(lambda: self.btn_filter.setChecked(False))

        body = self.drawer.body_layout
        sev_label = QLabel("SEVERITY")
        sev_label.setObjectName("SectionLabel")
        body.addWidget(sev_label)
        self.sev_boxes = {}
        for severity in SEVERITIES:
            box = QCheckBox(severity.capitalize())
            box.setChecked(True)
            box.stateChanged.connect(self._render_tree)
            self.sev_boxes[severity] = box
            body.addWidget(box)

        body.addSpacing(8)
        conf_label = QLabel("CONFIDENCE")
        conf_label.setObjectName("SectionLabel")
        body.addWidget(conf_label)
        self.conf_box = QComboBox()
        self.conf_box.addItems(["Any", "Certain only", "Certain + likely"])
        self.conf_box.currentIndexChanged.connect(self._render_tree)
        body.addWidget(self.conf_box)

        body.addSpacing(8)
        group_label = QLabel("GROUPING")
        group_label.setObjectName("SectionLabel")
        body.addWidget(group_label)
        self.group_box = QComboBox()
        self.group_box.addItems(["Group by file", "Flat list"])
        self.group_box.currentIndexChanged.connect(self._render_tree)
        body.addWidget(self.group_box)

        body.addStretch()
        self.filter_summary = QLabel("")
        self.filter_summary.setObjectName("Meta")
        self.filter_summary.setWordWrap(True)
        body.addWidget(self.filter_summary)
        reset = QPushButton("Reset filters")
        reset.clicked.connect(self._reset_filters)
        body.addWidget(reset)

    # ── theming ──────────────────────────────────────────────────────────────
    def on_theme_toggle(self):
        new_theme = "light" if self.theme == "dark" else "dark"
        root = self.centralWidget()
        self._fade(root, 1.0, 0.0, 100)
        QTimer.singleShot(62, lambda: self._apply_theme(new_theme))
        QTimer.singleShot(104, lambda: self._fade(root, 0.0, 1.0, 150))

    def _apply_theme(self, name, first=False):
        self.theme = name
        self.c = PALETTES[name]
        self._settings.setValue("theme", name)
        self.setStyleSheet(build_qss(self.c))

        self.nav.set_palette(self.c)
        self.delegate.set_palette(self.c)
        self.sev_bar.set_palette(self.c)
        for severity, card in self.cards.items():
            card.set_colour(self.c[severity])
        self.btn_theme.setIcon(icons.icon("sun" if self.c["is_dark"] else "moon",
                                          self.c["text_muted"], 16))
        self.btn_filter.setIcon(icons.icon("filter", self.c["text_muted"], 15))
        self.btn_scan.setIcon(icons.icon("scan", self.c["accent_ink"], 14))
        self._drawer_close.setIcon(icons.icon("close", self.c["text_muted"], 14))
        self.btn_copy.setIcon(icons.icon("copy", self.c["text_muted"], 14))
        self.btn_forget.setIcon(icons.icon("trash", self.c["text_muted"], 14))

        self._render_about()
        if not first:
            self.tree.viewport().update()
            self._render_detail(self._current_finding)
            self._render_history()
            if self._report:
                self._render_overview(self._report)

    def _fade(self, widget, start, end, duration):
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(duration)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anims.append(anim)

        def cleanup():
            if anim in self._anims:
                self._anims.remove(anim)
            widget.setGraphicsEffect(None)

        anim.finished.connect(cleanup)
        anim.start()

    def _make_counter(self, severity):
        anim = QVariantAnimation(self)
        anim.setDuration(520)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.valueChanged.connect(
            lambda value, s=severity: self.cards[s].value.setText(str(int(value))))
        return anim

    # ── navigation, drawer, layout ───────────────────────────────────────────
    def _on_nav(self, index):
        self.pages.setCurrentIndex(index)
        page = self.pages.currentWidget()
        self._fade(page, 0.0, 1.0, 170)
        if index == 2:
            self._render_history()

    def _toggle_filters(self):
        if self.pages.currentIndex() != 1:
            self.nav.select(1)
        self.drawer.toggle("FILTERS")
        self.btn_filter.setChecked(self.drawer.is_open)

    def _reset_filters(self):
        for box in self.sev_boxes.values():
            box.setChecked(True)
        self.conf_box.setCurrentIndex(0)
        self.group_box.setCurrentIndex(0)
        self.search.clear()

    def _focus_search(self):
        if self.pages.currentIndex() != 1:
            self.nav.select(1)
        self.search.setFocus()
        self.search.selectAll()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.drawer.reposition()

    # ── scanning ─────────────────────────────────────────────────────────────
    def on_scan(self):
        if not self.btn_scan.isEnabled():
            return
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("SCANNING")
        self.status.setText("Reading files…")
        self._start_pulse()

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

    def _start_pulse(self):
        self._pulse_step = 0

        def tick():
            if self.btn_scan.isEnabled():
                self.progress.setText("")
                return
            self._pulse_step = (self._pulse_step + 1) % 4
            self.progress.setText("scanning" + "." * self._pulse_step)
            QTimer.singleShot(320, tick)

        tick()

    @Slot(object)
    def _on_data(self, report):
        self._report = report
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("SCAN")
        self.progress.setText("")

        self._render_overview(report)
        self._render_tree()
        self._render_history()

        counts = by_severity(report.findings)
        self.status.setText(
            f"{len(report.findings)} finding(s) · {report.files_seen:,} files · "
            f"{report.duration_seconds:.1f}s")
        self.status_right.setText(time.strftime("scanned %H:%M:%S"))
        if counts["critical"] or counts["high"]:
            self.nav.select(1)

    @Slot(str)
    def _on_error(self, message):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("SCAN")
        self.progress.setText("")
        self.status.setText(f"Error: {message}")

    # ── rendering ────────────────────────────────────────────────────────────
    def _show_empty_state(self):
        c = self.c
        self.top_files.setText(
            f"<div style='color:{c['text_muted']};padding:18px 2px'>"
            "No scan yet. Press <b>Scan</b> to read this machine — it takes a few seconds "
            "and changes nothing on disk.</div>")
        self.detail.setText(
            f"<div style='color:{c['text_muted']}'>Select a finding to see why it matters "
            "and how to fix it.</div>")
        self.sev_bar.set_counts({})
        self._render_history()

    def _render_overview(self, report):
        c = self.c
        counts = by_severity(report.findings)
        for index, severity in enumerate(SEVERITIES):
            QTimer.singleShot(index * 70,
                              lambda s=severity, v=counts[severity]: self._count_to(s, v))
        self.sev_bar.set_counts(counts)

        if report.coverage_is_partial:
            parts = []
            if report.stopped_early:
                parts.append(esc(report.stop_reason))
            if report.skipped_too_large:
                parts.append(f"{report.skipped_too_large:,} file(s) skipped for size.")
            if report.skipped_unreadable:
                parts.append(f"{report.skipped_unreadable:,} file(s) couldn't be read.")
            if report.detector_errors:
                parts.append(f"{report.detector_errors:,} file(s) hit an internal error.")
            self.notice.setText(
                "<b>Coverage was not complete.</b> " + " ".join(parts)
                + " Findings are real — but an empty result is not proof that nothing "
                  "else is exposed.")
            self.notice.show()
        else:
            self.notice.hide()

        groups = group_by_file(report.findings)[:14]
        if not groups:
            self.top_files.setText(
                f"<div style='color:{c['text_muted']};padding:18px 2px'>"
                "Nothing found in what could be read.</div>")
            return

        rows = []
        for path, findings in groups:
            worst = min(findings, key=lambda f: SEVERITIES.index(f.severity)).severity
            counts = [(s, sum(1 for f in findings if f.severity == s)) for s in SEVERITIES]
            chips = "&nbsp;&nbsp;".join(
                f"<span style='color:{c[s]}'>{n}&nbsp;{s}</span>"
                for s, n in counts if n)
            rows.append(
                f"<tr>"
                f"<td width='14' style='padding:6px 0;color:{c[worst]};font-size:11px'>&#9632;</td>"
                f"<td style='padding:6px 12px 6px 0;font-family:{MONO};font-size:11px;"
                f"color:{c['text']}'>{esc(path)}</td>"
                f"<td align='right' style='padding:6px 0;font-family:{MONO};font-size:10px;"
                f"white-space:nowrap'>{chips}</td>"
                f"</tr>"
                f"<tr><td colspan='3' style='background:{c['border']};font-size:1px'></td></tr>")
        self.top_files.setText(
            f"<table width='100%' cellspacing='0' cellpadding='0'>{''.join(rows)}</table>")

    def _count_to(self, severity, value):
        anim = self._kpi_anims[severity]
        anim.stop()
        anim.setStartValue(self._kpi_prev.get(severity, 0))
        anim.setEndValue(value)
        anim.start()
        self._kpi_prev[severity] = value

    def _passes_filters(self, finding, query):
        rule = RULES_BY_ID.get(finding.rule_id)
        title = rule.title if rule else finding.rule_id
        if not self.sev_boxes[finding.severity].isChecked():
            return False
        confidence_mode = self.conf_box.currentIndex()
        if confidence_mode == 1 and finding.confidence != "certain":
            return False
        if confidence_mode == 2 and finding.confidence == "possible":
            return False
        if query and query not in finding.display_path.lower() and query not in title.lower():
            return False
        return True

    def _render_tree(self):
        if not self._report:
            return
        c = self.c
        query = self.search.text().lower().strip()
        kept = [f for f in ranked(self._report.findings) if self._passes_filters(f, query)]

        self.tree.clear()
        if self.group_box.currentIndex() == 0:
            for path, findings in group_by_file(kept):
                group = QTreeWidgetItem(self.tree)
                group.setData(0, ROLE_KIND, "group")
                group.setData(0, ROLE_TITLE, path)
                group.setData(0, ROLE_BADGE, f"{len(findings)}")
                group.setFlags(Qt.ItemIsEnabled)
                for finding in ranked(findings):
                    self._add_finding_item(group, finding)
                group.setExpanded(True)
        else:
            for finding in kept:
                self._add_finding_item(self.tree, finding)

        total = len(self._report.findings)
        self.filter_summary.setText(f"Showing {len(kept)} of {total} findings.")
        self.status_right.setText(f"{len(kept)} of {total} shown")
        if not kept:
            self.detail.setText(
                f"<div style='color:{c['text_muted']}'>Nothing matches these filters.</div>")
            self.btn_copy.setEnabled(False)

    def _add_finding_item(self, parent, finding):
        rule = RULES_BY_ID.get(finding.rule_id)
        item = QTreeWidgetItem(parent)
        item.setData(0, ROLE_KIND, "finding")
        item.setData(0, ROLE_FINDING, finding)
        item.setData(0, ROLE_TITLE, rule.title if rule else finding.rule_id)
        location = finding.display_path + (f":{finding.line_no}" if finding.line_no else "")
        item.setData(0, ROLE_SUBTITLE, f"{location}  ·  {finding.confidence}")
        item.setData(0, ROLE_SEVERITY, finding.severity)
        return item

    def _on_select(self, current, _previous):
        if current is None or current.data(0, ROLE_KIND) != "finding":
            return
        finding = current.data(0, ROLE_FINDING)
        self._current_finding = finding
        self._render_detail(finding)
        self.btn_copy.setEnabled(True)

    def _render_detail(self, finding):
        if finding is None:
            return
        c = self.c
        rule = RULES_BY_ID.get(finding.rule_id)
        title = rule.title if rule else finding.rule_id
        location = esc(finding.display_path) + (f":{finding.line_no}" if finding.line_no else "")
        self.detail_label.setText(finding.severity.upper() + " · " + finding.confidence.upper())

        parts = [
            f"<div style='font-size:16px;font-weight:600;color:{c['text']}'>{esc(title)}</div>",
            f"<div style='font-family:{MONO};font-size:11px;color:{c['text_faint']};"
            f"margin:6px 0 14px 0'>{location}</div>",
            f"<div style='color:{c['text']};line-height:150%'>{esc(finding.detail)}</div>",
        ]

        if finding.evidence:
            parts.append(
                f"<div style='margin:14px 0 4px 0;padding:11px 13px;"
                f"background:{c['surface_alt']};border-left:3px solid {c['accent']};"
                f"font-family:{MONO};font-size:12px;color:{c['text']}'>"
                f"{esc(finding.evidence)}</div>"
                f"<div style='color:{c['text_faint']};font-size:10px'>"
                f"{esc(REDACT_CHAR * 3)} covered here, and never written to disk by this app."
                f"</div>")

        if rule:
            parts += [
                f"<div style='margin-top:18px;color:{c['accent']};font-family:{MONO};"
                f"font-size:10px;font-weight:700;letter-spacing:1.5px'>WHY IT MATTERS</div>",
                f"<div style='margin-top:6px;color:{c['text_muted']};line-height:150%'>"
                f"{esc(rule.rationale)}</div>",
                f"<div style='margin-top:18px;color:{c['accent']};font-family:{MONO};"
                f"font-size:10px;font-weight:700;letter-spacing:1.5px'>HOW TO FIX IT</div>",
                f"<div style='margin-top:8px;padding:12px 13px;background:{c['surface_alt']};"
                f"border:1px solid {c['border']};color:{c['text']};font-family:{MONO};"
                f"font-size:11px;line-height:145%'>"
                f"{esc_block(rule.remediation(finding))}</div>",
            ]
        self.detail.setText("".join(parts))

    def _copy_fix(self):
        if not self._current_finding:
            return
        rule = RULES_BY_ID.get(self._current_finding.rule_id)
        if not rule:
            return
        QApplication.clipboard().setText(rule.remediation(self._current_finding))
        self.status.setText("Fix copied to clipboard.")

    def _render_history(self):
        c = self.c
        rows = store.history(limit=40)
        if not rows:
            self.history_body.setText(
                f"<div style='color:{c['text_muted']};padding:14px 2px'>No scans recorded yet.</div>")
            return
        html_rows = []
        for index, (ts, count, weighted, partial) in enumerate(rows):
            when = time.strftime("%d %b %Y · %H:%M", time.localtime(ts))
            delta = ""
            if index + 1 < len(rows):
                previous = rows[index + 1][1]
                change = count - previous
                if change > 0:
                    delta = f"<span style='color:{c['critical']}'>&#9650; +{change}</span>"
                elif change < 0:
                    delta = f"<span style='color:{c['low']}'>&#9660; {change}</span>"
                else:
                    delta = f"<span style='color:{c['text_faint']}'>no change</span>"
            flag = (f" <span style='color:{c['medium']}'>· partial coverage</span>"
                    if partial else "")
            html_rows.append(
                f"<div style='padding:8px 0;border-bottom:1px solid {c['border']}'>"
                f"<span style='font-family:{MONO};font-size:11px;color:{c['text']}'>{esc(when)}"
                f"</span> &nbsp; <span style='color:{c['text_muted']}'>{count} finding(s)</span>"
                f" &nbsp; {delta}{flag}</div>")
        self.history_body.setText("".join(html_rows))

    def _render_about(self):
        c = self.c
        rule_rows = "".join(
            f"<tr><td style='padding:3px 14px 3px 0;font-family:{MONO};font-size:11px;"
            f"color:{c[rule.severity]}'>{esc(rule.severity)}</td>"
            f"<td style='padding:3px 0;color:{c['text_muted']}'>{esc(rule.title)}</td></tr>"
            for rule in sorted(ALL_RULES, key=lambda r: SEVERITIES.index(r.severity)))
        self.about_body.setText(f"""
<div style='font-size:15px;font-weight:600;color:{c['text']}'>Exposure Auditor</div>
<div style='color:{c['text_muted']};margin-top:6px;line-height:150%'>
Finds credentials sitting unprotected on this disk — private keys other accounts can read,
keys with no passphrase, plaintext credential stores, and API tokens in files that were never
meant to hold them.</div>

<div style='margin-top:20px;color:{c['accent']};font-family:{MONO};font-size:10px;
font-weight:700;letter-spacing:1.5px'>IT NEVER LEAVES THIS MACHINE</div>
<div style='margin-top:6px;color:{c['text_muted']};line-height:150%'>
There is no network code in this application. Not disabled, not opt-out — none. A tool that
reads every file in your home directory looking for secrets and then talks to a server is a
worse version of the problem it claims to solve.</div>

<div style='margin-top:18px;color:{c['accent']};font-family:{MONO};font-size:10px;
font-weight:700;letter-spacing:1.5px'>IT NEVER CHANGES ANYTHING</div>
<div style='margin-top:6px;color:{c['text_muted']};line-height:150%'>
No file is edited, moved, quarantined or deleted. Every fix is a command you run yourself.</div>

<div style='margin-top:18px;color:{c['accent']};font-family:{MONO};font-size:10px;
font-weight:700;letter-spacing:1.5px'>IT NEVER SHOWS YOU THE SECRET</div>
<div style='margin-top:6px;color:{c['text_muted']};line-height:150%'>
Findings show a masked form with a few characters at each end — enough to recognise which
credential it is when you rotate it, never enough to use. Masked evidence is not written to
the history database either.</div>

<div style='margin-top:22px;color:{c['text_faint']};font-family:{MONO};font-size:10px;
font-weight:700;letter-spacing:1.5px'>RULES ({len(ALL_RULES)})</div>
<table style='margin-top:8px'>{rule_rows}</table>

<div style='margin-top:22px;color:{c['text_faint']};font-family:{MONO};font-size:10px;
font-weight:700;letter-spacing:1.5px'>LOCAL DATA</div>
<div style='margin-top:6px;font-family:{MONO};font-size:11px;color:{c['text_muted']};
word-wrap:break-word'>{esc(store.DB_PATH)}</div>
<div style='margin-top:4px;color:{c['text_faint']};font-size:11px'>
Owner-only (0600). Delete it any time from the History page.</div>
""")

    def on_forget(self):
        answer = QMessageBox.question(
            self, "Forget scan history",
            "Delete the local history database?\n\n"
            f"{store.DB_PATH}\n\n"
            "It records which files held findings, so it's worth not keeping around once "
            "you've acted on them. Findings currently on screen stay until you rescan.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer == QMessageBox.Yes:
            store.forget_everything()
            store.init()
            self._render_history()
            self.status.setText("History deleted.")
