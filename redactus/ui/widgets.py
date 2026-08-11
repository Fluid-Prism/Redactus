"""widgets.py — the custom pieces the stock Qt controls don't cover.

Everything here exists because a stylesheet couldn't get there: a nav rail
with an indicator that slides between items, a drawer that animates in over
the content, a severity distribution bar, and an item delegate that paints
two-line rows with a severity pill instead of putting coloured text in a
table cell.
"""
from PySide6.QtCore import (QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt,
                            Property, Signal)
from PySide6.QtGui import (QColor, QFont, QFontMetrics, QPainter, QPainterPath,
                           QPen)
from PySide6.QtWidgets import (QAbstractButton, QFrame, QGraphicsDropShadowEffect,
                               QHBoxLayout, QLabel, QSizePolicy, QStyle,
                               QStyledItemDelegate, QVBoxLayout, QWidget)

from . import icons
from .theme import MONO

MONO_FAMILY = MONO.split(",")[0].strip("' ")


def _mono_font(point_size, weight=QFont.Normal):
    font = QFont(MONO_FAMILY)
    font.setStyleHint(QFont.Monospace)
    font.setPointSize(point_size)
    font.setWeight(weight)
    return font


def _ui_font(option, point_size, weight=QFont.Normal):
    font = QFont(option.font)
    font.setPointSize(point_size)
    font.setWeight(weight)
    return font


ROLE_FINDING = Qt.UserRole + 1
ROLE_KIND = Qt.UserRole + 2      # "group" | "finding"
ROLE_TITLE = Qt.UserRole + 3
ROLE_SUBTITLE = Qt.UserRole + 4
ROLE_SEVERITY = Qt.UserRole + 5
ROLE_BADGE = Qt.UserRole + 6


class NavButton(QAbstractButton):
    """One row of the nav rail. Painted rather than styled so the icon can be
    recoloured with the label and the whole row can share one hover state."""

    def __init__(self, kind, text, palette):
        super().__init__()
        self.kind = kind
        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(38)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._c = palette
        self._hover = False

    def set_palette(self, palette):
        self._c = palette
        self.update()

    def enterEvent(self, event):
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, _event):
        c = self._c
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(6, 2, -6, -2)

        if self.isChecked():
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(c["accent_wash"]))
            painter.drawRoundedRect(QRectF(rect), 3, 3)
        elif self._hover:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(c["surface"]))
            painter.drawRoundedRect(QRectF(rect), 3, 3)

        colour = c["accent"] if self.isChecked() else (
            c["text"] if self._hover else c["text_muted"])
        pixmap = icons.icon(self.kind, colour, 17).pixmap(17, 17)
        painter.drawPixmap(rect.left() + 10, rect.center().y() - 8, pixmap)

        font = painter.font()
        font.setPointSize(12)
        font.setWeight(QFont.DemiBold if self.isChecked() else QFont.Normal)
        painter.setFont(font)
        painter.setPen(QColor(colour))
        painter.drawText(rect.adjusted(36, 0, -8, 0),
                         Qt.AlignVCenter | Qt.AlignLeft, self.text())
        painter.end()


class NavRail(QWidget):
    """Vertical navigation with an indicator bar that animates between items."""

    changed = Signal(int)

    def __init__(self, palette):
        super().__init__()
        self.setObjectName("NavRail")
        self.setFixedWidth(178)
        self._c = palette
        self._buttons = []
        self._indicator_y = 0.0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(2)
        self._layout = layout

        self._anim = QPropertyAnimation(self, b"indicator_y", self)
        self._anim.setDuration(220)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def add_item(self, kind, text):
        button = NavButton(kind, text, self._c)
        index = len(self._buttons)
        button.clicked.connect(lambda _=False, i=index: self.select(i))
        self._buttons.append(button)
        self._layout.addWidget(button)
        if index == 0:
            button.setChecked(True)
        return button

    def finish(self):
        self._layout.addStretch()

    def select(self, index, emit=True):
        for i, button in enumerate(self._buttons):
            button.setChecked(i == index)
        target = self._buttons[index]
        self._anim.stop()
        self._anim.setStartValue(float(self._indicator_y))
        self._anim.setEndValue(float(target.y() + 8))
        self._anim.start()
        if emit:
            self.changed.emit(index)

    def set_palette(self, palette):
        self._c = palette
        for button in self._buttons:
            button.set_palette(palette)
        self.update()

    def get_indicator_y(self):
        return self._indicator_y

    def set_indicator_y(self, value):
        self._indicator_y = value
        self.update()

    indicator_y = Property(float, get_indicator_y, set_indicator_y)

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self._buttons:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(self._c["accent"]))
        painter.drawRoundedRect(QRectF(0, self._indicator_y, 2.5, 22), 1.2, 1.2)
        painter.end()


class StatCard(QFrame):
    """A count with a label. The number carries the colour; there's no accent
    bar, because four cards each with a coloured stripe reads as decoration."""

    def __init__(self, label, palette):
        super().__init__()
        self.setObjectName("Panel")
        self._c = palette
        self._colour = palette["text"]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 12)
        layout.setSpacing(3)

        self.value = QLabel("—")
        font = QFont(MONO.split(",")[0].strip("'"))
        font.setStyleHint(QFont.Monospace)
        font.setPointSize(21)
        font.setWeight(QFont.DemiBold)
        self.value.setFont(font)

        self.label = QLabel(label)
        self.label.setObjectName("SectionLabel")
        layout.addWidget(self.value)
        layout.addWidget(self.label)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setOffset(0, 2)
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(*palette["shadow"]))
        self.setGraphicsEffect(shadow)

    def set_colour(self, colour):
        self._colour = colour
        self.value.setStyleSheet(f"color:{colour}; background:transparent;")


class SeverityBar(QWidget):
    """Proportional distribution of findings by severity, as one bar. Reads at
    a glance in a way four separate numbers don't."""

    def __init__(self, palette):
        super().__init__()
        self.setFixedHeight(8)
        self._c = palette
        self._counts = {}

    def set_palette(self, palette):
        self._c = palette
        self.update()

    def set_counts(self, counts):
        self._counts = counts
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        total = sum(self._counts.values())

        path = QPainterPath()
        path.addRoundedRect(QRectF(rect), 4, 4)
        painter.setClipPath(path)

        if not total:
            painter.fillRect(rect, QColor(self._c["border"]))
            painter.end()
            return

        x = 0.0
        for severity in ("critical", "high", "medium", "low"):
            count = self._counts.get(severity, 0)
            if not count:
                continue
            width = rect.width() * count / total
            painter.fillRect(QRectF(x, 0, width + 0.5, rect.height()),
                             QColor(self._c[severity]))
            x += width
        painter.end()


class FindingDelegate(QStyledItemDelegate):
    """Two-line rows with a severity pill, painted rather than assembled from
    table cells. This is where most of the density and polish comes from: a
    finding is a title, a location and a severity, and those want different
    weights and colours on different lines."""

    ROW_HEIGHT = 52
    GROUP_HEIGHT = 30

    def __init__(self, palette, parent=None):
        super().__init__(parent)
        self._c = palette

    def set_palette(self, palette):
        self._c = palette

    def sizeHint(self, option, index):
        if index.data(ROLE_KIND) == "group":
            return QSize(option.rect.width(), self.GROUP_HEIGHT)
        return QSize(option.rect.width(), self.ROW_HEIGHT)

    def paint(self, painter, option, index):
        c = self._c
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = option.rect
        kind = index.data(ROLE_KIND)

        if kind == "group":
            painter.fillRect(rect, QColor(c["surface_alt"]))
            painter.setPen(QPen(QColor(c["border"]), 1))
            painter.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
            painter.setFont(_mono_font(10, QFont.DemiBold))
            painter.setPen(QColor(c["text_muted"]))
            painter.drawText(rect.adjusted(14, 0, -90, 0),
                             Qt.AlignVCenter | Qt.AlignLeft,
                             self._elide(painter, index.data(ROLE_TITLE), rect.width() - 104))
            badge = index.data(ROLE_BADGE) or ""
            painter.setPen(QColor(c["text_faint"]))
            painter.drawText(rect.adjusted(0, 0, -14, 0),
                             Qt.AlignVCenter | Qt.AlignRight, badge)
            painter.restore()
            return

        selected = bool(option.state & QStyle.State_Selected)
        hovered = bool(option.state & QStyle.State_MouseOver)
        severity = index.data(ROLE_SEVERITY) or "low"

        if selected:
            painter.fillRect(rect, QColor(c["selection"]))
        elif hovered:
            painter.fillRect(rect, QColor(c["surface_alt"]))

        if selected:
            painter.fillRect(QRectF(rect.left(), rect.top(), 2.5, rect.height()),
                             QColor(c["accent"]))

        painter.setPen(QPen(QColor(c["border"]), 1))
        painter.drawLine(rect.left() + 14, rect.bottom(), rect.right() - 14, rect.bottom())

        pill_rect = QRectF(rect.left() + 16, rect.center().y() - 9, 62, 18)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(c[severity + "_wash"]))
        painter.drawRoundedRect(pill_rect, 2.5, 2.5)
        painter.setFont(_mono_font(8, QFont.Bold))
        painter.setPen(QColor(c[severity]))
        painter.drawText(pill_rect, Qt.AlignCenter, severity.upper())

        text_left = rect.left() + 90
        text_width = rect.width() - (text_left - rect.left()) - 16

        # Built from the view's own font rather than by mutating the painter's:
        # clearing a family to "get back to the default" yields an unspecified
        # family whose metrics make drawText stretch the line.
        painter.setFont(_ui_font(option, 12, QFont.DemiBold if selected else QFont.Normal))
        painter.setPen(QColor(c["text"]))
        painter.drawText(text_left, rect.top() + 20,
                         self._elide(painter, index.data(ROLE_TITLE), text_width))

        painter.setFont(_mono_font(10, QFont.Normal))
        painter.setPen(QColor(c["text_faint"]))
        painter.drawText(text_left, rect.top() + 38,
                         self._elide(painter, index.data(ROLE_SUBTITLE), text_width))
        painter.restore()

    @staticmethod
    def _elide(painter, text, width):
        return QFontMetrics(painter.font()).elidedText(text or "", Qt.ElideMiddle, int(width))


class Drawer(QFrame):
    """A panel that slides in over the content from the right, with a scrim
    behind it. Used for filters and for the About panel — both are things you
    consult and dismiss, which is a drawer rather than another tab."""

    closed = Signal()

    def __init__(self, parent, width=320):
        super().__init__(parent)
        self.setObjectName("Drawer")
        self._width = width
        self._open = False

        self.scrim = QWidget(parent)
        self.scrim.setObjectName("Scrim")
        self.scrim.hide()
        self.scrim.mousePressEvent = lambda _event: self.close_drawer()

        self.header = QWidget()
        self.header.setObjectName("DrawerHeader")
        self.header.setFixedHeight(44)
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(14, 0, 8, 0)
        self.title = QLabel("")
        self.title.setObjectName("SectionLabel")
        header_layout.addWidget(self.title)
        header_layout.addStretch()
        self._header_layout = header_layout

        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(14, 14, 14, 14)
        self.body_layout.setSpacing(10)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.header)
        layout.addWidget(self.body, 1)

        self._anim = QPropertyAnimation(self, b"pos", self)
        self._anim.setDuration(230)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self.hide()

    def add_header_button(self, widget):
        self._header_layout.addWidget(widget)

    def reposition(self):
        parent = self.parentWidget()
        if not parent:
            return
        self.resize(self._width, parent.height())
        self.scrim.setGeometry(0, 0, parent.width(), parent.height())
        x = parent.width() - self._width if self._open else parent.width()
        self.move(x, 0)

    def open_drawer(self, title=""):
        parent = self.parentWidget()
        if not parent or self._open:
            return
        if title:
            self.title.setText(title)
        self._open = True
        self.resize(self._width, parent.height())
        self.scrim.setGeometry(0, 0, parent.width(), parent.height())
        self.scrim.show()
        self.scrim.raise_()
        self.move(parent.width(), 0)
        self.show()
        self.raise_()
        self._anim.stop()
        self._anim.setStartValue(self.pos())
        self._anim.setEndValue(self.pos().__class__(parent.width() - self._width, 0))
        self._anim.start()

    def close_drawer(self):
        parent = self.parentWidget()
        if not parent or not self._open:
            return
        self._open = False
        self._anim.stop()
        self._anim.setStartValue(self.pos())
        self._anim.setEndValue(self.pos().__class__(parent.width(), 0))

        def finish():
            if not self._open:
                self.hide()
                self.scrim.hide()
                self.closed.emit()
            try:
                self._anim.finished.disconnect(finish)
            except RuntimeError:
                pass

        self._anim.finished.connect(finish)
        self._anim.start()

    def toggle(self, title=""):
        self.close_drawer() if self._open else self.open_drawer(title)

    @property
    def is_open(self):
        return self._open
