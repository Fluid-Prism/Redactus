"""icons.py — icons drawn with QPainter rather than loaded from files.

An icon set is normally a dependency or a directory of SVGs. Both are avoided
here for the same reason the engine is stdlib-only: this app reads every file
in someone's home directory, so the less third-party code and fewer loose
assets involved, the smaller the thing anyone has to trust. These are simple
geometric glyphs, drawn at 2x and marked as such so they stay crisp on
retina displays, and recoloured per theme at draw time.
"""
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

_SCALE = 2


def _pen(painter, colour, width=1.6):
    pen = QPen(QColor(colour))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    return pen


def _draw(kind, painter, colour, size):
    """All glyphs are drawn inside a nominal 24x24 box, then scaled."""
    painter.scale(size / 24.0, size / 24.0)
    _pen(painter, colour)

    if kind == "overview":
        painter.drawRect(QRectF(3.5, 3.5, 7, 7))
        painter.drawRect(QRectF(13.5, 3.5, 7, 7))
        painter.drawRect(QRectF(3.5, 13.5, 7, 7))
        painter.drawRect(QRectF(13.5, 13.5, 7, 7))

    elif kind == "findings":
        path = QPainterPath(QPointF(12, 2.6))
        path.lineTo(20.2, 6.2)
        path.lineTo(20.2, 12)
        path.cubicTo(20.2, 16.6, 16.6, 20.2, 12, 21.4)
        path.cubicTo(7.4, 20.2, 3.8, 16.6, 3.8, 12)
        path.lineTo(3.8, 6.2)
        path.closeSubpath()
        painter.drawPath(path)
        painter.drawLine(QPointF(12, 8.4), QPointF(12, 13))
        painter.drawPoint(QPointF(12, 16.2))

    elif kind == "history":
        painter.drawEllipse(QRectF(3.4, 3.4, 17.2, 17.2))
        painter.drawLine(QPointF(12, 7.4), QPointF(12, 12))
        painter.drawLine(QPointF(12, 12), QPointF(15.6, 14.4))

    elif kind == "about":
        painter.drawEllipse(QRectF(3.4, 3.4, 17.2, 17.2))
        painter.drawLine(QPointF(12, 10.8), QPointF(12, 16.6))
        painter.drawPoint(QPointF(12, 7.8))

    elif kind == "scan":
        painter.drawEllipse(QRectF(4, 4, 12, 12))
        painter.drawLine(QPointF(15.2, 15.2), QPointF(20.4, 20.4))

    elif kind == "filter":
        painter.drawLine(QPointF(3.6, 6.4), QPointF(20.4, 6.4))
        painter.drawLine(QPointF(6.6, 12), QPointF(17.4, 12))
        painter.drawLine(QPointF(9.6, 17.6), QPointF(14.4, 17.6))

    elif kind == "sun":
        painter.drawEllipse(QRectF(8.4, 8.4, 7.2, 7.2))
        for dx, dy in ((0, -8.2), (0, 8.2), (-8.2, 0), (8.2, 0),
                       (-5.8, -5.8), (5.8, 5.8), (-5.8, 5.8), (5.8, -5.8)):
            painter.drawLine(QPointF(12 + dx * 0.72, 12 + dy * 0.72),
                             QPointF(12 + dx * 0.95, 12 + dy * 0.95))

    elif kind == "moon":
        path = QPainterPath(QPointF(19.4, 14.6))
        path.cubicTo(17.6, 15.4, 15.4, 15.2, 13.6, 13.9)
        path.cubicTo(11.1, 12.1, 10.5, 8.7, 12.1, 6.1)
        path.cubicTo(8.2, 6.7, 5.4, 10.3, 5.9, 14.3)
        path.cubicTo(6.4, 18.3, 10, 21.1, 14, 20.6)
        path.cubicTo(16.6, 20.2, 18.7, 17.7, 19.4, 14.6)
        path.closeSubpath()
        painter.drawPath(path)

    elif kind == "close":
        painter.drawLine(QPointF(7, 7), QPointF(17, 17))
        painter.drawLine(QPointF(17, 7), QPointF(7, 17))

    elif kind == "copy":
        painter.drawRect(QRectF(8.5, 8.5, 11, 11))
        path = QPainterPath(QPointF(15.5, 5.5))
        path.lineTo(5.5, 5.5)
        path.lineTo(5.5, 15.5)
        painter.drawPath(path)

    elif kind == "reveal":
        painter.drawPath(_folder_path())

    elif kind == "trash":
        painter.drawLine(QPointF(4.4, 7), QPointF(19.6, 7))
        painter.drawPath(_bin_path())
        painter.drawLine(QPointF(10, 11), QPointF(10, 17))
        painter.drawLine(QPointF(14, 11), QPointF(14, 17))


def _folder_path():
    path = QPainterPath(QPointF(3.6, 19))
    path.lineTo(3.6, 6)
    path.lineTo(9.6, 6)
    path.lineTo(11.6, 8.6)
    path.lineTo(20.4, 8.6)
    path.lineTo(20.4, 19)
    path.closeSubpath()
    return path


def _bin_path():
    path = QPainterPath(QPointF(6.2, 7))
    path.lineTo(7.1, 19.4)
    path.lineTo(16.9, 19.4)
    path.lineTo(17.8, 7)
    path2 = QPainterPath(QPointF(9.4, 7))
    path2.lineTo(9.4, 4.6)
    path2.lineTo(14.6, 4.6)
    path2.lineTo(14.6, 7)
    path.addPath(path2)
    return path


def icon(kind, colour, size=18):
    pixmap = QPixmap(size * _SCALE, size * _SCALE)
    # With a device pixel ratio set, the painter works in *logical* units — so
    # the glyph is drawn at `size`, not `size * _SCALE`. Passing the device
    # size here draws at double scale and clips everything but the top-left
    # quadrant, which is subtle enough on a 18px icon to look like a design.
    pixmap.setDevicePixelRatio(_SCALE)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    _draw(kind, painter, colour, size)
    painter.end()
    return QIcon(pixmap)
