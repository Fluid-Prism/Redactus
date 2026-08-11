"""theme.py — design tokens and the stylesheet built from them.

Qt Style Sheets have no variables and no transitions, so tokens live here as
plain dicts and get interpolated into one QSS string per theme. Anything that
needs to animate is driven from Python instead.

The identity is a dossier: moss charcoal, one signal-orange accent used
sparingly, monospace for anything that's data rather than prose, and square
corners. Its two sibling apps are cool blue-black/teal and indigo/gold, so
this one deliberately shares none of that.
"""

# 4px base. Every margin and padding in the app is a multiple of this, which
# is most of what separates a laid-out interface from an arranged one.
SPACE = 4

PALETTES = {
    "dark": {
        "bg": "#0C100E", "chrome": "#121714", "surface": "#161C18",
        "surface_alt": "#1A211C", "surface_raised": "#1F2721",
        "border": "#252E28", "border_strong": "#333F36",
        "text": "#E6EAE4", "text_muted": "#8D998F", "text_faint": "#606B64",
        "accent": "#E05A3C", "accent_hover": "#EC6B4E", "accent_ink": "#FFFFFF",
        "accent_wash": "#241612",
        "critical": "#E85D62", "critical_wash": "#2A1517",
        "high": "#E08236", "high_wash": "#271A11",
        "medium": "#C9A94A", "medium_wash": "#232013",
        "low": "#7E8C83", "low_wash": "#1A201C",
        "certain": "#E85D62", "likely": "#C9A94A", "possible": "#8D998F",
        "selection": "#26312A",
        "shadow": (0, 0, 0, 150),
        "is_dark": True,
    },
    "light": {
        "bg": "#EEF1EA", "chrome": "#E4E9DF", "surface": "#FBFCF9",
        "surface_alt": "#F2F5EE", "surface_raised": "#FFFFFF",
        "border": "#D8DFD2", "border_strong": "#C0C9B9",
        "text": "#171D18", "text_muted": "#5C6860", "text_faint": "#859389",
        "accent": "#B33F1D", "accent_hover": "#C64A26", "accent_ink": "#FFFFFF",
        "accent_wash": "#F8E9E3",
        "critical": "#B3272E", "critical_wash": "#F9E7E8",
        "high": "#9A551A", "high_wash": "#F8EEE1",
        "medium": "#7B6412", "medium_wash": "#F5F1DF",
        "low": "#66736A", "low_wash": "#EEF1EC",
        "certain": "#B3272E", "likely": "#7B6412", "possible": "#5C6860",
        "selection": "#E2E9DC",
        "shadow": (40, 55, 42, 38),
        "is_dark": False,
    },
}

# Menlo leads because it's the one that resolves by name on macOS; Qt logs a
# font-substitution warning for 'SF Mono' even though it renders fine.
MONO = "Menlo, 'SF Mono', 'JetBrains Mono', Consolas, monospace"
# Body text deliberately names no family, so Qt uses the platform's own UI
# font — San Francisco on macOS, Segoe on Windows. Naming families Qt can't
# resolve ('-apple-system' is a CSS keyword, not a font; 'Inter' is usually
# not installed) makes it substitute silently and warn on every launch, and
# the substitute is rarely as good as the native default.


def rgba(hex_colour, alpha):
    h = hex_colour.lstrip("#")
    return f"rgba({int(h[0:2],16)},{int(h[2:4],16)},{int(h[4:6],16)},{alpha})"


def build_qss(c):
    return f"""
QWidget {{ background: transparent; color: {c['text']}; font-size: 13px; }}
QMainWindow, #Root {{ background: {c['bg']}; }}

/* chrome ------------------------------------------------------------- */
#TopBar {{ background: {c['chrome']}; border-bottom: 1px solid {c['border']}; }}
#NavRail {{ background: {c['chrome']}; border-right: 1px solid {c['border']}; }}
#StatusBar {{ background: {c['chrome']}; border-top: 1px solid {c['border']}; }}
#BrandMark {{ font-family: {MONO}; font-size: 11px; font-weight: 700;
    letter-spacing: 2.5px; color: {c['accent']}; }}
#BrandName {{ font-size: 13px; font-weight: 600; color: {c['text']}; }}

/* panels -------------------------------------------------------------- */
#Panel {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 3px; }}
#PanelHeader {{ background: {c['surface_alt']}; border-bottom: 1px solid {c['border']};
    border-top-left-radius: 3px; border-top-right-radius: 3px; }}
#SectionLabel {{ font-family: {MONO}; font-size: 9px; font-weight: 700;
    letter-spacing: 1.8px; color: {c['text_faint']}; }}
#PageTitle {{ font-size: 19px; font-weight: 600; color: {c['text']}; }}
#PageSub {{ font-size: 12px; color: {c['text_muted']}; }}
#Meta {{ font-family: {MONO}; font-size: 11px; color: {c['text_muted']}; }}
#Divider {{ background: {c['border']}; }}

/* buttons ------------------------------------------------------------- */
QPushButton {{ background: {c['surface']}; color: {c['text']};
    border: 1px solid {c['border_strong']}; border-radius: 3px;
    padding: 6px 13px; font-size: 12px; font-weight: 500; }}
QPushButton:hover {{ background: {c['surface_raised']}; border-color: {c['text_faint']}; }}
QPushButton:pressed {{ background: {c['surface_alt']}; }}
QPushButton:disabled {{ color: {c['text_faint']}; border-color: {c['border']}; background: transparent; }}
QPushButton#Primary {{ background: {c['accent']}; color: {c['accent_ink']};
    border: 1px solid {c['accent']}; font-weight: 600;
    font-family: {MONO}; letter-spacing: 1.2px; font-size: 11px; padding: 7px 16px; }}
QPushButton#Primary:hover {{ background: {c['accent_hover']}; border-color: {c['accent_hover']}; }}
QPushButton#Primary:disabled {{ background: {c['border']}; border-color: {c['border']};
    color: {c['text_faint']}; }}
QPushButton#Quiet {{ background: transparent; border: 1px solid transparent; padding: 6px 9px; }}
QPushButton#Quiet:hover {{ background: {c['surface']}; border-color: {c['border']}; }}
QPushButton#Quiet:checked {{ background: {c['accent_wash']}; border-color: {c['accent']};
    color: {c['accent']}; }}

/* inputs -------------------------------------------------------------- */
QLineEdit, QComboBox {{ background: {c['surface']}; color: {c['text']};
    border: 1px solid {c['border_strong']}; border-radius: 3px;
    padding: 6px 10px; font-size: 12px; selection-background-color: {c['accent']};
    selection-color: {c['accent_ink']}; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {c['accent']}; }}
QLineEdit::placeholder {{ color: {c['text_faint']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: {c['surface_raised']}; color: {c['text']};
    border: 1px solid {c['border_strong']}; padding: 3px;
    selection-background-color: {c['selection']}; outline: none; }}

/* tree / lists -------------------------------------------------------- */
QTreeView {{ background: {c['surface']}; border: none; outline: none;
    show-decoration-selected: 1; }}
QTreeView::item {{ border: none; }}
QTreeView::item:selected {{ background: {c['selection']}; }}
QTreeView::branch {{ background: transparent; }}
QHeaderView::section {{ background: {c['surface_alt']}; color: {c['text_faint']};
    border: none; border-bottom: 1px solid {c['border']}; padding: 7px 10px;
    font-family: {MONO}; font-size: 9px; font-weight: 700; letter-spacing: 1.4px; }}

/* tabs ---------------------------------------------------------------- */
QTabWidget::pane {{ border: none; background: transparent; }}
QTabBar::tab {{ background: transparent; color: {c['text_muted']};
    padding: 7px 14px; margin-right: 2px; border: none;
    border-bottom: 2px solid transparent; font-size: 12px; }}
QTabBar::tab:selected {{ color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
QTabBar::tab:hover {{ color: {c['text']}; }}

/* drawer -------------------------------------------------------------- */
#Drawer {{ background: {c['surface']}; border-left: 1px solid {c['border_strong']}; }}
#DrawerHeader {{ background: {c['surface_alt']}; border-bottom: 1px solid {c['border']}; }}
#Scrim {{ background: {rgba('#000000', 0.32 if c['is_dark'] else 0.16)}; }}

/* misc ---------------------------------------------------------------- */
#Notice {{ background: {c['accent_wash']}; border: 1px solid {c['border']};
    border-left: 3px solid {c['accent']}; border-radius: 3px;
    padding: 10px 12px; color: {c['text_muted']}; font-size: 12px; }}
#Detail {{ background: transparent; font-size: 12px; }}
QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {c['border_strong']}; border-radius: 5px;
    min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {c['text_faint']}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {c['border_strong']}; border-radius: 5px;
    min-width: 28px; }}
QScrollBar::handle:horizontal:hover {{ background: {c['text_faint']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QToolTip {{ background: {c['surface_raised']}; color: {c['text']};
    border: 1px solid {c['border_strong']}; padding: 5px 8px; }}
QSplitter::handle {{ background: {c['border']}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QMenu {{ background: {c['surface_raised']}; border: 1px solid {c['border_strong']}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px 6px 12px; border-radius: 2px; }}
QMenu::item:selected {{ background: {c['selection']}; }}
"""
