import os
import sys

import idaapi


# This nasty piece of code is here to force the loading of IDA's PySide.
# Without it, Python attempts to load PySide from the site-packages directory,
# and failing, as it does not play nicely with IDA.
old_path = sys.path[:]
try:
    ida_python_path = os.path.dirname(idaapi.__file__)
    sys.path.insert(0, ida_python_path)
    from PySide import QtGui, QtCore
finally:
    sys.path = old_path


def capture_widget(widget, path):
    """Grab an image of a Qt widget and save to file."""
    pixmap = QtGui.QPixmap.grabWidget(widget)
    pixmap.save(path)


def get_widget(title):
    """Get the Qt widget of the IDA window with the given title."""
    tform = idaapi.find_tform(title)
    if not tform:
        return

    return idaapi.PluginForm.FormToPySideWidget(tform)


def resize_widget(widget, width, height):
    """Resize a Qt widget."""
    widget.setGeometry(0, 0, width, height)