import os
import sys

from PyQt5 import QtCore, QtWidgets, QtGui

import idaapi

from . import exceptions


def capture_widget(widget, path=None):
    """Grab an image of a Qt widget

    Args:
        widget: The Qt Widget to capture
        path (optional): The path to save to. If not provided - will return image data.

    Returns:
        If a path is provided, the image will be saved to it.
        If not, the PNG buffer will be returned.
    """
    pixmap = widget.grab()

    if path:
        pixmap.save(path)

    else:
        image_buffer = QtCore.QBuffer()
        image_buffer.open(QtCore.QIODevice.ReadWrite)

        pixmap.save(image_buffer, "PNG")

        return image_buffer.data().data()


def get_widget(title):
    """Get the Qt widget of the IDA window with the given title."""
    tform = idaapi.find_widget(title)
    if not tform:
        raise exceptions.FormNotFound("No form titled {!r} found.".format(title))

    return idaapi.PluginForm.FormToPyQtWidget(tform)


def resize_widget(widget, width, height):
    """Resize a Qt widget."""
    widget.setGeometry(0, 0, width, height)


def get_window():
    """Get IDA's top level window."""
    tform = idaapi.get_current_widget()

    # Required sometimes when closing IDBs and not IDA.
    if not tform:
        tform = idaapi.find_widget("Output window")

    widget = idaapi.PluginForm.FormToPyQtWidget(tform)
    window = widget.window()
    return window


class MenuManager(object):
    """IDA Menu Manipulation

    Use this class to add your own top-level menus.
    While this is discouraged by the SDK:

    > You should not change top level menu, or the Edit,Plugins submenus

    (documentation for `attach_action_to_menu`, kernwin.hpp)

    Adding top-level menus is useful sometimes.
    Nonetheless, you should be careful and make sure to remove all your menus
    when you are done. Leaving them handing would force users to restart IDA
    to remove them.

    Usage of this class should be as follows:

    >>> # Use the manager to add top-level menus
    >>> menu_manager = MenuManager()
    >>> menu_manager.add_menu("My Menu")
    >>> # Use the standard API to add menu items
    >>> idaapi.attach_action_to_menu("My Menu/", ":My-Action:", idaapi.SETMENU_APP)
    >>> # When a menu is not needed, remove it
    >>> menu_manager.remove_menu("My Menu")
    >>> # When you are done with the manager (and want to remove all menus you added,)
    >>> # clear it before deleting.
    >>> menu_manager.clear()
    """

    def __init__(self):
        super(MenuManager, self).__init__()

        self._window = get_window()
        self._menu = self._window.findChild(QtWidgets.QMenuBar)

        self._menus = {}

    def add_menu(self, name):
        """Add a top-level menu.

        The menu manager only allows one menu of the same name. However, it does
        not make sure that there are no pre-existing menus of that name.
        """
        if name in self._menus:
            raise exceptions.MenuAlreadyExists("Menu name {!r} already exists.".format(name))
        menu = self._menu.addMenu(name)
        self._menus[name] = menu

    def remove_menu(self, name):
        """Remove a top-level menu.

        Only removes menus created by the same menu manager.
        """
        if name not in self._menus:
            raise exceptions.MenuNotFound(
                "Menu {!r} was not found. It might be deleted, or belong to another menu manager.".format(name))

        self._menu.removeAction(self._menus[name].menuAction())
        del self._menus[name]

    def clear(self):
        """Clear all menus created by this manager."""
        for menu in self._menus.values():
            self._menu.removeAction(menu.menuAction())
        self._menus = {}
