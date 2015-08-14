import re
import subprocess
import idaapi
import sark
from sark.qt import MenuManager

OUTPUT_WINDOW_WIDGET_TITLE = "Output window"
TEXTEDIT_WIDGET_INDEX = 1
IDA_IPYTHON_KERNEL_PATTERN = r"To connect another client to this kernel, use:\s+--existing (?P<kernel>kernel-\d+.json)"

def get_output_text_edit_widget():
    """Get the Output Window's text edit widget."""
    output_widget = sark.qt.get_widget(OUTPUT_WINDOW_WIDGET_TITLE)
    output_children_widgets = output_widget.children()
    text_edit_widget = output_children_widgets[TEXTEDIT_WIDGET_INDEX]

    return text_edit_widget


def get_ida_python_kernel_filename():
    """
    """
    output_widget = get_output_text_edit_widget()
    output_text = output_widget.document().toPlainText()

    match = re.search(IDA_IPYTHON_KERNEL_PATTERN, output_text)
    kernel = match.group("kernel")

    return kernel


def launch_qt_console():
    """
    TODO: launch qtconsole with specific color-set.
    """
    kernel_filename = get_ida_python_kernel_filename()
    # todo if..

    subprocess.Popen(["ipython", "qtconsole", "--existing", kernel_filename])


def launch_console():
    """
    """
    kernel_filename = get_ida_python_kernel_filename()
    # todo if..

    subprocess.Popen(["ipython", "console", "--existing", kernel_filename])

class IPython(idaapi.plugin_t):
    flags = 0
    comment = "IPython Plugin's Manager"
    help = "Manages IDA's IPython plugin."
    wanted_name = "IPython"
    wanted_hotkey = ""

    # GUI-related constants.
    MENU_NAME = "&IPython"

    def init(self):
        self._menu_manager = None
        self._init_ui()

        return idaapi.PLUGIN_KEEP

    def _init_ui(self):
        """Initializes the plugin's UI."""
        self._menu_manager = MenuManager()
        self._menu_manager.add_menu(self.MENU_NAME)

        menu = self._menu_manager.get_menu(self.MENU_NAME)
        menu.addAction("Launch &Console", launch_console)
        menu.addAction("Launch &Qt Console", launch_qt_console)

    def term(self):
        self._menu_manager.clear()

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return IPython()
