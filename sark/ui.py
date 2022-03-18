import idaapi
import idc
from threading import RLock
import itertools
import wrapt
import traceback

if idaapi.is_idaq():
    # Only load Qt if we're in IDAQ.
    # This should allow running in IDAT.
    from .qt import MenuManager
    from PyQt5 import QtGui, QtWidgets

def ask_color(initial=None):
    if initial is not None:
        color = QtGui.QColor(initial & 0xFF, (initial >> 8) & 0xFF, (initial >> 16) & 0xFF)
        qcolor_dialog = QtWidgets.QColorDialog(color)

    else:
        qcolor_dialog = QtWidgets.QColorDialog()

    qcolor = qcolor_dialog.getColor()

    if not qcolor.isValid:
        return None

    return (qcolor.blue() << 16) | (qcolor.green() << 8) | (qcolor.red() << 0)


class Update(object):
    """
    A context manager that refreshes the UI on `__exit__`.

    When nested, only the topmost context manager can update the UI.
    This is used to make sure that UI-heavy code does not update the
    UI until it is finished.

    Note that this does not prevent updates via other APIs, so be sure
    to use this and the `updates_ui` decorator.
    """
    LOCK = RLock()

    def __enter__(self):
        self.LOCK.acquire(blocking=False)

    def __exit__(self, exc_type, exc_val, exc_tb):
        can_update = self.LOCK._is_owned()

        if can_update:
            idaapi.refresh_idaview_anyway()

        self.LOCK.release()


@wrapt.decorator
def updates_ui(wrapped, instance, args, kwargs):
    """Refresh UI on return."""
    with Update():
        return wrapped(*args, **kwargs)


class BasicNodeHandler(object):
    """Basic Node Handler

    This is the base class for all node handlers (for NXGraph).
    It implements usable defaults for all required events.

    When subclassing, simply replace the events you want to modify.
    """

    def on_get_text(self, value, attrs):
        """Get the text to display on the node.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            str: The text to display.
        """
        return str(value)

    def on_click(self, value, attrs):
        """Action to perform on click.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            ``True`` to accept the click, ``False`` to ignore it.
        """
        return False

    def on_double_click(self, value, attrs):
        """Action to perform on double click.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            ``True`` to accept the click, ``False`` to ignore it.
        """
        return False

    def on_hint(self, value, attrs):
        """Hint to show.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            The hint to show.
        """
        return None

    def on_bg_color(self, value, attrs):
        """Background color.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            ``None`` for default color, otherwise the color as a number.
        """
        return attrs.get(NXGraph.BG_COLOR, None)

    def on_frame_color(self, value, attrs):
        """Frame color.

        Args:
            value: The value of the current node.
            attrs (dict): The node's attributes.

        Returns:
            ``None`` for default color, otherwise the color as a number.
        """
        return attrs.get(NXGraph.FRAME_COLOR, None)


class AddressNodeHandler(BasicNodeHandler):
    """Address Node Handler

    Used to display addresses.
    In addition to the default functionality:
        1. Shows the name of an address (hex value if no name exists) instead of
            just the number;
        2. On double-click, jumps to the address clicked.
    """

    def on_get_text(self, value, attrs):
        name = idaapi.get_ea_name(value)
        demangle = getattr(idaapi, 'demangle_name2', idaapi.demangle_name)
        name = demangle(name, 0) or name
        return name or "0x{:08X}".format(value)

    def on_double_click(self, value, attrs):
        idaapi.jumpto(value)
        return False


class NXGraph(idaapi.GraphViewer):
    """NetworkX Graph Viewer

    A utility class for displaying NetworkX graphs inside IDA with ease.

    When showing a graph, the nodes and edges are iterated to create the graph structure.
    For every node, a "handler" is used to get display parameters:
        - Text to display
        - Background and Frame colors
        - Hint
        - Actions on click and double-click

    Handlers can be specified in one of 2 ways:
        1. By specifying the `handler` parameter to the constructor;
        2. By setting the `NXGraph.HANDLER` attribute of a specific node:

            >>> my_graph.nodes[my_node][NXGraph.HANDLER] = MyCustomHandler()

    Two other useful attribute are `NXGraph.BG_COLOR` and `NXGraph.FRAME_COLOR` that allow
    specifying colors for your nodes. If not provided, the default color will be used.
    Note that the handler is responsible for using those attributes, and can therefore
    modify their behaviour or ignore them completely.

    for more information about handlers see the `BasicNodeHandler` class.

    To display a graph, use:

        >>> viewer = sark.ui.NXGraph(my_graph, title="My Graph")
        >>> viewer.Show()


    To make the graph easier on the eye, node text is padded, adding empty space around it.
    `PADDING` is the default amount of padding to use in all directions.
    `PADDING_WIDTH` scales the padding width.
    To change the padding, simply provide the constructor with a padding to use.
    """
    PAD_WIDTH = 3
    PADDING = 1
    HANDLER = "HANDLER"
    BG_COLOR = "BG_COLOR"
    FRAME_COLOR = "FRAME_COLOR"
    DEFAULT_HANDLER = BasicNodeHandler()

    def __init__(self, graph, title="GraphViewer", handler=None, padding=PADDING):
        """Initialize the graph viewer.

        To avoid bizarre IDA errors (crashing when creating 2 graphs with the same title,)
        a counter is appended to the title (similar to "Hex View-1".)

        Args:
            graph: A NetworkX graph to display.
            title: The graph title.
            handler: The default node handler to use when accessing node data.
        """
        title = self._make_unique_title(title)

        idaapi.GraphViewer.__init__(self, title)

        self._graph = graph

        if handler is None:
            handler = self.DEFAULT_HANDLER

        # Here we make sure the handler is an instance of `BasicNodeHandler` or inherited
        # types. While generally being bad Python practice, we still need it here as an
        # invalid handler can cause IDA to crash.
        if not isinstance(handler, BasicNodeHandler):
            raise TypeError("Node handler must inherit from `BasicNodeHandler`.")

        self._default_handler = handler
        self._padding = padding

    def _pad(self, text):
        """Pad the text."""
        top_bottom = ("\n" * self._padding) + " "
        right_left = " " * self._padding * self.PAD_WIDTH
        return top_bottom + right_left + text + right_left + top_bottom

    def _make_unique_title(self, title):
        """Make the title unique.

        Adds a counter to the title to prevent duplicates.

        Prior to IDA 6.8, two graphs with the same title could crash IDA.
        This has been fixed (https://www.hex-rays.com/products/ida/6.8/index.shtml).
        The code will not change for support of older versions and as it is
        more usable this way.
        """
        unique_title = title

        for counter in itertools.count():
            unique_title = "{}-{}".format(title, counter)
            if not idaapi.find_widget(unique_title):
                break

        return unique_title

    def _get_handler(self, node_id):
        """Get the handler of a given node."""
        handler = self._get_attrs(node_id).get(self.HANDLER, self._default_handler)

        # Here we make sure the handler is an instance of `BasicNodeHandler` or inherited
        # types. While generally being bad Python practice, we still need it here as an
        # invalid handler can cause IDA to crash.
        if not isinstance(handler, BasicNodeHandler):
            idaapi.msg(("Invalid handler for node {}: {}. All handlers must inherit from"
                        "`BasicNodeHandler`.").format(node_id, handler))
            handler = self._default_handler
        return handler

    def _get_attrs(self, node_id):
        """Get the node's attributes"""
        return self._graph.nodes[self[node_id]]

    def _get_handling_triplet(self, node_id):
        """_get_handling_triplet(node_id) -> (handler, value, attrs)"""
        handler = self._get_handler(node_id)
        value = self[node_id]
        attrs = self._get_attrs(node_id)

        return handler, value, attrs

    def _OnNodeInfo(self, node_id):
        """Sets the node info based on its attributes."""
        handler, value, attrs = self._get_handling_triplet(node_id)
        frame_color = handler.on_frame_color(value, attrs)

        node_info = idaapi.node_info_t()

        if frame_color is not None:
            node_info.frame_color = frame_color

        flags = node_info.get_flags_for_valid()

        self.SetNodeInfo(node_id, node_info, flags)

    def update_node_info(self):
        """Sets the node info for all nodes."""
        for node_id, node in enumerate(self):
            self._OnNodeInfo(node_id)

    def OnGetText(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        self._OnNodeInfo(node_id)
        return (self._pad(handler.on_get_text(value, attrs)), handler.on_bg_color(value, attrs))

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False

        return True

    def OnRefresh(self):
        self.Clear()

        # Compatibility between NetworkX 1.x and 2.x
        try:
            graph_nodes_iter = self._graph.nodes()
            graph_edges_iter = self._graph.edges()
        except AttributeError:
            graph_nodes_iter = self._graph.nodes_iter()
            graph_edges_iter = self._graph.edges_iter()

        node_ids = {node: self.AddNode(node) for node in graph_nodes_iter}

        for frm, to in graph_edges_iter:
            self.AddEdge(node_ids[frm], node_ids[to])

        self.update_node_info()

        return True

    def OnActivate(self):
        # Refresh on every activation to keep the graph up to date.
        self.Refresh()
        return True

    def OnDeactivate(self):
        pass

    def OnDblClick(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        return handler.on_double_click(value, attrs)

    def OnClick(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        return handler.on_click(value, attrs)

    def OnHint(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        return handler.on_hint(value, attrs)


class ActionHandler(idaapi.action_handler_t):
    """A wrapper around `idaapi.action_handler_t`.

    The class simplifies the creation of UI actions in IDA >= 6.7.

    To create an action, simply create subclass and override the relevant fields
    and register it::

        class MyAction(ActionHandler):
            TEXT = "My Action"
            HOTKEY = "Alt+Z"

            def _activate(self, ctx):
                idaapi.msg("Activated!")

        MyAction.register()

    Additional Documentation:
        Introduction to `idaapi.action_handler_t`:
            http://www.hexblog.com/?p=886

        Return values for update (from the SDK):
            AST_ENABLE_ALWAYS     // enable action and do not call action_handler_t::update() anymore
            AST_ENABLE_FOR_IDB    // enable action for the current idb. Call action_handler_t::update() when a database is opened/closed
            AST_ENABLE_FOR_WIDGET // enable action for the current widget. Call action_handler_t::update() when a form gets/loses focus
            AST_ENABLE            // enable action - call action_handler_t::update() when anything changes

            AST_DISABLE_ALWAYS    // disable action and do not call action_handler_t::action() anymore
            AST_DISABLE_FOR_IDB   // analog of ::AST_ENABLE_FOR_IDB
            AST_DISABLE_FOR_WIDGET// analog of ::AST_ENABLE_FOR_WIDGET
            AST_DISABLE           // analog of ::AST_ENABLE
    """
    NAME = None
    TEXT = "Default. Replace me!"
    HOTKEY = ""
    TOOLTIP = ""
    ICON = -1

    @classmethod
    def get_name(cls):
        """Return the name of the action.

        If a name has not been set (using the `Name` class variable), the
        function generates a name based on the class name and id.
        :return: action name
        :rtype: str
        """
        if cls.NAME is not None:
            return cls.NAME

        return "{}:{}".format(cls.__name__, id(cls))

    @classmethod
    def get_desc(cls):
        """Get a descriptor for this handler."""
        name = cls.get_name()
        text = cls.TEXT
        handler = cls()
        hotkey = cls.HOTKEY
        tooltip = cls.TOOLTIP
        icon = cls.ICON
        action_desc = idaapi.action_desc_t(
            name,
            text,
            handler,
            hotkey,
            tooltip,
            icon,
        )
        return action_desc

    @classmethod
    def register(cls):
        """Register the action.

        Each action MUST be registered before it can be used. To remove the action
        use the `unregister` method.
        """
        action_desc = cls.get_desc()

        return idaapi.register_action(action_desc)

    @classmethod
    def unregister(cls):
        """Unregister the action.

        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            self._activate(ctx)
            return 1
        except:
            trace = traceback.format_exc()
            idaapi.msg("Action {!r} failed to activate. Traceback:\n{}".format(self.get_name(), trace))
            return 0

    def update(self, ctx):
        """Update the action.

        Optionally override this function.
        See IDA-SDK for more information.
        """
        return idaapi.AST_ENABLE_ALWAYS

    def _activate(self, ctx):
        """Activate the action.

        This function contains the action code itself. You MUST implement
        it in your class for the action to work.

        Args:
            ctx: The action context passed from IDA.
        """
        raise NotImplementedError()
