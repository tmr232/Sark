"""
Reference:
    http://www.hexblog.com/?p=886

Return values for update:
    AST_ENABLE_ALWAYS     // enable action and do not call action_handler_t::update() anymore
    AST_ENABLE_FOR_IDB    // enable action for the current idb. Call action_handler_t::update() when a database is opened/closed
    AST_ENABLE_FOR_FORM   // enable action for the current form. Call action_handler_t::update() when a form gets/loses focus
    AST_ENABLE            // enable action - call action_handler_t::update() when anything changes

    AST_DISABLE_ALWAYS    // disable action and do not call action_handler_t::action() anymore
    AST_DISABLE_FOR_IDB   // analog of ::AST_ENABLE_FOR_IDB
    AST_DISABLE_FOR_FORM  // analog of ::AST_ENABLE_FOR_FORM
    AST_DISABLE           // analog of ::AST_ENABLE
"""
import idaapi
import idc
from threading import RLock
import itertools
import wrapt


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
        self.LOCK.acquire(blocking=0)

    def __exit__(self, exc_type, exc_val, exc_tb):
        can_update = self.LOCK._is_owned()

        if can_update:
            idc.Refresh()

        self.LOCK.release()


@wrapt.decorator
def updates_ui(wrapped, instance, args, kwargs):
    """Refresh UI on return."""
    with Update():
        return wrapped(*args, **kwargs)


class BasicNodeHandler(object):
    @classmethod
    def on_get_text(cls, value, attrs):
        return str(value)

    @classmethod
    def on_click(cls, value, attrs):
        return False

    @classmethod
    def on_double_click(cls, value, attrs):
        return False

    @classmethod
    def on_hint(cls, value, attrs):
        return None

    @classmethod
    def on_bg_color(cls, value, attrs):
        return attrs.get(NXGraph.BG_COLOR, None)


class AddressNodeHandler(BasicNodeHandler):
    @classmethod
    def on_get_text(cls, value, attrs):
        return idc.Name(value)

    @classmethod
    def on_double_click(cls, value, attrs):
        idaapi.jumpto(value)
        return False


class NXGraph(idaapi.GraphViewer):
    PAD_WIDTH = 3
    PADDING = 1
    HANDLER = "HANDLER"
    BG_COLOR = "BG_COLOR"
    DEFAULT_HANDLER = BasicNodeHandler

    def __init__(self, title, graph, default_handler=DEFAULT_HANDLER):
        title = self._make_unique_title(title)

        idaapi.GraphViewer.__init__(self, title)

        self._graph = graph
        self._default_handler = default_handler

    def _pad(self, text, padding=PADDING):
        top_bottom = ("\n" * padding) + " "
        right_left = " " * padding * self.PAD_WIDTH
        return top_bottom + right_left + text + right_left + top_bottom

    def _make_unique_title(self, title):
        unique_title = title

        for counter in itertools.count():
            unique_title = "{}-{}".format(title, counter)
            if not idaapi.find_tform(unique_title):
                break

        return unique_title

    def _get_handler(self, node_id):
        return self._get_attrs(node_id).get(self.HANDLER, self._default_handler)

    def _get_attrs(self, node_id):
        return self._graph.node[self[node_id]]

    def _get_handling_triplet(self, node_id):
        handler = self._get_handler(node_id)
        attrs = self._get_attrs(node_id)
        value = self[node_id]

        return handler, value, attrs


    def _OnBgColor(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        bg_color = handler.on_bg_color(value, attrs)
        if bg_color is None:
            return

        node_info = idaapi.node_info_t()
        node_info.bg_color = bg_color
        self.SetNodeInfo(node_id, node_info, idaapi.NIF_BG_COLOR)

    def color_nodes(self):
        for node_id, node in enumerate(self):
            self._OnBgColor(node_id)


    def OnGetText(self, node_id):
        handler, value, attrs = self._get_handling_triplet(node_id)
        self._OnBgColor(node_id)
        return self._pad(handler.on_get_text(value, attrs))

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False

        self.color_nodes()

        return True

    def OnRefresh(self):
        self.Clear()

        node_ids = {node: self.AddNode(node) for node in self._graph.nodes_iter()}

        for frm, to in self._graph.edges_iter():
            self.AddEdge(node_ids[frm], node_ids[to])

        self.color_nodes()

        return True

    def OnActivate(self):
        # Refresh on every activation to keep the graph up to date.
        self.Refresh()
        self.color_nodes()
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


# Make sure API is supported to enable use of other functionality in older versions.
if idaapi.IDA_SDK_VERSION >= 670:
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

            :param ctx: The action context passed from IDA.
            :return: None
            """
            raise NotImplementedError()


