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


class ActionHandler(idaapi.action_handler_t):
    NAME = None
    TEXT = "Default. Replace me!"
    HOTKEY = ""
    TOOLTIP = ""
    ICON = -1

    @classmethod
    def get_name(cls):
        if cls.NAME is not None:
            return cls.NAME

        return "{}:{}".format(cls.__name__, id(cls))

    @classmethod
    def register(cls):
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

        idaapi.register_action(action_desc)

    @classmethod
    def unregister(cls):
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
        return idaapi.AST_ENABLE_ALWAYS

    def _activate(self, ctx):
        raise NotImplementedError()