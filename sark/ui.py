import idaapi


# TODO: use a metaclass to automatically generate names for classes.
class ActionHandler(idaapi.action_handler_t):
    NAME = None
    TEXT = "Default. Replace me!"
    HOTKEY = ""
    TOOLTIP = ""
    ICON = 0

    @classmethod
    def register(cls):
        name = cls.NAME
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
        idaapi.unregister_action(cls.NAME)

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