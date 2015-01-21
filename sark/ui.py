import idaapi

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