from awesome.context import ignored
import idaapi
import sark
from ida_settings import IDASettings

HIGHLIGHT_COLOR = 0x303060


def highlight_calls_in_function(ea):
    highlighted_lines = set()
    for line in sark.Function(ea).lines:
        if not line.insn.is_call:
            continue

        # Refrain from painting over someone else...
        if line.color is None:
            line.color = HIGHLIGHT_COLOR
            highlighted_lines.add(line.ea)
    return highlighted_lines


class UiHooks(idaapi.UI_Hooks):
    def __init__(self, lines):
        super(UiHooks, self).__init__()
        self.lines = lines

    def updating_actions(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            with ignored(sark.exceptions.SarkNoFunction):
                self.lines.update(highlight_calls_in_function(ctx.cur_ea))

        return super(UiHooks, self).updating_actions(ctx)


class ToggleHandler(idaapi.action_handler_t):
    def __init__(self, state=False):
        idaapi.action_handler_t.__init__(self)

        self._state = state

    def on_enable(self, ctx):
        raise NotImplementedError()

    def on_disable(self, ctx):
        raise NotImplementedError()

    def activate(self, ctx=idaapi.action_activation_ctx_t()):
        if self._state:
            self.on_disable(ctx)
        else:
            self.on_enable(ctx)

        self._state = not self._state


class ToggleHighlightHandler(ToggleHandler):
    def __init__(self, enable, disable):
        ToggleHandler.__init__(self)

        self.enable = enable
        self.disable = disable

    def on_enable(self, ctx):
        self.enable()

    def on_disable(self, ctx):
        self.disable()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class SelectColorHandler(idaapi.action_handler_t):
    def __init__(self, set_color):
        idaapi.action_handler_t.__init__(self)
        self._set_color = set_color

    def activate(self, ctx):
        color = sark.ui.ask_color(initial=HIGHLIGHT_COLOR)
        if color is not None:
            self._set_color(color)

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class HighlightCalls(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = 'Highlight Call Instructions'
    help = 'Highlight all call instructions'
    wanted_name = 'Highlight Calls'
    wanted_hotkey = ''

    def init(self):
        self.lines = set()
        self.settings = IDASettings('HighlightCalls')
        try:
            self.set_color(self.settings['color'])
        except KeyError:
            self.settings.user['color'] = HIGHLIGHT_COLOR
            self.set_color(HIGHLIGHT_COLOR)
        self.ui_hooks = UiHooks(self.lines)

        self.toggle_action_desc = idaapi.action_desc_t('HighlightCalls:Toggle',
                                                       'Toggle call highlighting',
                                                       ToggleHighlightHandler(self.enable_highlights,
                                                                              self.disable_highlights),
                                                       '',
                                                       'Toggle call highlighting',
                                                       -1)
        idaapi.register_action(self.toggle_action_desc)

        self.color_selector = idaapi.action_desc_t('HighlightCalls:SelectColor',
                                                   'Select highlight color',
                                                   SelectColorHandler(set_color=self.set_color),
                                                   '',
                                                   'Select highlight color',
                                                   -1)
        idaapi.register_action(self.color_selector)

        idaapi.attach_action_to_menu('View/', self.toggle_action_desc.name, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu('View/', self.color_selector.name, idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def set_color(self, color):
        self.color = color
        self.settings.user['color'] = color
        global HIGHLIGHT_COLOR
        HIGHLIGHT_COLOR = color
        self.clear_all_highlights()

    def enable_highlights(self):
        self.ui_hooks.hook()

    def term(self):
        self.disable_highlights()
        idaapi.unregister_action(self.toggle_action_desc.name)
        idaapi.unregister_action(self.color_selector.name)

    def disable_highlights(self):
        self.ui_hooks.unhook()
        self.clear_all_highlights()

    def clear_all_highlights(self):
        for ea in self.lines:
            sark.Line(ea=ea).color = None
        self.lines.clear()

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HighlightCalls()
