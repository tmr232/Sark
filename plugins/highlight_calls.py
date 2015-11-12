from awesome.context import ignored
import idaapi
import sark

HIGHLIGHT_COLOR = 0x303060


@sark.ui.updates_ui
def highlight_calls_in_function(ea):
    for line in sark.Function(ea).lines:
        if not line.insn.is_call:
            continue

        # Refrain from painting over someone else...
        if line.color is None:
            line.color = HIGHLIGHT_COLOR


class UiHooks(idaapi.UI_Hooks):
    def updating_actions(self, ctx):
        if ctx.form_type == idaapi.BWN_DISASM:
            with ignored(sark.exceptions.SarkNoFunction):
                highlight_calls_in_function(ctx.cur_ea)

        return super(UiHooks, self).updating_actions(ctx)


class CallHighlighter(object):
    def __init__(self, timing):
        self.last_func = None
        self.interval = timing

    def run(self):
        with ignored(sark.exceptions.SarkNoFunction):
            current_func = sark.Function()
            if current_func != self.last_func:
                highlight_calls_in_function(current_func.startEA)
            self.last_func = current_func

        return self.interval

class HighlightCalls(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = 'Highlight Call Instructions'
    help = 'Highlight all call instructions'
    wanted_name = 'Highlight Calls'
    wanted_hotkey = ''

    def init(self):
        # self.ui_hooks = UiHooks()
        # self.ui_hooks.hook()
        highlighter = CallHighlighter(100)
        self.timer = idaapi.register_timer(highlighter.interval, highlighter.run)
        return idaapi.PLUGIN_KEEP

    def term(self):
        # self.ui_hooks.unhook()
        idaapi.unregister_timer(self.timer)

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HighlightCalls()
