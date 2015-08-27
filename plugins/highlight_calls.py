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


class HighlightCalls(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = 'Highlight Call Instructions'
    help = 'Highlight all call instructions'
    wanted_name = 'Highlight Calls'
    wanted_hotkey = ''

    def init(self):
        self.ui_hooks = UiHooks()
        self.ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.ui_hooks.unhook()

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HighlightCalls()
