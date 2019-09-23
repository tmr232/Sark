import networkx

import idaapi
from .code import lines, functions
from .core import get_func, fix_addresses


class CodeBlock(idaapi.BasicBlock):
    def __init__(self, id_ea=None, bb=None, fc=None):
        if bb is None and fc is None:
            if id_ea is None:
                id_ea = idaapi.get_screen_ea()
            temp_codeblock = get_codeblock(id_ea)
            self.__dict__.update(temp_codeblock.__dict__)
        else:
            super(CodeBlock, self).__init__(id=id_ea, bb=bb, fc=fc)

    @property
    def lines(self):
        return lines(self.start_ea, self.end_ea)

    @property
    def next(self):
        return self.succs()

    @property
    def prev(self):
        return self.preds()

    def set_color(self, color=None):
        for line in self.lines:
            line.color = color

        if color is None:
            idaapi.clr_node_info(self._fc._q.bounds.start_ea, self.id, idaapi.NIF_BG_COLOR)

        else:
            node_info = idaapi.node_info_t()
            node_info.bg_color = color
            idaapi.set_node_info(self._fc._q.bounds.start_ea, self.id, node_info, idaapi.NIF_BG_COLOR)

    @property
    def color(self):
        node_info = idaapi.node_info_t()
        success = idaapi.get_node_info(node_info, self._fc._q.bounds.start_ea, self.id)

        if not success:
            return None

        if not node_info.valid_bg_color():
            return None

        return node_info.bg_color

    @color.setter
    def color(self, color):
        self.set_color(color)

    def __repr__(self):
        return "<CodeBlock(start_ea=0x{:08X}, end_ea=0x{:08X})>".format(self.start_ea, self.end_ea)

    def __eq__(self, other):
        return self.start_ea == other.start_ea


class FlowChart(idaapi.FlowChart):
    def __init__(self, f=None, bounds=None, flags=idaapi.FC_PREDS, ignore_external=False):
        if f is None and bounds is None:
            f = idaapi.get_screen_ea()
        if f is not None:
            f = get_func(f)
        if ignore_external:
            flags |= idaapi.FC_NOEXT

        super(FlowChart, self).__init__(f=f, bounds=bounds, flags=flags)

    def _getitem(self, index):
        return CodeBlock(index, self._q[index], self)


def get_flowchart(ea=None):
    if ea is None:
        ea = idaapi.get_screen_ea()
    func = idaapi.get_func(ea)
    flowchart_ = FlowChart(func)
    return flowchart_


def get_codeblock(ea=None):
    if ea is None:
        ea = idaapi.get_screen_ea()
    flowchart_ = get_flowchart(ea)
    for code_block in flowchart_:
        if code_block.start_ea == ea: # External blocks can be zero-sized.
            return code_block
        if code_block.start_ea <= ea < code_block.end_ea:
            return code_block


def get_block_start(ea):
    """Get the start address of an IDA Graph block."""
    return get_codeblock(ea).start_ea


def get_nx_graph(ea, ignore_external=False):
    """Convert an IDA flowchart to a NetworkX graph."""
    nx_graph = networkx.DiGraph()
    func = idaapi.get_func(ea)
    flowchart = FlowChart(func, ignore_external=ignore_external)
    for block in flowchart:
        # Make sure all nodes are added (including edge-less nodes)
        nx_graph.add_node(block.start_ea)

        for pred in block.preds():
            nx_graph.add_edge(pred.start_ea, block.start_ea)
        for succ in block.succs():
            nx_graph.add_edge(block.start_ea, succ.start_ea)

    return nx_graph


def codeblocks(start=None, end=None, full=True):
    """Get all `CodeBlock`s in a given range.

    Args:
        start - start address of the range. If `None` uses IDB start.
        end - end address of the range. If `None` uses IDB end.
        full - `True` is required to change node info (e.g. color). `False` causes faster iteration.
    """
    if full:
        for function in functions(start, end):
            fc = FlowChart(f=function.func_t)
            for block in fc:
                yield block

    else:
        start, end = fix_addresses(start, end)

        for code_block in FlowChart(bounds=(start, end)):
            yield code_block
