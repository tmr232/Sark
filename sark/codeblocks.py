import networkx

import idaapi
from . import code


class CodeBlock(idaapi.BasicBlock):
    @property
    def lines(self):
        return code.iter_lines(self.startEA, self.endEA)

    @property
    def next(self):
        return self.succs()

    @property
    def prev(self):
        return self.preds()

    def set_color(self, color=None):
        for line in self.lines:
            line.color = color

    @property
    def color(self):
        return next(self.lines).color

    @color.setter
    def color(self, color):
        self.set_color(color)


class FlowChart(idaapi.FlowChart):
    def _getitem(self, index):
        return CodeBlock(index, self._q[index], self)


def flowchart(ea):
    func = idaapi.get_func(ea)
    flowchart = FlowChart(func)
    return flowchart


def codeblock(ea):
    flowchart_ = flowchart(ea)
    for code_block in flowchart_:
        if code_block.startEA <= ea < code_block.endEA:
            return code_block


def get_block_start(ea):
    return codeblock(ea).startEA


def get_nx_graph(ea):
    nx_graph = networkx.DiGraph()
    func = idaapi.get_func(ea)
    flowchart = FlowChart(func)
    for block in flowchart:
        for pred in block.preds():
            nx_graph.add_edge(pred.startEA, block.startEA)
        for succ in block.succs():
            nx_graph.add_edge(block.startEA, succ.startEA)

    return nx_graph